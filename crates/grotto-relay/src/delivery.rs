//! Conditional ordered delivery. All write outcomes and Welcome publication share one transaction.
use crate::storage::{RelayState, StorageError};
use grotto_protocol::{
    MAX_KEY_PACKAGE_BYTES, MAX_MLS_BLOB_BYTES, MessageId, RoomId, UserId, decode_message,
    delivery::*, encode_message, normalize_room_name,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

fn corrupt() -> StorageError {
    StorageError::InvalidStoredData("invalid V9 delivery record")
}

impl RelayState {
    pub fn deliver(
        &self,
        user: UserId,
        id: MessageId,
        request: Request,
    ) -> Result<Response, StorageError> {
        let mut connection = self.lock_connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let hash = payload_hash(&request).map_err(|_| corrupt())?;
        if let Some((saved_hash, bytes)) = tx
            .query_row(
                "SELECT hash,response FROM delivery_requests WHERE user_id=?1 AND request_id=?2",
                params![user.to_bytes().as_slice(), id.to_bytes().as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
        {
            if saved_hash != hash {
                return Ok(Response::Rejected(Rejection::RequestConflict));
            }
            // Release the possibly maximum-sized retry before decoding its saved
            // response, keeping the leased working payload below 2 MiB.
            drop(request);
            return decode_message(&bytes).map_err(|_| corrupt());
        }
        let receipt = matches!(request, Request::Acknowledge { .. });
        if let Request::Acknowledge { events, welcomes } = &request
            && (events.len() + welcomes.len() != 1
                || id != acknowledgement_id(user, events, welcomes))
        {
            return Ok(Response::Rejected(Rejection::Invalid));
        }
        let durable = !matches!(
            request,
            Request::FetchRoomEvents { .. }
                | Request::FetchWelcomes { .. }
                | Request::SyncIndex { .. }
        );
        if durable
            && !matches!(request, Request::Acknowledge { .. })
            && !self.limits.admit(&tx, &self.path, user, &request)?
        {
            crate::metrics::increment(&crate::metrics::QUOTA_REJECTIONS);
            return Ok(Response::Rejected(Rejection::Quota));
        }
        let charge_room = if let Request::AppendRoomOperation(operation) = &request {
            Some(operation.room)
        } else {
            None
        };
        let charge_bytes = (encode_message(&request).map_err(|_| corrupt())?.len() as u64)
            .saturating_mul(3)
            .saturating_add(16 * 1024);
        let response = execute(&tx, user, id, request)?;
        match response {
            Response::HeadConflict { .. } => {
                crate::metrics::increment(&crate::metrics::COMMIT_CONFLICTS)
            }
            Response::Rejected(Rejection::Quota) => {
                crate::metrics::increment(&crate::metrics::QUOTA_REJECTIONS)
            }
            _ => {}
        }
        if receipt && !matches!(response, Response::Acknowledged) {
            return Ok(response);
        }
        // Overload/quota can change: preserve the intent for a later retry.
        if durable
            && !matches!(
                response,
                Response::Rejected(Rejection::Quota | Rejection::Overloaded | Rejection::Internal)
            )
        {
            if !receipt {
                tx.execute("INSERT INTO usage_sender VALUES(?1,?2) ON CONFLICT(user_id) DO UPDATE SET bytes=bytes+excluded.bytes",params![user.to_bytes().as_slice(),charge_bytes])?;
                if let Some(room) = charge_room {
                    tx.execute("INSERT INTO usage_room VALUES(?1,?2) ON CONFLICT(room) DO UPDATE SET bytes=bytes+excluded.bytes",params![room.to_bytes().as_slice(),charge_bytes])?;
                }
            }
            let bytes = encode_message(&response).map_err(|_| corrupt())?;
            tx.execute(
                "INSERT INTO delivery_requests VALUES(?1,?2,?3,?4)",
                params![
                    user.to_bytes().as_slice(),
                    id.to_bytes().as_slice(),
                    hash.as_slice(),
                    bytes
                ],
            )?;
        }
        tx.commit()?;
        Ok(response)
    }
}

fn execute(
    tx: &Transaction<'_>,
    user: UserId,
    id: MessageId,
    mut request: Request,
) -> Result<Response, StorageError> {
    let denied = || Ok(Response::Rejected(Rejection::Unauthorized));
    match &mut request {
        Request::CreateRoom { name } => {
            let Ok(name) = normalize_room_name(name) else {
                return Ok(Response::Rejected(Rejection::Invalid));
            };
            let count: u64 = tx.query_row(
                "SELECT count(*) FROM rooms WHERE created_by=?1",
                [user.to_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if count >= 64 {
                return Ok(Response::Rejected(Rejection::Quota));
            }
            let room = RoomId::new().map_err(|e| StorageError::Random(e.to_string()))?;
            tx.execute(
                "INSERT INTO rooms(room_id,name,created_by) VALUES(?1,?2,?3)",
                params![room.to_bytes().as_slice(), name, user.to_bytes().as_slice()],
            )?;
            subscribe(tx, room, user)?;
            Ok(Response::RoomCreated { room })
        }
        Request::PublishKeyPackages { packages } => {
            if packages.is_empty()
                || packages.len() > 64
                || packages
                    .iter()
                    .any(|p| p.is_empty() || p.len() > MAX_KEY_PACKAGE_BYTES)
                || packages.iter().map(Vec::len).sum::<usize>() > MAX_PAYLOAD
            {
                return Ok(Response::Rejected(Rejection::Invalid));
            }
            let count: usize = tx.query_row(
                "SELECT count(*) FROM key_packages WHERE user_id=?1",
                [user.to_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if count + packages.len() > 64 {
                return Ok(Response::Rejected(Rejection::Quota));
            }
            for package in packages.iter() {
                tx.execute(
                    "INSERT INTO key_packages(user_id,key_package) VALUES(?1,?2)",
                    params![user.to_bytes().as_slice(), package],
                )?;
            }
            Ok(Response::KeyPackagesPublished {
                count: packages.len() as u64,
            })
        }
        Request::SetFetchGrant { requester, allowed } => {
            if *allowed {
                tx.execute(
                    "INSERT OR IGNORE INTO fetch_grants VALUES(?1,?2)",
                    params![user.to_bytes().as_slice(), requester.to_bytes().as_slice()],
                )?;
            } else {
                tx.execute(
                    "DELETE FROM fetch_grants WHERE recipient=?1 AND requester=?2",
                    params![user.to_bytes().as_slice(), requester.to_bytes().as_slice()],
                )?;
            }
            Ok(Response::FetchGrantSet)
        }
        Request::ReserveKeyPackage { recipient } => {
            let allowed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM fetch_grants WHERE recipient=?1 AND requester=?2)",
                params![recipient.to_bytes().as_slice(), user.to_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if !allowed {
                return denied();
            }
            let (total,pair):(u64,u64)=tx.query_row("SELECT count(*),coalesce(sum(requester=?2),0) FROM package_allocations WHERE recipient=?1 AND allocated_at>unixepoch()-3600",params![recipient.to_bytes().as_slice(),user.to_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?)))?;
            if total >= 16 || pair >= 4 {
                return Ok(Response::Rejected(Rejection::Overloaded));
            }
            let package:Option<(i64,Vec<u8>)>=tx.query_row("SELECT rowid,key_package FROM key_packages WHERE user_id=?1 ORDER BY rowid LIMIT 1",[recipient.to_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            let Some((row, package)) = package else {
                return Ok(Response::Rejected(Rejection::NotFound));
            };
            tx.execute("DELETE FROM key_packages WHERE rowid=?1", [row])?;
            tx.execute(
                "INSERT INTO package_allocations VALUES(?1,?2,unixepoch())",
                params![user.to_bytes().as_slice(), recipient.to_bytes().as_slice()],
            )?;
            Ok(Response::KeyPackage {
                recipient: *recipient,
                package,
            })
        }
        Request::AppendRoomOperation(operation) => {
            if !subscribed(tx, operation.room, user)? {
                return denied();
            }
            if operation.body.is_empty()
                || operation.body.len() > MAX_MLS_BLOB_BYTES
                || operation.parent >= i64::MAX as u64
                || operation
                    .welcome
                    .as_ref()
                    .is_some_and(|w| w.body.is_empty() || w.body.len() > MAX_MLS_BLOB_BYTES)
                || operation.body.len()
                    + operation.welcome.as_ref().map_or(0, |w| w.body.len())
                    + 256
                    > MAX_PAYLOAD
            {
                return Ok(Response::Rejected(Rejection::Invalid));
            }
            let head: u64 = tx.query_row(
                "SELECT coalesce(max(sequence),0) FROM delivery_events WHERE room=?1",
                [operation.room.to_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if head != operation.parent {
                return Ok(Response::HeadConflict {
                    room: operation.room,
                    head,
                });
            }
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM delivery_events WHERE event_id=?1)",
                [id.to_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if exists {
                return Ok(Response::Rejected(Rejection::RequestConflict));
            }
            let event = Event {
                id,
                sender: user,
                operation: Append {
                    room: operation.room,
                    parent: operation.parent,
                    epoch: operation.epoch,
                    content_type: operation.content_type,
                    body: std::mem::take(&mut operation.body),
                    welcome: operation.welcome.take(),
                },
            };
            let operation = &event.operation;
            let bytes = encode_message(&event).map_err(|_| corrupt())?;
            tx.execute(
                "INSERT INTO delivery_events VALUES(?1,?2,?3,?4,?5)",
                params![
                    operation.room.to_bytes().as_slice(),
                    head + 1,
                    id.to_bytes().as_slice(),
                    user.to_bytes().as_slice(),
                    bytes
                ],
            )?;
            drop(bytes);
            if let Some(welcome) = &operation.welcome {
                let delivery = WelcomeDelivery {
                    room_name: tx.query_row(
                        "SELECT name FROM rooms WHERE room_id=?1",
                        [operation.room.to_bytes().as_slice()],
                        |r| r.get(0),
                    )?,
                    cursor: 0,
                    event: id,
                    room: operation.room,
                    sequence: head + 1,
                    inviter: user,
                    attachment: welcome.clone(),
                };
                tx.execute(
                    "INSERT INTO delivery_welcomes(recipient,record) VALUES(?1,?2)",
                    params![
                        welcome.recipient.to_bytes().as_slice(),
                        encode_message(&delivery).map_err(|_| corrupt())?
                    ],
                )?;
                subscribe(tx, operation.room, welcome.recipient)?;
            }
            Ok(Response::AppendAccepted { event })
        }
        Request::FetchRoomEvents {
            room,
            after_sequence,
        } => {
            if *after_sequence > i64::MAX as u64 {
                return Ok(Response::Rejected(Rejection::Invalid));
            }
            if !subscribed(tx, *room, user)? {
                return denied();
            }
            let mut statement=tx.prepare("SELECT record FROM delivery_events WHERE room=?1 AND sequence>?2 ORDER BY sequence LIMIT 101")?;
            let rows = statement
                .query_map(params![room.to_bytes().as_slice(), *after_sequence], |r| {
                    r.get::<_, Vec<u8>>(0)
                })?;
            let mut events = Vec::new();
            let mut bytes = 0;
            let mut more = false;
            for row in rows {
                let row = row?;
                if events.len() == PAGE_SIZE || bytes + row.len() > MAX_PAYLOAD - 96 {
                    more = true;
                    break;
                }
                bytes += row.len();
                events.push(decode_message(&row).map_err(|_| corrupt())?);
            }
            Ok(Response::RoomEvents {
                room: *room,
                after_sequence: *after_sequence,
                events,
                more,
            })
        }
        Request::SyncIndex { after_room } => {
            let mut statement=tx.prepare("SELECT r.room_id,r.name,coalesce((SELECT max(sequence) FROM delivery_events e WHERE e.room=r.room_id),0) FROM rooms r JOIN room_subscribers s ON r.room_id=s.room_id WHERE s.user_id=?1 AND (?2 IS NULL OR r.room_id>?2) ORDER BY r.room_id LIMIT 101")?;
            let rows = statement.query_map(
                params![
                    user.to_bytes().as_slice(),
                    after_room.map(|r| r.to_bytes().to_vec())
                ],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, u64>(2)?,
                    ))
                },
            )?;
            let mut rooms = Vec::new();
            for row in rows {
                let (room, name, sequence) = row?;
                rooms.push(RoomHead {
                    room: RoomId::from_bytes(room.try_into().map_err(|_| corrupt())?),
                    name,
                    sequence,
                });
            }
            let more = rooms.len() > PAGE_SIZE;
            rooms.truncate(PAGE_SIZE);
            Ok(Response::SyncIndex { rooms, more })
        }
        Request::FetchWelcomes { after_cursor } => {
            if *after_cursor > i64::MAX as u64 {
                return Ok(Response::Rejected(Rejection::Invalid));
            }
            let mut statement=tx.prepare("SELECT cursor,record FROM delivery_welcomes WHERE recipient=?1 AND cursor>?2 ORDER BY cursor LIMIT 101")?;
            let rows = statement
                .query_map(params![user.to_bytes().as_slice(), *after_cursor], |r| {
                    Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?;
            let mut welcomes = Vec::new();
            let mut bytes = 0;
            let mut more = false;
            for row in rows {
                let (cursor, row) = row?;
                if welcomes.len() == PAGE_SIZE || bytes + row.len() > MAX_PAYLOAD - 96 {
                    more = true;
                    break;
                }
                bytes += row.len();
                let mut welcome: WelcomeDelivery = decode_message(&row).map_err(|_| corrupt())?;
                welcome.cursor = cursor;
                welcomes.push(welcome);
            }
            Ok(Response::Welcomes {
                after_cursor: *after_cursor,
                welcomes,
                more,
            })
        }
        Request::Acknowledge { events, welcomes } => {
            if events.len() + welcomes.len() > PAGE_SIZE {
                return Ok(Response::Rejected(Rejection::Invalid));
            }
            for event in events {
                let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM delivery_events e JOIN room_subscribers s ON s.room_id=e.room WHERE e.event_id=?1 AND s.user_id=?2)",params![event.to_bytes().as_slice(),user.to_bytes().as_slice()],|r|r.get(0))?;
                if !allowed {
                    return denied();
                }
            }
            for cursor in welcomes {
                let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM delivery_welcomes WHERE cursor=?1 AND recipient=?2)",params![*cursor,user.to_bytes().as_slice()],|r|r.get(0))?;
                if !allowed {
                    return denied();
                }
            }
            // Recovery cursors are deliberately independent of these advisory receipts.
            Ok(Response::Acknowledged)
        }
    }
}
fn subscribed(tx: &Transaction<'_>, room: RoomId, user: UserId) -> Result<bool, StorageError> {
    Ok(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM room_subscribers WHERE room_id=?1 AND user_id=?2)",
        params![room.to_bytes().as_slice(), user.to_bytes().as_slice()],
        |r| r.get(0),
    )?)
}
fn subscribe(tx: &Transaction<'_>, room: RoomId, user: UserId) -> Result<(), StorageError> {
    tx.execute(
        "INSERT OR IGNORE INTO room_subscribers VALUES(?1,?2)",
        params![room.to_bytes().as_slice(), user.to_bytes().as_slice()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user(n: u8) -> UserId {
        UserId::from_bytes([n; 16])
    }
    fn id(n: u128) -> MessageId {
        MessageId::from_bytes(n.to_be_bytes())
    }
    fn create(state: &RelayState) -> RoomId {
        let Response::RoomCreated { room } = state
            .deliver(
                user(1),
                id(1),
                Request::CreateRoom {
                    name: "Cave".into(),
                },
            )
            .unwrap()
        else {
            panic!("room creation failed")
        };
        room
    }
    fn append(room: RoomId, parent: u64, welcome: bool) -> Request {
        Request::AppendRoomOperation(Append {
            room,
            parent,
            epoch: 0,
            content_type: grotto_protocol::MlsContentType::Commit,
            body: vec![42],
            welcome: welcome.then(|| WelcomeAttachment {
                recipient: user(2),
                body: vec![43],
                signature: grotto_protocol::Ed25519SignatureBytes::new([0; 64]),
            }),
        })
    }
    #[test]
    fn index_and_maximum_records_make_progress_across_pages() {
        let dir = crate::private_test_directory().unwrap();
        let state = RelayState::open(&dir.path().join("relay.db")).unwrap();
        let room = create(&state);
        // Populate a large subscribed index independently of the creator's cap.
        for n in 2..=102u128 {
            let creator = UserId::from_bytes(n.to_be_bytes());
            let Response::RoomCreated { room } = state
                .deliver(
                    creator,
                    id(n),
                    Request::CreateRoom {
                        name: "Page".into(),
                    },
                )
                .unwrap()
            else {
                panic!()
            };
            state
                .lock_connection()
                .unwrap()
                .execute(
                    "INSERT INTO room_subscribers VALUES(?1,?2)",
                    params![room.to_bytes().as_slice(), user(1).to_bytes().as_slice()],
                )
                .unwrap();
        }
        let Response::SyncIndex { rooms, more } = state
            .deliver(user(1), id(200), Request::SyncIndex { after_room: None })
            .unwrap()
        else {
            panic!()
        };
        assert!(more);
        assert_eq!(rooms.len(), 100);
        let Response::SyncIndex { rooms: tail, more } = state
            .deliver(
                user(1),
                id(201),
                Request::SyncIndex {
                    after_room: Some(rooms.last().unwrap().room),
                },
            )
            .unwrap()
        else {
            panic!()
        };
        assert!(!more);
        assert_eq!(tail.len(), 2);
        assert!(tail[0].room.to_bytes() > rooms[99].room.to_bytes());
        let mut request = append(room, 0, true);
        let Request::AppendRoomOperation(op) = &mut request else {
            panic!()
        };
        op.body = vec![42; MAX_MLS_BLOB_BYTES];
        op.welcome.as_mut().unwrap().body = vec![43; MAX_PAYLOAD - MAX_MLS_BLOB_BYTES - 256];
        assert!(matches!(
            state.deliver(user(1), id(202), request).unwrap(),
            Response::AppendAccepted { .. }
        ));
        let response = state
            .deliver(
                user(2),
                id(203),
                Request::FetchRoomEvents {
                    room,
                    after_sequence: 0,
                },
            )
            .unwrap();
        let Response::RoomEvents { events, more, .. } = &response else {
            panic!()
        };
        assert_eq!(events.len(), 1);
        assert!(!more);
        assert!(
            grotto_protocol::encode_message(&grotto_protocol::RelayMessage::Delivery {
                request_id: id(203),
                response
            })
            .unwrap()
            .len()
                <= MAX_PAYLOAD
        );
    }

    #[test]
    fn conditional_append_conflicts_and_welcome_are_atomic_and_stable() {
        let dir = crate::private_test_directory().unwrap();
        let path = dir.path().join("relay.db");
        let state = RelayState::open(&path).unwrap();
        let room = create(&state);
        let accepted = state
            .deliver(user(1), id(2), append(room, 0, true))
            .unwrap();
        assert!(matches!(accepted, Response::AppendAccepted { .. }));
        let conflict = state
            .deliver(user(1), id(3), append(room, 0, true))
            .unwrap();
        assert_eq!(conflict, Response::HeadConflict { room, head: 1 });
        state
            .deliver(user(1), id(4), append(room, 1, false))
            .unwrap();
        assert_eq!(
            state
                .deliver(user(1), id(3), append(room, 0, true))
                .unwrap(),
            conflict
        );
        assert_eq!(
            state
                .deliver(user(1), id(2), append(room, 0, true))
                .unwrap(),
            accepted
        );
        assert_eq!(
            state
                .deliver(user(1), id(2), append(room, 1, true))
                .unwrap(),
            Response::Rejected(Rejection::RequestConflict)
        );
        let Response::Welcomes { welcomes, .. } = state
            .deliver(user(2), id(5), Request::FetchWelcomes { after_cursor: 0 })
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(welcomes.len(), 1);
        assert_eq!(welcomes[0].event, id(2));
        drop(state);
        let state = RelayState::open(&path).unwrap();
        assert_eq!(
            state
                .deliver(user(1), id(2), append(room, 0, true))
                .unwrap(),
            accepted
        );
    }
    #[test]
    fn sql_failure_rolls_back_event_welcome_head_and_attempt() {
        let dir = crate::private_test_directory().unwrap();
        let path = dir.path().join("relay.db");
        let state = RelayState::open(&path).unwrap();
        let room = create(&state);
        state.lock_connection().unwrap().execute_batch("CREATE TEMP TRIGGER fail_result BEFORE INSERT ON delivery_requests BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(
            state
                .deliver(user(1), id(2), append(room, 0, true))
                .is_err()
        );
        let connection = state.lock_connection().unwrap();
        for table in ["delivery_events", "delivery_welcomes"] {
            assert_eq!(
                connection
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, u64>(0))
                    .unwrap(),
                0
            );
        }
        drop(connection);
        drop(state);
        let state = RelayState::open(&path).unwrap();
        assert!(matches!(
            state
                .deliver(user(1), id(2), append(room, 0, true))
                .unwrap(),
            Response::AppendAccepted { .. }
        ));
    }
    #[test]
    fn recovery_paginates_independently_of_acknowledgements() {
        let dir = crate::private_test_directory().unwrap();
        let state = RelayState::open(&dir.path().join("relay.db")).unwrap();
        let room = create(&state);
        for n in 0..101 {
            state
                .deliver(user(1), id(n + 10), append(room, n as u64, true))
                .unwrap();
        }
        let Response::Welcomes { welcomes, more, .. } = state
            .deliver(user(2), id(500), Request::FetchWelcomes { after_cursor: 0 })
            .unwrap()
        else {
            panic!()
        };
        assert!(more);
        assert_eq!(welcomes.len(), 100);
        let cursor = welcomes.last().unwrap().cursor;
        let Response::Welcomes { welcomes, more, .. } = state
            .deliver(
                user(2),
                id(501),
                Request::FetchWelcomes {
                    after_cursor: cursor,
                },
            )
            .unwrap()
        else {
            panic!()
        };
        assert!(!more);
        assert_eq!(welcomes.len(), 1);
        let response = state
            .deliver(
                user(2),
                id(502),
                Request::FetchRoomEvents {
                    room,
                    after_sequence: 0,
                },
            )
            .unwrap();
        let Response::RoomEvents { events, more, .. } = &response else {
            panic!()
        };
        assert!(*more);
        assert_eq!(events.len(), 100);
        for event in events {
            assert_eq!(
                state
                    .deliver(
                        user(2),
                        grotto_protocol::delivery::acknowledgement_id(user(2), &[event.id], &[]),
                        Request::Acknowledge {
                            events: vec![event.id],
                            welcomes: vec![]
                        }
                    )
                    .unwrap(),
                Response::Acknowledged
            );
        }
        assert_eq!(
            response,
            state
                .deliver(
                    user(2),
                    id(504),
                    Request::FetchRoomEvents {
                        room,
                        after_sequence: 0
                    }
                )
                .unwrap()
        );
        assert_eq!(
            state
                .deliver(
                    user(3),
                    id(505),
                    Request::FetchRoomEvents {
                        room,
                        after_sequence: 0
                    }
                )
                .unwrap(),
            Response::Rejected(Rejection::Unauthorized)
        );
    }
    #[test]
    fn allocations_require_grants_are_stable_and_rate_limited() {
        let dir = crate::private_test_directory().unwrap();
        let state = RelayState::open(&dir.path().join("relay.db")).unwrap();
        state
            .deliver(
                user(2),
                id(1),
                Request::PublishKeyPackages {
                    packages: (0..8).map(|i| vec![i]).collect(),
                },
            )
            .unwrap();
        let request = Request::ReserveKeyPackage { recipient: user(2) };
        assert_eq!(
            state.deliver(user(1), id(2), request.clone()).unwrap(),
            Response::Rejected(Rejection::Unauthorized)
        );
        state
            .deliver(
                user(2),
                id(3),
                Request::SetFetchGrant {
                    requester: user(1),
                    allowed: true,
                },
            )
            .unwrap();
        let first = state.deliver(user(1), id(4), request.clone()).unwrap();
        assert!(matches!(first, Response::KeyPackage { .. }));
        assert_eq!(
            first,
            state.deliver(user(1), id(4), request.clone()).unwrap()
        );
        for n in 5..8 {
            assert!(matches!(
                state.deliver(user(1), id(n), request.clone()).unwrap(),
                Response::KeyPackage { .. }
            ));
        }
        assert_eq!(
            state.deliver(user(1), id(8), request.clone()).unwrap(),
            Response::Rejected(Rejection::Overloaded)
        );
        state
            .deliver(
                user(2),
                id(9),
                Request::SetFetchGrant {
                    requester: user(1),
                    allowed: false,
                },
            )
            .unwrap();
        assert_eq!(
            first,
            state.deliver(user(1), id(4), request.clone()).unwrap()
        );
        assert_eq!(
            state.deliver(user(1), id(10), request).unwrap(),
            Response::Rejected(Rejection::Unauthorized)
        );
        assert_eq!(
            state
                .deliver(
                    user(2),
                    id(1),
                    Request::PublishKeyPackages {
                        packages: vec![vec![99]]
                    }
                )
                .unwrap(),
            Response::Rejected(Rejection::RequestConflict)
        );
    }
    #[test]
    fn quotas_preserve_existing_results_and_recovery_reads() {
        let dir = crate::private_test_directory().unwrap();
        let path = dir.path().join("relay.db");
        let state = RelayState::open(&path).unwrap();
        let room = create(&state);
        let accepted = state
            .deliver(user(1), id(2), append(room, 0, true))
            .unwrap();
        drop(state);
        let state = RelayState::open_with_limits(
            &path,
            crate::limits::StorageLimits {
                global: 0,
                sender: 0,
                room: 0,
                reserve: 0,
            },
        )
        .unwrap();
        assert_eq!(
            accepted,
            state
                .deliver(user(1), id(2), append(room, 0, true))
                .unwrap()
        );
        assert_eq!(
            state
                .deliver(user(1), id(3), append(room, 1, true))
                .unwrap(),
            Response::Rejected(Rejection::Quota)
        );
        assert!(matches!(
            state
                .deliver(
                    user(2),
                    id(4),
                    Request::FetchRoomEvents {
                        room,
                        after_sequence: 0
                    }
                )
                .unwrap(),
            Response::RoomEvents { .. }
        ));
        assert_eq!(
            state
                .deliver(
                    user(2),
                    acknowledgement_id(user(2), &[id(2)], &[]),
                    Request::Acknowledge {
                        events: vec![id(2)],
                        welcomes: vec![]
                    }
                )
                .unwrap(),
            Response::Acknowledged
        );
    }
}
