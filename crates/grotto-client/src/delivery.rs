//! Serialized V9 application service. Transactions never cross network awaits.
use crate::{
    UserCommand,
    contacts::ContactCard,
    mls_session::{MlsSession, Processed},
    parse_command,
    store::ClientStore,
    terminal_safe,
};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use grotto_protocol::{
    ClientMessage, MessageId, MlsContentType, RelayMessage, RoomId, StoredRoomMessage, UserId,
    decode_message, delivery::*, encode_message, read_frame, write_frame,
};
use mls_rs::client_builder::MlsConfig;
use rusqlite::{OptionalExtension, params};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
type Error = Box<dyn std::error::Error + Send + Sync>;

struct Wire<W> {
    writer: W,
    incoming: mpsc::Receiver<Result<RelayMessage, Error>>,
}
impl<W: AsyncWrite + Unpin> Wire<W> {
    async fn request(&mut self, id: MessageId, request: Request) -> Result<Response, Error> {
        let bytes = encode_message(&ClientMessage::Delivery {
            request_id: id,
            request,
        })?;
        tokio::time::timeout(
            Duration::from_secs(10),
            write_frame(&mut self.writer, &bytes),
        )
        .await??;
        loop {
            let response = tokio::time::timeout(Duration::from_secs(30), self.incoming.recv())
                .await?
                .ok_or_else(crate::disconnected)??;
            match response {
                RelayMessage::DeliveryChanged => {}
                RelayMessage::Delivery {
                    request_id,
                    response,
                } if request_id == id => return Ok(response),
                _ => return Err("unexpected V9 response".into()),
            }
        }
    }
    async fn read(&mut self, request: Request) -> Result<Response, Error> {
        let id = MessageId::new()?;
        loop {
            let response = self.request(id, request.clone()).await?;
            if matches!(
                response,
                Response::Rejected(Rejection::Overloaded | Rejection::Internal)
            ) {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            return Ok(response);
        }
    }
}

async fn read_client_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>, Error> {
    use tokio::io::AsyncReadExt;
    let mut first = [0];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let mut framed = first.as_slice().chain(reader);
    Ok(tokio::time::timeout(Duration::from_secs(15), read_frame(&mut framed)).await??)
}

pub async fn run<S: AsyncRead + AsyncWrite + Unpin + Send + 'static, C: MlsConfig>(
    socket: S,
    store: Arc<ClientStore>,
    mls: MlsSession<C>,
    user: UserId,
    input: &mut mpsc::Receiver<std::io::Result<String>>,
) -> Result<(), Error> {
    let (mut reader, writer) = tokio::io::split(socket);
    let (sender, incoming) = mpsc::channel(2);
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        loop {
            let result = match read_client_frame(&mut reader).await {
                Ok(Some(bytes)) => decode_message(&bytes).map_err(|e| Box::new(e) as Error),
                Ok(None) => Err(crate::disconnected().into()),
                Err(e) => Err(e),
            };
            let terminal = result.is_err();
            if sender.send(result).await.is_err() || terminal {
                break;
            }
        }
    });
    let mut wire = Wire { writer, incoming };
    let mut engine = Engine { store, mls, user };
    let mut timer = tokio::time::interval(Duration::from_secs(30));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result=async {
        engine.drive(&mut wire).await?;
        loop {
            tokio::select! {
                line=input.recv()=>{
                    let Some(line)=line else {return Ok(());};
                    match parse_command(&line?) {
                        Ok(Some(command))=>{
                            if let Err(error)=engine.command(command) {eprintln!("Command rejected: {error}");}
                            engine.drive(&mut wire).await?;
                        }
                        Ok(None)=>{},Err(error)=>eprintln!("{error}"),
                    }
                }
                event=wire.incoming.recv()=>match event {
                    Some(Ok(RelayMessage::DeliveryChanged))=>engine.drive(&mut wire).await?,
                    Some(Err(error))=>return Err(error),
                    None=>return Err(crate::disconnected().into()),
                    _=>return Err("unexpected V9 response".into()),
                },
                _=timer.tick()=>{crate::metrics::report();engine.drive(&mut wire).await?;},
            }
        }
    }.await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

struct Engine<C: MlsConfig> {
    store: Arc<ClientStore>,
    mls: MlsSession<C>,
    user: UserId,
}
fn room_id(bytes: Vec<u8>) -> Result<RoomId, Error> {
    Ok(RoomId::from_bytes(
        bytes.try_into().map_err(|_| "invalid stored room")?,
    ))
}
fn user_id(bytes: Vec<u8>) -> Result<UserId, Error> {
    Ok(UserId::from_bytes(
        bytes.try_into().map_err(|_| "invalid stored user")?,
    ))
}
fn envelope(event: &Event) -> StoredRoomMessage {
    StoredRoomMessage {
        message_id: event.id,
        room_id: event.operation.room,
        sequence: event.operation.parent + 1,
        sender_id: event.sender,
        epoch: event.operation.epoch,
        content_type: event.operation.content_type,
        body: event.operation.body.clone(),
    }
}

impl<C: MlsConfig> Engine<C> {
    fn unresolved(&self, room: RoomId) -> Result<bool, Error> {
        Ok(self.store.lock()?.query_row("SELECT EXISTS(SELECT 1 FROM delivery_intents i JOIN outbox o ON o.request_id=i.attempt WHERE i.room=?1 AND NOT EXISTS(SELECT 1 FROM delivery_inbox e WHERE e.event_id=i.attempt))",[room.to_bytes().as_slice()],|r|r.get(0))?)
    }
    fn cursor(&self, room: RoomId) -> Result<u64, Error> {
        Ok(self
            .store
            .lock()?
            .query_row(
                "SELECT sequence FROM delivery_cursors WHERE room=?1",
                [room.to_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }
    fn journal(store: &ClientStore, id: MessageId, request: Request) -> Result<(), Error> {
        if !matches!(request, Request::Acknowledge { .. }) {
            store.admit_new_data(encode_message(&request)?.len())?;
        }
        store.save_outbox(
            id,
            "Delivery",
            &encode_message(&ClientMessage::Delivery {
                request_id: id,
                request,
            })?,
        )?;
        Ok(())
    }
    fn command(&mut self, command: UserCommand) -> Result<(), Error> {
        match command {
            UserCommand::ContactExport => {
                let card = ContactCard::own(&self.store)?;
                println!(
                    "Contact card: {}\nFingerprint: {}",
                    card.encode(),
                    card.fingerprint()
                );
            }
            UserCommand::ContactImport { card, fingerprint } => {
                ContactCard::parse(&card)?.import(&self.store, &fingerprint)?;
                println!("Contact verified");
            }
            UserCommand::ListContacts => {
                let connection = self.store.lock()?;
                let mut statement =
                    connection.prepare("SELECT card FROM verified_contacts ORDER BY user_id")?;
                let rows = statement.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
                for row in rows {
                    let bytes = row?;
                    let card = ContactCard::parse(
                        &bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    )?;
                    println!("{} {}", card.user, card.fingerprint());
                }
            }
            UserCommand::ListRooms => {
                for (room, name, _) in self.store.list_rooms()? {
                    println!("{room} {}", terminal_safe(&name));
                }
            }
            UserCommand::FetchRoomHistory {
                room_id,
                before_sequence,
            } => {
                for message in self.store.history(room_id, before_sequence)? {
                    println!(
                        "[{} #{}] {}: {}",
                        message.room_id,
                        message.sequence,
                        message.author,
                        terminal_safe(&String::from_utf8_lossy(&message.plaintext))
                    );
                }
            }
            UserCommand::CreateRoom(name) => {
                Self::journal(&self.store, MessageId::new()?, Request::CreateRoom { name })?;
            }
            UserCommand::PublishKeyPackages(count) => {
                let id = MessageId::new()?;
                let store = self.store.clone();
                self.mls.atomic(&store, |mls| {
                    let packages = mls.generate_key_packages(count)?;
                    Self::journal(&store, id, Request::PublishKeyPackages { packages })
                })?;
            }
            UserCommand::AddToRoom { room_id, user_id } => {
                self.require_contact(user_id)?;
                self.intent(room_id, Some(user_id), None)?;
            }
            UserCommand::SendRoomMessage { room_id, body } => {
                self.intent(room_id, None, Some(body))?
            }
            UserCommand::SyncWelcomes => {}
            UserCommand::SetFetchGrant { requester, allowed } => {
                self.require_contact(requester)?;
                Self::journal(
                    &self.store,
                    MessageId::new()?,
                    Request::SetFetchGrant { requester, allowed },
                )?;
            }
        }
        Ok(())
    }
    fn require_contact(&self, user: UserId) -> Result<ContactCard, Error> {
        let bytes: Vec<u8> = self.store.lock()?.query_row(
            "SELECT card FROM verified_contacts WHERE user_id=?1",
            [user.to_bytes().as_slice()],
            |r| r.get(0),
        )?;
        Ok(ContactCard::parse(
            &bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        )?)
    }
    fn intent(
        &mut self,
        room: RoomId,
        target: Option<UserId>,
        plaintext: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        self.store
            .admit_new_data(plaintext.as_ref().map_or(16, Vec::len))?;
        if !self.mls.has_group(room) {
            return Err("no verified MLS group for room".into());
        }
        self.store.lock()?.execute(
            "INSERT INTO delivery_intents(id,room,target,plaintext) VALUES(?1,?2,?3,?4)",
            params![
                MessageId::new()?.to_bytes().as_slice(),
                room.to_bytes().as_slice(),
                target.map(|u| u.to_bytes().to_vec()),
                plaintext
            ],
        )?;
        Ok(())
    }
    async fn drive<W: AsyncWrite + Unpin>(&mut self, wire: &mut Wire<W>) -> Result<(), Error> {
        let result = self.drive_inner(wire).await;
        if result.is_err() {
            crate::metrics::increment(&crate::metrics::RECOVERY_FAILURES);
        }
        result
    }
    async fn drive_inner<W: AsyncWrite + Unpin>(
        &mut self,
        wire: &mut Wire<W>,
    ) -> Result<(), Error> {
        // Resolve uncertain attempts before processing a competing history or rebuilding.
        for _ in 0..4 {
            let mut after = 0;
            loop {
                let page = self.store.outbox_page(after)?;
                if page.is_empty() {
                    break;
                }
                for (rowid, entry) in page {
                    after = rowid;
                    let ClientMessage::Delivery {
                        request_id,
                        request,
                    } = decode_message(&entry.message)?
                    else {
                        return Err("unsupported old outbox protocol".into());
                    };
                    if request_id != entry.request_id {
                        return Err("outbox ID mismatch".into());
                    }
                    let response = wire.request(request_id, request.clone()).await?;
                    self.complete(request_id, &request, response)?;
                }
            }
            self.synchronize(wire).await?;
            if !self.build_attempts()? {
                break;
            }
        }
        Ok(())
    }
    fn complete(
        &mut self,
        id: MessageId,
        request: &Request,
        response: Response,
    ) -> Result<(), Error> {
        let store = self.store.clone();
        match (request, response) {
            (Request::CreateRoom { name }, Response::RoomCreated { room }) => {
                self.mls.atomic(&store, |mls| {
                    mls.create_group(room)?;
                    store.upsert_room(room, name, "created")?;
                    store.lock()?.execute(
                        "INSERT OR IGNORE INTO delivery_cursors VALUES(?1,0)",
                        [room.to_bytes().as_slice()],
                    )?;
                    store.remove_outbox(id)?;
                    Ok(())
                })?;
                println!("Room created: {} ({room})", terminal_safe(name));
            }
            (
                Request::PublishKeyPackages { packages },
                Response::KeyPackagesPublished { count },
            ) if count == packages.len() as u64 => {
                store.remove_outbox(id)?;
                println!("Published {count} key package(s)");
            }
            (Request::SetFetchGrant { .. }, Response::FetchGrantSet) => {
                store.remove_outbox(id)?;
                println!("KeyPackage fetch grant updated");
            }
            (
                Request::ReserveKeyPackage { recipient },
                Response::KeyPackage {
                    recipient: actual,
                    package,
                },
            ) if *recipient == actual => {
                let message = grotto_mls::from_wire(&package)?;
                let identity = message
                    .as_key_package()
                    .ok_or("response is not a KeyPackage")?
                    .signing_identity()
                    .clone();
                let actual =
                    crate::contacts::VerifiedIdentityProvider(store.clone()).verify(&identity)?;
                if actual != recipient.to_bytes() {
                    return Err("KeyPackage target mismatch".into());
                }
                let tx = store.transaction()?;
                let changed=store.lock()?.execute("UPDATE delivery_intents SET package=?1,attempt=NULL WHERE attempt=?2 AND target=?3",params![package,id.to_bytes().as_slice(),recipient.to_bytes().as_slice()])?;
                if changed != 1 {
                    return Err("reservation has no matching durable target".into());
                }
                store.remove_outbox(id)?;
                tx.commit()?;
            }
            (Request::AppendRoomOperation(operation), Response::AppendAccepted { event })
                if event.id == id && event.sender == self.user && event.operation == *operation =>
            {
                self.receive(&event)?;
            }
            (Request::AppendRoomOperation(operation), Response::HeadConflict { room, head })
                if room == operation.room && head != operation.parent =>
            {
                self.mls.atomic(&store, |mls| {
                    if operation.content_type == MlsContentType::Commit {
                        mls.discard_pending(room)?;
                    }
                    store.remove_outbox(id)?;
                    store.lock()?.execute(
                        "DELETE FROM authenticated_history WHERE message_id=?1",
                        [id.to_bytes().as_slice()],
                    )?;
                    store.lock()?.execute(
                        "UPDATE delivery_intents SET attempt=NULL WHERE attempt=?1",
                        [id.to_bytes().as_slice()],
                    )?;
                    Ok(())
                })?;
                crate::metrics::increment(&crate::metrics::COMMIT_CONFLICTS);
                eprintln!("Commit conflict in {room}; synchronizing before rebuilding");
            }
            (
                _,
                Response::Rejected(Rejection::Overloaded | Rejection::Quota | Rejection::Internal),
            ) => eprintln!("Relay temporarily rejected the operation; exact retry retained"),
            (_, Response::Rejected(reason)) => {
                self.mls.atomic(&store, |mls| {
                    if let Request::AppendRoomOperation(op) = request
                        && op.content_type == MlsContentType::Commit
                    {
                        mls.discard_pending(op.room)?;
                    }
                    store.lock()?.execute(
                        "DELETE FROM delivery_intents WHERE attempt=?1",
                        [id.to_bytes().as_slice()],
                    )?;
                    store.remove_outbox(id)?;
                    Ok(())
                })?;
                eprintln!("Operation rejected: {reason:?}");
            }
            (Request::Acknowledge { .. }, Response::Acknowledged) => {
                store.remove_outbox(id)?;
            }
            _ => return Err("response differs from durable operation".into()),
        }
        Ok(())
    }
    fn receive(&self, event: &Event) -> Result<(), Error> {
        let room = event.operation.room;
        let sequence = event
            .sequence()
            .filter(|s| *s <= i64::MAX as u64)
            .ok_or("invalid event sequence")?;
        let bytes = encode_message(event)?;
        let connection = self.store.lock()?;
        let existing: Option<Vec<u8>> = connection
            .query_row(
                "SELECT record FROM delivery_inbox WHERE event_id=?1 OR (room=?2 AND sequence=?3)",
                params![
                    event.id.to_bytes().as_slice(),
                    room.to_bytes().as_slice(),
                    sequence
                ],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != bytes {
                return Err("relay equivocated about an event".into());
            }
        } else {
            drop(connection);
            self.store.admit_new_data(bytes.len())?;
            self.store.lock()?.execute(
                "INSERT INTO delivery_inbox(event_id,room,sequence,record) VALUES(?1,?2,?3,?4)",
                params![
                    event.id.to_bytes().as_slice(),
                    room.to_bytes().as_slice(),
                    sequence,
                    bytes
                ],
            )?;
        }
        Ok(())
    }
    fn build_attempts(&mut self) -> Result<bool, Error> {
        type IntentRow = (
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let rows: Vec<IntentRow> = {
            let connection = self.store.lock()?;
            let mut statement=connection.prepare("SELECT id,room,target,plaintext,package FROM delivery_intents WHERE attempt IS NULL")?;
            statement
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<Result<_, _>>()?
        };
        let mut built = false;
        for (intent, room, target, plaintext, package) in rows {
            let room = room_id(room)?;
            if !self.mls.has_group(room) {
                continue;
            }
            // A blocked prerequisite must be resolved before generating new MLS state.
            let room_cursor = self.cursor(room)?;
            let blocked: bool = self.store.lock()?.query_row(
                "SELECT EXISTS(SELECT 1 FROM delivery_inbox WHERE room=?1 AND sequence>?2)",
                params![room.to_bytes().as_slice(), room_cursor],
                |r| r.get(0),
            )?;
            if blocked {
                continue;
            }
            let target = target.map(user_id).transpose()?;
            let id = MessageId::new()?;
            let parent = self.cursor(room)?;
            let store = self.store.clone();
            let signing = store.identity()?;
            self.mls.atomic(&store, |mls| {
                let request = if let (Some(recipient), None) = (target, package.as_ref()) {
                    Request::ReserveKeyPackage { recipient }
                } else {
                    let aad = event_authenticated_data(room, id, parent);
                    let (epoch, body, welcome, content_type) = if let Some(package) = &package {
                        let (epoch, body, welcome) = mls.build_pending_add(room, package, aad)?;
                        let recipient = target.ok_or("add intent has no target")?;
                        let signature = signing.signing_key().sign(&welcome_transcript(
                            recipient,
                            room,
                            id,
                            parent + 1,
                            &welcome,
                        ));
                        (
                            epoch,
                            body,
                            Some(WelcomeAttachment {
                                recipient,
                                body: welcome,
                                signature: grotto_protocol::Ed25519SignatureBytes::new(
                                    signature.to_bytes(),
                                ),
                            }),
                            MlsContentType::Commit,
                        )
                    } else {
                        let plaintext = plaintext.as_ref().ok_or("send intent has no plaintext")?;
                        let (epoch, body) = mls.encrypt_bound(room, plaintext, aad)?;
                        let event = Event {
                            id,
                            sender: self.user,
                            operation: Append {
                                room,
                                parent,
                                epoch,
                                content_type: MlsContentType::Application,
                                body: body.clone(),
                                welcome: None,
                            },
                        };
                        store.record_plaintext(&envelope(&event), self.user, plaintext)?;
                        (epoch, body, None, MlsContentType::Application)
                    };
                    Request::AppendRoomOperation(Append {
                        room,
                        parent,
                        epoch,
                        body,
                        welcome,
                        content_type,
                    })
                };
                Self::journal(&store, id, request)?;
                store.lock()?.execute(
                    "UPDATE delivery_intents SET attempt=?1 WHERE id=?2",
                    params![id.to_bytes().as_slice(), intent],
                )?;
                Ok(())
            })?;
            built = true;
        }
        Ok(built)
    }
    async fn synchronize<W: AsyncWrite + Unpin>(
        &mut self,
        wire: &mut Wire<W>,
    ) -> Result<(), Error> {
        loop {
            let cursor: u64 = self.store.lock()?.query_row(
                "SELECT welcome_cursor FROM delivery_meta WHERE id=1",
                [],
                |r| r.get(0),
            )?;
            let Response::Welcomes {
                after_cursor,
                welcomes,
                more,
            } = wire
                .read(Request::FetchWelcomes {
                    after_cursor: cursor,
                })
                .await?
            else {
                return Err("invalid Welcome recovery response".into());
            };
            if after_cursor != cursor || (more && welcomes.is_empty()) {
                return Err("invalid Welcome page cursor".into());
            }
            if welcomes.is_empty() {
                break;
            }
            self.store.admit_new_data(
                welcomes
                    .iter()
                    .map(|w| w.attachment.body.len() + 1024)
                    .sum(),
            )?;
            let tx = self.store.transaction()?;
            let mut last = cursor;
            for welcome in welcomes {
                if welcome.cursor <= last || welcome.attachment.recipient != self.user {
                    return Err("Welcome cursor or target mismatch".into());
                }
                last = welcome.cursor;
                self.store.lock()?.execute(
                    "INSERT INTO welcome_inbox(cursor,record) VALUES(?1,?2)",
                    params![welcome.cursor, encode_message(&welcome)?],
                )?;
            }
            self.store.lock()?.execute(
                "UPDATE delivery_meta SET welcome_cursor=?1 WHERE id=1",
                [last],
            )?;
            tx.commit()?;
            if !more {
                break;
            }
        }
        self.process_welcomes()?;
        let mut after_room = None;
        loop {
            let Response::SyncIndex { rooms, more } =
                wire.read(Request::SyncIndex { after_room }).await?
            else {
                return Err("invalid room index response".into());
            };
            if more && rooms.is_empty() {
                return Err("empty continuing room index".into());
            }
            for head in rooms {
                if after_room.is_some_and(|r: RoomId| r.to_bytes() >= head.room.to_bytes()) {
                    return Err("room index is not ordered".into());
                }
                if head.sequence > i64::MAX as u64 || head.sequence < self.cursor(head.room)? {
                    return Err("invalid or regressing room head".into());
                }
                after_room = Some(head.room);
                self.store
                    .upsert_room(head.room, &head.name, "subscribed")?;
                if self.unresolved(head.room)? || !self.mls.has_group(head.room) {
                    continue;
                }
                while self.cursor(head.room)? < head.sequence {
                    let cursor = self.cursor(head.room)?;
                    let Response::RoomEvents {
                        room,
                        after_sequence,
                        events,
                        more: _,
                    } = wire
                        .read(Request::FetchRoomEvents {
                            room: head.room,
                            after_sequence: cursor,
                        })
                        .await?
                    else {
                        return Err("invalid room recovery response".into());
                    };
                    if room != head.room || after_sequence != cursor || events.is_empty() {
                        return Err("room history omitted a required sequence".into());
                    }
                    for (expected, event) in (cursor..).zip(events.iter()) {
                        if event.operation.room != room || event.operation.parent != expected {
                            return Err("noncontiguous room event page".into());
                        }
                        self.receive(event)?;
                    }
                    let mut blocked = false;
                    for event in events {
                        if !self.apply_event(&event)? {
                            blocked = true;
                            break;
                        }
                    }
                    if blocked {
                        break;
                    }
                }
            }
            if !more {
                break;
            }
        }
        Ok(())
    }
    fn process_welcomes(&mut self) -> Result<(), Error> {
        let mut after = 0u64;
        loop {
            let row:Option<(u64,Vec<u8>)>=self.store.lock()?.query_row("SELECT cursor,record FROM welcome_inbox WHERE cursor>?1 AND state IN ('received','blocked') ORDER BY cursor LIMIT 1",[after],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
            let Some((cursor, bytes)) = row else {
                break;
            };
            after = cursor;
            let welcome: WelcomeDelivery = decode_message(&bytes)?;
            let verified = (|| -> Result<(), Error> {
                if welcome.sequence == 0 || welcome.sequence > i64::MAX as u64 {
                    return Err("invalid Welcome boundary".into());
                }
                let card = self.require_contact(welcome.inviter)?;
                VerifyingKey::from_bytes(&card.transport_key)?.verify_strict(
                    &welcome_transcript(
                        self.user,
                        welcome.room,
                        welcome.event,
                        welcome.sequence,
                        &welcome.attachment.body,
                    ),
                    &Signature::from_bytes(welcome.attachment.signature.as_bytes()),
                )?;
                Ok(())
            })();
            if verified.is_err() {
                crate::metrics::increment(&crate::metrics::BLOCKED_ROOMS);
                self.store.lock()?.execute(
                    "UPDATE welcome_inbox SET state='blocked' WHERE cursor=?1",
                    [cursor],
                )?;
                continue;
            }
            let store = self.store.clone();
            let result = self.mls.atomic(&store, |mls| {
                if mls.has_group(welcome.room) {
                    return Err("room already exists; refusing another Welcome boundary".into());
                }
                mls.join(welcome.room, &welcome.attachment.body)?;
                if !mls.contains_user(welcome.room, welcome.inviter)? {
                    return Err("Welcome signer is not a group member".into());
                }
                store.lock()?.execute(
                    "INSERT INTO delivery_cursors VALUES(?1,?2)",
                    params![welcome.room.to_bytes().as_slice(), welcome.sequence],
                )?;
                store.upsert_room(welcome.room, &welcome.room_name, "welcomed")?;
                store.lock()?.execute(
                    "UPDATE welcome_inbox SET state='applied' WHERE cursor=?1",
                    [cursor],
                )?;
                Self::journal(
                    &store,
                    acknowledgement_id(self.user, &[], &[cursor]),
                    Request::Acknowledge {
                        events: vec![],
                        welcomes: vec![cursor],
                    },
                )?;
                Ok(())
            });
            if result.is_err() {
                crate::metrics::increment(&crate::metrics::BLOCKED_ROOMS);
                store.lock()?.execute(
                    "UPDATE welcome_inbox SET state='blocked' WHERE cursor=?1",
                    [cursor],
                )?;
            } else {
                println!(
                    "Joined room '{}' ({})",
                    terminal_safe(&welcome.room_name),
                    welcome.room
                );
            }
        }
        Ok(())
    }
    fn apply_event(&mut self, event: &Event) -> Result<bool, Error> {
        let room = event.operation.room;
        if self.cursor(room)? != event.operation.parent {
            return Err("attempted noncontiguous MLS processing".into());
        }
        let own = self.store.find_outbox(event.id)?;
        let store = self.store.clone();
        let result = self.mls.atomic(&store, |mls| {
            let plaintext = if event.sender == self.user {
                let entry = own
                    .as_ref()
                    .ok_or("own event has no exact durable attempt")?;
                let ClientMessage::Delivery {
                    request_id,
                    request: Request::AppendRoomOperation(operation),
                } = decode_message(&entry.message)?
                else {
                    return Err("invalid own attempt".into());
                };
                if request_id != event.id || operation != event.operation {
                    return Err("own event differs from exact attempt".into());
                }
                if operation.content_type == MlsContentType::Commit {
                    mls.apply_accepted_commit(room)?;
                }
                store.remove_outbox(event.id)?;
                store.lock()?.execute(
                    "DELETE FROM delivery_intents WHERE attempt=?1",
                    [event.id.to_bytes().as_slice()],
                )?;
                store.lock()?.execute(
                    "UPDATE authenticated_history SET sequence=?1 WHERE message_id=?2",
                    params![event.operation.parent + 1, event.id.to_bytes().as_slice()],
                )?;
                None
            } else {
                match mls.process_bound(event)? {
                    Processed::Application { plaintext, author } => {
                        let author = user_id(author)?;
                        store.record_plaintext(&envelope(event), author, &plaintext)?;
                        Some((author, plaintext))
                    }
                    _ => None,
                }
            };
            Self::finish_event(&store, self.user, event, "applied")?;
            #[cfg(test)]
            crash_boundary("before-apply-commit");
            Ok(plaintext)
        });
        match result {
            Ok(plaintext) => {
                #[cfg(test)]
                crash_boundary("after-apply-commit");
                if let Some((author, plaintext)) = plaintext {
                    println!(
                        "[{room} #{}] {author}: {}",
                        event.operation.parent + 1,
                        terminal_safe(&String::from_utf8_lossy(&plaintext))
                    );
                } else if event.sender == self.user
                    && event.operation.content_type == MlsContentType::Application
                {
                    let messages = store.history(room, None)?;
                    if let Some(message) = messages.iter().find(|m| m.message_id == event.id) {
                        println!(
                            "[{room} #{}] {}: {}",
                            message.sequence,
                            self.user,
                            terminal_safe(&String::from_utf8_lossy(&message.plaintext))
                        );
                    }
                }
                Ok(true)
            }
            Err(error) => {
                let Some(fault) = error.downcast_ref::<crate::mls_session::ProcessingFault>()
                else {
                    return Err(error);
                };
                if matches!(fault, crate::mls_session::ProcessingFault::Blocked) {
                    store.lock()?.execute(
                        "UPDATE delivery_inbox SET state='blocked' WHERE event_id=?1",
                        [event.id.to_bytes().as_slice()],
                    )?;
                    crate::metrics::increment(&crate::metrics::BLOCKED_ROOMS);
                    eprintln!("Room {room} blocked pending a verified prerequisite");
                    Ok(false)
                } else {
                    let tx = store.transaction()?;
                    Self::finish_event(&store, self.user, event, "rejected")?;
                    tx.commit()?;
                    eprintln!("Rejected unauthenticated event {}", event.id);
                    Ok(true)
                }
            }
        }
    }
    fn finish_event(
        store: &ClientStore,
        user: UserId,
        event: &Event,
        state: &str,
    ) -> Result<(), Error> {
        store.lock()?.execute(
            "UPDATE delivery_inbox SET state=?1 WHERE event_id=?2",
            params![state, event.id.to_bytes().as_slice()],
        )?;
        store.lock()?.execute("INSERT INTO delivery_cursors VALUES(?1,?2) ON CONFLICT(room) DO UPDATE SET sequence=excluded.sequence",params![event.operation.room.to_bytes().as_slice(),event.operation.parent+1])?;
        Self::journal(
            store,
            acknowledgement_id(user, &[event.id], &[]),
            Request::Acknowledge {
                events: vec![event.id],
                welcomes: vec![],
            },
        )
    }
}

#[cfg(test)]
fn crash_boundary(point: &str) {
    if std::env::var("GROTTO_DELIVERY_CRASH_POINT").as_deref() == Ok(point) {
        std::process::exit(77);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls_storage::tests::{pin, session, store};
    use grotto_relay::storage::RelayState;
    fn engine(store: Arc<ClientStore>) -> Engine<impl MlsConfig> {
        Engine {
            mls: session(&store),
            user: store.identity().unwrap().user_id(),
            store,
        }
    }
    #[test]
    fn reservation_response_cannot_substitute_target_or_signing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let a = store(dir.path(), "a");
        let b = store(dir.path(), "b");
        let c = store(dir.path(), "c");
        pin(&a, &b);
        pin(&a, &c);
        let mut alice = engine(a.clone());
        let mut carol = engine(c.clone());
        let bob = b.identity().unwrap().user_id();
        let room = RoomId::new().unwrap();
        alice.mls.atomic(&a, |mls| mls.create_group(room)).unwrap();
        alice.intent(room, Some(bob), None).unwrap();
        assert!(alice.build_attempts().unwrap());
        let entry = a.load_outbox().unwrap().remove(0);
        let ClientMessage::Delivery {
            request_id,
            request,
        } = decode_message(&entry.message).unwrap()
        else {
            panic!()
        };
        assert!(
            alice
                .complete(
                    request_id,
                    &request,
                    Response::KeyPackage {
                        recipient: carol.user,
                        package: vec![]
                    }
                )
                .is_err()
        );
        let package = carol
            .mls
            .atomic(&c, |mls| mls.generate_key_packages(1))
            .unwrap()
            .remove(0);
        assert!(
            alice
                .complete(
                    request_id,
                    &request,
                    Response::KeyPackage {
                        recipient: bob,
                        package
                    }
                )
                .is_err()
        );
        assert_eq!(
            a.find_outbox(request_id).unwrap().unwrap().message,
            entry.message
        );
    }

    #[test]
    fn envelope_claims_and_aad_fail_without_consuming_the_valid_generation() {
        let dir = tempfile::tempdir().unwrap();
        let a = store(dir.path(), "a");
        let b = store(dir.path(), "b");
        pin(&a, &b);
        pin(&b, &a);
        let mut alice = engine(a.clone());
        let mut bob = engine(b.clone());
        let room = RoomId::new().unwrap();
        alice.mls.atomic(&a, |mls| mls.create_group(room)).unwrap();
        let package = bob
            .mls
            .atomic(&b, |mls| mls.generate_key_packages(1))
            .unwrap()
            .remove(0);
        let (_, _, welcome) = alice
            .mls
            .atomic(&a, |mls| mls.build_add(room, &package))
            .unwrap();
        bob.mls.atomic(&b, |mls| mls.join(room, &welcome)).unwrap();
        let id = MessageId::new().unwrap();
        let (epoch, body) = alice
            .mls
            .atomic(&a, |mls| {
                mls.encrypt_bound(
                    room,
                    b"authenticated",
                    event_authenticated_data(room, id, 1),
                )
            })
            .unwrap();
        let event = Event {
            id,
            sender: alice.user,
            operation: Append {
                room,
                parent: 1,
                epoch,
                content_type: MlsContentType::Application,
                body,
                welcome: None,
            },
        };
        for mode in 0..5 {
            let mut forged = event.clone();
            match mode {
                0 => forged.sender = bob.user,
                1 => forged.id = MessageId::new().unwrap(),
                2 => forged.operation.parent = 2,
                3 => forged.operation.content_type = MlsContentType::Commit,
                _ => forged.operation.epoch += 1,
            }
            assert!(
                bob.mls
                    .atomic(&b, |mls| mls.process_bound(&forged))
                    .is_err()
            );
        }
        let Processed::Application { plaintext, author } =
            bob.mls.atomic(&b, |mls| mls.process_bound(&event)).unwrap()
        else {
            panic!()
        };
        assert_eq!(plaintext, b"authenticated");
        assert_eq!(author, alice.user.to_bytes());
    }

    fn wire(
        state: Arc<RelayState>,
        user: UserId,
        tasks: &mut tokio::task::JoinSet<()>,
    ) -> Wire<tokio::io::DuplexStream> {
        let (writer, mut reader) = tokio::io::duplex(1024 * 1024);
        let (sender, incoming) = mpsc::channel(2);
        tasks.spawn(async move {
            while let Ok(Some(bytes)) = read_frame(&mut reader).await {
                let ClientMessage::Delivery {
                    request_id,
                    request,
                } = decode_message(&bytes).unwrap()
                else {
                    panic!("legacy wire")
                };
                let response = state.deliver(user, request_id, request).unwrap();
                if sender
                    .send(Ok(RelayMessage::Delivery {
                        request_id,
                        response,
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Wire { writer, incoming }
    }
    async fn reserve_only<C: MlsConfig>(
        engine: &mut Engine<C>,
        wire: &mut Wire<tokio::io::DuplexStream>,
    ) {
        assert!(engine.build_attempts().unwrap());
        for entry in engine.store.load_outbox().unwrap() {
            let ClientMessage::Delivery {
                request_id,
                request,
            } = decode_message(&entry.message).unwrap()
            else {
                panic!()
            };
            let response = wire.request(request_id, request.clone()).await.unwrap();
            engine.complete(request_id, &request, response).unwrap();
        }
        assert!(engine.build_attempts().unwrap());
    }
    #[tokio::test]
    async fn concurrent_adds_rebuild_and_all_members_converge_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let stores: Vec<_> = (0..4)
            .map(|n| store(dir.path(), &format!("client{n}")))
            .collect();
        for a in &stores {
            for b in &stores {
                pin(a, b);
            }
        }
        let state = Arc::new(RelayState::open(&dir.path().join("relay/relay.db")).unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        let mut alice = engine(stores[0].clone());
        let mut bob = engine(stores[1].clone());
        let mut carol = engine(stores[2].clone());
        let mut dave = engine(stores[3].clone());
        let mut aw = wire(state.clone(), alice.user, &mut tasks);
        let mut bw = wire(state.clone(), bob.user, &mut tasks);
        let mut cw = wire(state.clone(), carol.user, &mut tasks);
        let mut dw = wire(state.clone(), dave.user, &mut tasks);
        let bob_user = bob.user;
        for (engine, wire, requester) in [
            (&mut bob, &mut bw, alice.user),
            (&mut carol, &mut cw, alice.user),
            (&mut dave, &mut dw, bob_user),
        ] {
            engine.command(UserCommand::PublishKeyPackages(1)).unwrap();
            engine
                .command(UserCommand::SetFetchGrant {
                    requester,
                    allowed: true,
                })
                .unwrap();
            engine.drive(wire).await.unwrap();
        }
        alice
            .command(UserCommand::CreateRoom("Concurrent".into()))
            .unwrap();
        alice.drive(&mut aw).await.unwrap();
        let room = alice.store.list_rooms().unwrap()[0].0;
        alice
            .command(UserCommand::AddToRoom {
                room_id: room,
                user_id: bob.user,
            })
            .unwrap();
        alice.drive(&mut aw).await.unwrap();
        bob.drive(&mut bw).await.unwrap();
        assert_eq!(alice.cursor(room).unwrap(), 1);
        assert_eq!(bob.cursor(room).unwrap(), 1);
        alice
            .command(UserCommand::AddToRoom {
                room_id: room,
                user_id: carol.user,
            })
            .unwrap();
        bob.command(UserCommand::AddToRoom {
            room_id: room,
            user_id: dave.user,
        })
        .unwrap();
        reserve_only(&mut alice, &mut aw).await;
        reserve_only(&mut bob, &mut bw).await;
        // Both commits are durable but neither has been applied locally.
        assert_eq!(alice.mls.current_epoch(room).unwrap(), 1);
        assert_eq!(bob.mls.current_epoch(room).unwrap(), 1);
        // Reload Bob with his pending commit before the race resolves.
        drop(bob);
        let mut bob = engine(stores[1].clone());
        alice.drive(&mut aw).await.unwrap();
        bob.drive(&mut bw).await.unwrap();
        alice.drive(&mut aw).await.unwrap();
        carol.drive(&mut cw).await.unwrap();
        dave.drive(&mut dw).await.unwrap();
        for member in [&mut alice, &mut bob, &mut carol, &mut dave] {
            assert_eq!(member.cursor(room).unwrap(), 3);
            assert_eq!(member.mls.current_epoch(room).unwrap(), 3);
        }
        bob.command(UserCommand::SendRoomMessage {
            room_id: room,
            body: b"converged".to_vec(),
        })
        .unwrap();
        bob.drive(&mut bw).await.unwrap();
        for (member, wire) in [
            (&mut alice, &mut aw),
            (&mut carol, &mut cw),
            (&mut dave, &mut dw),
        ] {
            member.drive(wire).await.unwrap();
            assert_eq!(
                member.store.history(room, None).unwrap()[0].plaintext,
                b"converged"
            );
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    #[tokio::test]
    async fn receiving_sql_failure_never_rejects_or_advances_the_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let a = store(dir.path(), "a");
        let b = store(dir.path(), "b");
        pin(&a, &b);
        pin(&b, &a);
        let state = Arc::new(RelayState::open(&dir.path().join("relay/relay.db")).unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        let mut alice = engine(a.clone());
        let mut bob = engine(b.clone());
        let mut aw = wire(state.clone(), alice.user, &mut tasks);
        let mut bw = wire(state, bob.user, &mut tasks);
        bob.command(UserCommand::PublishKeyPackages(1)).unwrap();
        bob.command(UserCommand::SetFetchGrant {
            requester: alice.user,
            allowed: true,
        })
        .unwrap();
        bob.drive(&mut bw).await.unwrap();
        alice
            .command(UserCommand::CreateRoom("Atomic".into()))
            .unwrap();
        alice.drive(&mut aw).await.unwrap();
        let room = alice.store.list_rooms().unwrap()[0].0;
        alice
            .command(UserCommand::AddToRoom {
                room_id: room,
                user_id: bob.user,
            })
            .unwrap();
        alice.drive(&mut aw).await.unwrap();
        bob.drive(&mut bw).await.unwrap();
        alice
            .command(UserCommand::SendRoomMessage {
                room_id: room,
                body: b"durable".to_vec(),
            })
            .unwrap();
        alice.drive(&mut aw).await.unwrap();
        b.lock().unwrap().execute_batch("CREATE TEMP TRIGGER fail_history BEFORE INSERT ON authenticated_history BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(bob.drive(&mut bw).await.is_err());
        assert_eq!(bob.cursor(room).unwrap(), 1);
        assert!(b.history(room, None).unwrap().is_empty());
        b.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_history")
            .unwrap();
        drop(bob);
        let mut bob = engine(b.clone());
        bob.drive(&mut bw).await.unwrap();
        assert_eq!(bob.cursor(room).unwrap(), 2);
        let history = b.history(room, None).unwrap();
        bob.drive(&mut bw).await.unwrap();
        assert_eq!(b.history(room, None).unwrap(), history);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    #[test]
    fn crash_child_delivery() {
        let Some(path) = std::env::var_os("GROTTO_DELIVERY_CRASH_DATABASE") else {
            return;
        };
        let store = Arc::new(ClientStore::open(std::path::Path::new(&path)).unwrap());
        let mut engine = engine(store.clone());
        let entry = store
            .load_outbox()
            .unwrap()
            .into_iter()
            .find(|e| {
                matches!(
                    decode_message::<ClientMessage>(&e.message),
                    Ok(ClientMessage::Delivery {
                        request: Request::AppendRoomOperation(_),
                        ..
                    })
                )
            })
            .unwrap();
        let ClientMessage::Delivery {
            request_id,
            request: Request::AppendRoomOperation(operation),
        } = decode_message(&entry.message).unwrap()
        else {
            panic!()
        };
        let event = Event {
            id: request_id,
            sender: engine.user,
            operation,
        };
        engine.receive(&event).unwrap();
        engine.apply_event(&event).unwrap();
        panic!("crash boundary did not exit");
    }

    #[test]
    fn process_crash_preserves_pending_commit_exact_attempt_and_welcome() {
        for point in ["before-apply-commit", "after-apply-commit"] {
            let dir = tempfile::tempdir().unwrap();
            let a = store(dir.path(), "a");
            let b = store(dir.path(), "b");
            pin(&a, &b);
            pin(&b, &a);
            let mut alice = engine(a.clone());
            let mut bob = engine(b.clone());
            let room = RoomId::new().unwrap();
            alice
                .mls
                .atomic(&a, |mls| {
                    mls.create_group(room)?;
                    a.upsert_room(room, "Crash", "created")?;
                    a.lock()?.execute(
                        "INSERT INTO delivery_cursors VALUES(?1,0)",
                        [room.to_bytes().as_slice()],
                    )?;
                    Ok(())
                })
                .unwrap();
            let package = bob
                .mls
                .atomic(&b, |mls| mls.generate_key_packages(1))
                .unwrap()
                .remove(0);
            alice.intent(room, Some(bob.user), None).unwrap();
            a.lock()
                .unwrap()
                .execute("UPDATE delivery_intents SET package=?1", [package])
                .unwrap();
            alice.build_attempts().unwrap();
            let original = a.load_outbox().unwrap().remove(0).message;
            let ClientMessage::Delivery {
                request_id,
                request: Request::AppendRoomOperation(operation),
            } = decode_message(&original).unwrap()
            else {
                panic!()
            };
            let event = Event {
                id: request_id,
                sender: alice.user,
                operation,
            };
            let welcome = event.operation.welcome.as_ref().unwrap().body.clone();
            drop(alice);
            drop(a);
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "delivery::tests::crash_child_delivery"])
                .env(
                    "GROTTO_DELIVERY_CRASH_DATABASE",
                    dir.path().join("a/client.db"),
                )
                .env("GROTTO_DELIVERY_CRASH_POINT", point)
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(77),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let a = Arc::new(ClientStore::open(&dir.path().join("a/client.db")).unwrap());
            let mut alice = engine(a.clone());
            if point == "before-apply-commit" {
                assert_eq!(alice.cursor(room).unwrap(), 0);
                assert!(
                    a.load_outbox()
                        .unwrap()
                        .iter()
                        .any(|e| e.message == original)
                );
                alice.receive(&event).unwrap();
                alice.apply_event(&event).unwrap();
            }
            assert_eq!(alice.cursor(room).unwrap(), 1);
            assert_eq!(alice.mls.current_epoch(room).unwrap(), 1);
            bob.mls.atomic(&b, |mls| mls.join(room, &welcome)).unwrap();
            let id = MessageId::new().unwrap();
            let (epoch, body) = alice
                .mls
                .atomic(&a, |mls| {
                    mls.encrypt_bound(room, b"after crash", event_authenticated_data(room, id, 1))
                })
                .unwrap();
            let event = Event {
                id,
                sender: alice.user,
                operation: Append {
                    room,
                    parent: 1,
                    epoch,
                    body,
                    welcome: None,
                    content_type: MlsContentType::Application,
                },
            };
            let Processed::Application { plaintext, .. } =
                bob.mls.atomic(&b, |mls| mls.process_bound(&event)).unwrap()
            else {
                panic!()
            };
            assert_eq!(plaintext, b"after crash");
        }
    }
}
