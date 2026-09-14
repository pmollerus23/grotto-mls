//! V9 delivery records. The relay treats MLS bodies as opaque bytes.
use crate::{Ed25519SignatureBytes, MessageId, MlsContentType, RoomId, UserId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_PAYLOAD: usize = 768 * 1024;
pub const PAGE_SIZE: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Append {
    pub room: RoomId,
    pub parent: u64,
    pub epoch: u64,
    pub content_type: MlsContentType,
    #[serde(deserialize_with = "body")]
    pub body: Vec<u8>,
    pub welcome: Option<WelcomeAttachment>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeAttachment {
    pub recipient: UserId,
    #[serde(deserialize_with = "body")]
    pub body: Vec<u8>,
    pub signature: Ed25519SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: MessageId,
    pub sender: UserId,
    pub operation: Append,
}
impl Event {
    pub fn sequence(&self) -> Option<u64> {
        self.operation.parent.checked_add(1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeDelivery {
    #[serde(deserialize_with = "name")]
    pub room_name: String,
    pub cursor: u64,
    pub event: MessageId,
    pub room: RoomId,
    pub sequence: u64,
    pub inviter: UserId,
    pub attachment: WelcomeAttachment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomHead {
    pub room: RoomId,
    #[serde(deserialize_with = "name")]
    pub name: String,
    pub sequence: u64,
}

/// Variant positions are reserved forever within the fresh V9 outer tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    CreateRoom {
        name: String,
    },
    PublishKeyPackages {
        packages: Vec<Vec<u8>>,
    },
    Acknowledge {
        events: Vec<MessageId>,
        welcomes: Vec<u64>,
    },
    AppendRoomOperation(Append),
    FetchRoomEvents {
        room: RoomId,
        after_sequence: u64,
    },
    SyncIndex {
        after_room: Option<RoomId>,
    },
    FetchWelcomes {
        after_cursor: u64,
    },
    ReserveKeyPackage {
        recipient: UserId,
    },
    SetFetchGrant {
        requester: UserId,
        allowed: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    RoomCreated {
        room: RoomId,
    },
    KeyPackagesPublished {
        count: u64,
    },
    Acknowledged,
    AppendAccepted {
        event: Event,
    },
    HeadConflict {
        room: RoomId,
        head: u64,
    },
    RoomEvents {
        room: RoomId,
        after_sequence: u64,
        events: Vec<Event>,
        more: bool,
    },
    SyncIndex {
        rooms: Vec<RoomHead>,
        more: bool,
    },
    Welcomes {
        after_cursor: u64,
        welcomes: Vec<WelcomeDelivery>,
        more: bool,
    },
    KeyPackage {
        recipient: UserId,
        package: Vec<u8>,
    },
    FetchGrantSet,
    Rejected(Rejection),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    Invalid,
    Unauthorized,
    NotFound,
    RequestConflict,
    Overloaded,
    Quota,
    Internal,
}

pub fn event_authenticated_data(room: RoomId, event: MessageId, parent: u64) -> Vec<u8> {
    [
        b"GROTTO-EVENT-V9\0".as_slice(),
        &room.to_bytes(),
        &event.to_bytes(),
        &parent.to_be_bytes(),
    ]
    .concat()
}

pub fn welcome_transcript(
    recipient: UserId,
    room: RoomId,
    event: MessageId,
    sequence: u64,
    body: &[u8],
) -> Vec<u8> {
    [
        b"GROTTO-WELCOME-V9\0".as_slice(),
        &recipient.to_bytes(),
        &room.to_bytes(),
        &event.to_bytes(),
        &sequence.to_be_bytes(),
        &Sha256::digest(body),
    ]
    .concat()
}

pub fn payload_hash(request: &Request) -> Result<[u8; 32], postcard::Error> {
    Ok(Sha256::digest(crate::encode_message(request)?).into())
}

fn bounded_vec<'de, D, T, const N: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {N} elements")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            use serde::de::Error;
            if sequence.size_hint().is_some_and(|n| n > N) {
                return Err(A::Error::custom("collection limit exceeded"));
            }
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() == N {
                    return Err(A::Error::custom("collection limit exceeded"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded::<T, N>(std::marker::PhantomData))
}
fn body<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec::<D, u8, { 512 * 1024 }>(d)
}
fn events<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Event>, D::Error> {
    bounded_vec::<D, Event, 100>(d)
}
fn rooms<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<RoomHead>, D::Error> {
    bounded_vec::<D, RoomHead, 100>(d)
}
fn welcomes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<WelcomeDelivery>, D::Error> {
    bounded_vec::<D, WelcomeDelivery, 100>(d)
}
fn ids<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<MessageId>, D::Error> {
    bounded_vec::<D, MessageId, 100>(d)
}
fn cursors<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
    bounded_vec::<D, u64, 100>(d)
}
fn packages<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
    #[derive(Deserialize)]
    struct Package(#[serde(deserialize_with = "package")] Vec<u8>);
    Ok(bounded_vec::<D, Package, 64>(d)?
        .into_iter()
        .map(|p| p.0)
        .collect())
}
fn package<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec::<D, u8, { 16 * 1024 }>(d)
}
fn name<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    use serde::de::Error;
    let text = <&str>::deserialize(d)?;
    if text.len() > 400 {
        return Err(D::Error::custom("room name limit exceeded"));
    }
    Ok(text.to_owned())
}

impl Serialize for Request {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::CreateRoom { name } => crate::serialize_tagged(serializer, 0, (name,)),
            Self::PublishKeyPackages { packages } => {
                crate::serialize_tagged(serializer, 1, (packages,))
            }
            Self::Acknowledge { events, welcomes } => {
                crate::serialize_tagged(serializer, 2, (events, welcomes))
            }
            Self::AppendRoomOperation(operation) => {
                crate::serialize_tagged(serializer, 3, (operation,))
            }
            Self::FetchRoomEvents {
                room,
                after_sequence,
            } => crate::serialize_tagged(serializer, 4, (room, after_sequence)),
            Self::SyncIndex { after_room } => crate::serialize_tagged(serializer, 5, (after_room,)),
            Self::FetchWelcomes { after_cursor } => {
                crate::serialize_tagged(serializer, 6, (after_cursor,))
            }
            Self::ReserveKeyPackage { recipient } => {
                crate::serialize_tagged(serializer, 7, (recipient,))
            }
            Self::SetFetchGrant { requester, allowed } => {
                crate::serialize_tagged(serializer, 8, (requester, allowed))
            }
        }
    }
}
impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Tagged;
        impl<'de> serde::de::Visitor<'de> for Tagged {
            type Value = Request;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an explicitly tagged V9 delivery record")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;
                match crate::required::<_, u8>(&mut sequence, "tag")? {
                    0 => Ok(Request::CreateRoom {
                        name: crate::required::<_, Boundedname>(&mut sequence, "name")?.0,
                    }),
                    1 => Ok(Request::PublishKeyPackages {
                        packages: crate::required::<_, Boundedpackages>(&mut sequence, "packages")?
                            .0,
                    }),
                    2 => Ok(Request::Acknowledge {
                        events: crate::required::<_, Boundedids>(&mut sequence, "events")?.0,
                        welcomes: crate::required::<_, Boundedcursors>(&mut sequence, "welcomes")?
                            .0,
                    }),
                    3 => Ok(Request::AppendRoomOperation(crate::required(
                        &mut sequence,
                        "operation",
                    )?)),
                    4 => Ok(Request::FetchRoomEvents {
                        room: crate::required(&mut sequence, "room")?,
                        after_sequence: crate::required(&mut sequence, "after_sequence")?,
                    }),
                    5 => Ok(Request::SyncIndex {
                        after_room: crate::required(&mut sequence, "after_room")?,
                    }),
                    6 => Ok(Request::FetchWelcomes {
                        after_cursor: crate::required(&mut sequence, "after_cursor")?,
                    }),
                    7 => Ok(Request::ReserveKeyPackage {
                        recipient: crate::required(&mut sequence, "recipient")?,
                    }),
                    8 => Ok(Request::SetFetchGrant {
                        requester: crate::required(&mut sequence, "requester")?,
                        allowed: crate::required(&mut sequence, "allowed")?,
                    }),
                    tag => Err(A::Error::custom(format_args!("unknown delivery tag {tag}"))),
                }
            }
        }
        d.deserialize_tuple(3, Tagged)
    }
}

impl Serialize for Response {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::RoomCreated { room } => crate::serialize_tagged(serializer, 0, (room,)),
            Self::KeyPackagesPublished { count } => {
                crate::serialize_tagged(serializer, 1, (count,))
            }
            Self::Acknowledged => crate::serialize_tagged(serializer, 2, ()),
            Self::AppendAccepted { event } => crate::serialize_tagged(serializer, 3, (event,)),
            Self::HeadConflict { room, head } => {
                crate::serialize_tagged(serializer, 4, (room, head))
            }
            Self::RoomEvents {
                room,
                after_sequence,
                events,
                more,
            } => crate::serialize_tagged(serializer, 5, (room, after_sequence, events, more)),
            Self::SyncIndex { rooms, more } => {
                crate::serialize_tagged(serializer, 6, (rooms, more))
            }
            Self::Welcomes {
                after_cursor,
                welcomes,
                more,
            } => crate::serialize_tagged(serializer, 7, (after_cursor, welcomes, more)),
            Self::KeyPackage { recipient, package } => {
                crate::serialize_tagged(serializer, 8, (recipient, package))
            }
            Self::FetchGrantSet => crate::serialize_tagged(serializer, 9, ()),
            Self::Rejected(reason) => crate::serialize_tagged(serializer, 10, (reason,)),
        }
    }
}
impl<'de> Deserialize<'de> for Response {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Tagged;
        impl<'de> serde::de::Visitor<'de> for Tagged {
            type Value = Response;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an explicitly tagged V9 delivery record")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;
                match crate::required::<_, u8>(&mut sequence, "tag")? {
                    0 => Ok(Response::RoomCreated {
                        room: crate::required(&mut sequence, "room")?,
                    }),
                    1 => Ok(Response::KeyPackagesPublished {
                        count: crate::required(&mut sequence, "count")?,
                    }),
                    2 => Ok(Response::Acknowledged),
                    3 => Ok(Response::AppendAccepted {
                        event: crate::required(&mut sequence, "event")?,
                    }),
                    4 => Ok(Response::HeadConflict {
                        room: crate::required(&mut sequence, "room")?,
                        head: crate::required(&mut sequence, "head")?,
                    }),
                    5 => Ok(Response::RoomEvents {
                        room: crate::required(&mut sequence, "room")?,
                        after_sequence: crate::required(&mut sequence, "after_sequence")?,
                        events: crate::required::<_, Boundedevents>(&mut sequence, "events")?.0,
                        more: crate::required(&mut sequence, "more")?,
                    }),
                    6 => Ok(Response::SyncIndex {
                        rooms: crate::required::<_, Boundedrooms>(&mut sequence, "rooms")?.0,
                        more: crate::required(&mut sequence, "more")?,
                    }),
                    7 => Ok(Response::Welcomes {
                        after_cursor: crate::required(&mut sequence, "after_cursor")?,
                        welcomes: crate::required::<_, Boundedwelcomes>(&mut sequence, "welcomes")?
                            .0,
                        more: crate::required(&mut sequence, "more")?,
                    }),
                    8 => Ok(Response::KeyPackage {
                        recipient: crate::required(&mut sequence, "recipient")?,
                        package: crate::required::<_, Boundedpackage>(&mut sequence, "package")?.0,
                    }),
                    9 => Ok(Response::FetchGrantSet),
                    10 => Ok(Response::Rejected(crate::required(
                        &mut sequence,
                        "reason",
                    )?)),
                    tag => Err(A::Error::custom(format_args!("unknown delivery tag {tag}"))),
                }
            }
        }
        d.deserialize_tuple(5, Tagged)
    }
}

#[derive(Deserialize)]
struct Boundedname(#[serde(deserialize_with = "name")] String);

#[derive(Deserialize)]
struct Boundedpackages(#[serde(deserialize_with = "packages")] Vec<Vec<u8>>);

#[derive(Deserialize)]
struct Boundedids(#[serde(deserialize_with = "ids")] Vec<MessageId>);

#[derive(Deserialize)]
struct Boundedcursors(#[serde(deserialize_with = "cursors")] Vec<u64>);

#[derive(Deserialize)]
struct Boundedevents(#[serde(deserialize_with = "events")] Vec<Event>);

#[derive(Deserialize)]
struct Boundedrooms(#[serde(deserialize_with = "rooms")] Vec<RoomHead>);

#[derive(Deserialize)]
struct Boundedwelcomes(#[serde(deserialize_with = "welcomes")] Vec<WelcomeDelivery>);

#[derive(Deserialize)]
struct Boundedpackage(#[serde(deserialize_with = "package")] Vec<u8>);

impl Serialize for Rejection {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(match self {
            Self::Invalid => 0,
            Self::Unauthorized => 1,
            Self::NotFound => 2,
            Self::RequestConflict => 3,
            Self::Overloaded => 4,
            Self::Quota => 5,
            Self::Internal => 6,
        })
    }
}
impl<'de> Deserialize<'de> for Rejection {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        match u8::deserialize(d)? {
            0 => Ok(Self::Invalid),
            1 => Ok(Self::Unauthorized),
            2 => Ok(Self::NotFound),
            3 => Ok(Self::RequestConflict),
            4 => Ok(Self::Overloaded),
            5 => Ok(Self::Quota),
            6 => Ok(Self::Internal),
            tag => Err(D::Error::custom(format_args!(
                "unknown rejection tag {tag}"
            ))),
        }
    }
}

/// One receipt has one canonical attempt ID, preventing fresh IDs from expanding
/// the recovery journal indefinitely for the same delivered record.
pub fn acknowledgement_id(user: UserId, events: &[MessageId], welcomes: &[u64]) -> MessageId {
    let mut hash = Sha256::new();
    hash.update(b"GROTTO-RECEIPT-V9\0");
    hash.update(user.to_bytes());
    hash.update((events.len() as u64).to_be_bytes());
    for event in events {
        hash.update(event.to_bytes());
    }
    hash.update((welcomes.len() as u64).to_be_bytes());
    for cursor in welcomes {
        hash.update(cursor.to_be_bytes());
    }
    let digest = hash.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    MessageId::from_bytes(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_delivery_tag_matches_sanitized_byte_fixtures() {
        let request_id = MessageId::from_bytes([0x11; 16]);
        let room = RoomId::from_bytes([0x22; 16]);
        let user = UserId::from_bytes([0x33; 16]);
        let event_id = MessageId::from_bytes([0x44; 16]);
        let append = Append {
            room,
            parent: 7,
            epoch: 3,
            content_type: MlsContentType::Commit,
            body: vec![1, 2, 3],
            welcome: None,
        };
        let event = Event {
            id: event_id,
            sender: user,
            operation: append.clone(),
        };
        let requests = [
            Request::CreateRoom {
                name: "Cave".into(),
            },
            Request::PublishKeyPackages {
                packages: vec![vec![0xaa, 0xbb]],
            },
            Request::Acknowledge {
                events: vec![event_id],
                welcomes: vec![],
            },
            Request::AppendRoomOperation(append),
            Request::FetchRoomEvents {
                room,
                after_sequence: 7,
            },
            Request::SyncIndex {
                after_room: Some(room),
            },
            Request::FetchWelcomes { after_cursor: 7 },
            Request::ReserveKeyPackage { recipient: user },
            Request::SetFetchGrant {
                requester: user,
                allowed: true,
            },
        ];
        let responses = [
            Response::RoomCreated { room },
            Response::KeyPackagesPublished { count: 2 },
            Response::Acknowledged,
            Response::AppendAccepted {
                event: event.clone(),
            },
            Response::HeadConflict { room, head: 9 },
            Response::RoomEvents {
                room,
                after_sequence: 7,
                events: vec![event],
                more: false,
            },
            Response::SyncIndex {
                rooms: vec![RoomHead {
                    room,
                    name: "Cave".into(),
                    sequence: 9,
                }],
                more: false,
            },
            Response::Welcomes {
                after_cursor: 0,
                welcomes: vec![WelcomeDelivery {
                    room_name: "Cave".into(),
                    cursor: 1,
                    event: event_id,
                    room,
                    sequence: 8,
                    inviter: user,
                    attachment: WelcomeAttachment {
                        recipient: UserId::from_bytes([0x55; 16]),
                        body: vec![0xaa, 0xbb],
                        signature: Ed25519SignatureBytes::new([0x66; 64]),
                    },
                }],
                more: false,
            },
            Response::KeyPackage {
                recipient: user,
                package: vec![0xaa, 0xbb],
            },
            Response::FetchGrantSet,
            Response::Rejected(Rejection::RequestConflict),
        ];
        let fixtures: std::collections::HashMap<_, _> = include_str!("../tests/fixtures/v9.hex")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.split_once(' ').unwrap())
            .collect();
        for (index, request) in requests.into_iter().enumerate() {
            let bytes = crate::encode_message(&crate::ClientMessage::Delivery {
                request_id,
                request: request.clone(),
            })
            .unwrap();
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, fixtures[format!("request_{index}").as_str()]);
            let crate::ClientMessage::Delivery {
                request: decoded, ..
            } = crate::decode_message(&bytes).unwrap()
            else {
                panic!()
            };
            assert_eq!(request, decoded);
        }
        for (index, response) in responses.into_iter().enumerate() {
            let bytes = crate::encode_message(&crate::RelayMessage::Delivery {
                request_id,
                response: response.clone(),
            })
            .unwrap();
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, fixtures[format!("response_{index}").as_str()]);
            let crate::RelayMessage::Delivery {
                response: decoded, ..
            } = crate::decode_message(&bytes).unwrap()
            else {
                panic!()
            };
            assert_eq!(response, decoded);
        }
    }
    #[test]
    fn malicious_collection_lengths_and_aggregate_payload_are_rejected() {
        let mut frame = vec![100];
        frame.extend([1; 16]);
        frame.extend([1, 65]);
        assert!(crate::decode_message::<crate::ClientMessage>(&frame).is_err());
        let mut frame = vec![100];
        frame.extend([1; 16]);
        frame.extend([1, 1, 0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert!(crate::decode_message::<crate::ClientMessage>(&frame).is_err());
        let request = Request::PublishKeyPackages {
            packages: vec![vec![0; 16 * 1024]; 64],
        };
        assert!(crate::encode_message(&request).is_err());
        let data = event_authenticated_data(
            RoomId::from_bytes([1; 16]),
            MessageId::from_bytes([2; 16]),
            3,
        );
        assert_ne!(
            data,
            event_authenticated_data(
                RoomId::from_bytes([1; 16]),
                MessageId::from_bytes([2; 16]),
                4
            )
        );
        assert_ne!(
            welcome_transcript(
                UserId::from_bytes([1; 16]),
                RoomId::from_bytes([2; 16]),
                MessageId::from_bytes([3; 16]),
                4,
                b"first"
            ),
            welcome_transcript(
                UserId::from_bytes([1; 16]),
                RoomId::from_bytes([2; 16]),
                MessageId::from_bytes([3; 16]),
                4,
                b"second"
            )
        );
    }
}
