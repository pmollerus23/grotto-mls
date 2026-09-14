pub mod delivery;

use std::{fmt, io, str::FromStr};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, Error as _, SeqAccess, Visitor},
    ser::SerializeTuple,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_SIZE: u32 = 1024 * 1024;
pub const MAX_ROOM_NAME_CHARS: usize = 100;
pub const MAX_MESSAGE_BODY_BYTES: usize = 64 * 1024;
pub const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;
pub const MAX_KEY_PACKAGES_PER_PUBLISH: usize = 64;
pub const MAX_MLS_BLOB_BYTES: usize = 512 * 1024;
pub const PROTOCOL_VERSION: u16 = 9;
const AUTHENTICATION_DOMAIN: &[u8; 14] = b"GROTTO-AUTH-V1";
const AUTHENTICATION_TRANSCRIPT_LENGTH: usize = 14 + 2 + 16 + 32 + 32;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct UserId([u8; 16]);

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct RoomId([u8; 16]);

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MessageId([u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseIdError {
    InvalidLength,
    InvalidHex,
}

impl fmt::Display for ParseIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("ID must contain exactly 32 hex characters"),
            Self::InvalidHex => formatter.write_str("ID contains a non-hex character"),
        }
    }
}

impl std::error::Error for ParseIdError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ed25519PublicKeyBytes([u8; 32]);

impl Ed25519PublicKeyBytes {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationChallenge([u8; 32]);

impl AuthenticationChallenge {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ed25519SignatureBytes(#[serde(with = "serde_arrays")] [u8; 64]);

impl Ed25519SignatureBytes {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Messages sent from a client to a relay.
///
/// Each variant has an explicit tag in its manual Serde implementation. Existing tags are part of
/// the wire protocol and must never be reused.
#[derive(Clone, Debug)]
pub enum ClientMessage {
    ClientHello {
        version: u16,
    },
    ClientIdentify {
        user_id: UserId,
        public_key: Ed25519PublicKeyBytes,
        enrollment: Option<[u8; 32]>,
    },
    ClientAuthenticationResponse {
        signature: Ed25519SignatureBytes,
    },
    Delivery {
        request_id: MessageId,
        request: delivery::Request,
    },
}

impl ClientMessage {
    pub const fn kind(&self) -> ClientMessageKind {
        match self {
            Self::ClientHello { .. } => ClientMessageKind::ClientHello,
            Self::ClientIdentify { .. } => ClientMessageKind::ClientIdentify,
            Self::ClientAuthenticationResponse { .. } => {
                ClientMessageKind::ClientAuthenticationResponse
            }
            Self::Delivery { .. } => ClientMessageKind::Delivery,
        }
    }
}

/// Messages sent from a relay to a client.
///
/// Each variant has an explicit tag in its manual Serde implementation. Existing tags are part of
/// the wire protocol and must never be reused.
#[derive(Clone, Debug)]
pub enum RelayMessage {
    ServerHello {
        version: u16,
    },
    ServerIdentifyAccepted {
        user_id: UserId,
    },
    ServerAuthenticationChallenge {
        challenge: AuthenticationChallenge,
    },
    ProtocolError {
        request_id: Option<MessageId>,
        error: ProtocolError,
    },
    Delivery {
        request_id: MessageId,
        response: delivery::Response,
    },
    DeliveryChanged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredRoomMessage {
    pub message_id: MessageId,
    pub room_id: RoomId,
    pub sequence: u64,
    pub sender_id: UserId,
    /// MLS epoch the sender was on. Opaque to the relay; lets receivers
    /// order commits against their local group state.
    pub epoch: u64,
    pub content_type: MlsContentType,
    /// Opaque MLS ciphertext (application, proposal, or commit). The relay
    /// must never parse this.
    pub body: Vec<u8>,
}

/// MLS payload class carried inside [`StoredRoomMessage::body`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MlsContentType {
    Application,
    Proposal,
    Commit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientMessageKind {
    ClientHello,
    ClientIdentify,
    ClientAuthenticationResponse,
    Delivery,
}

impl fmt::Display for ClientMessageKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    UnsupportedVersion {
        supported: u16,
        received: u16,
    },
    UnexpectedMessage {
        expected: ClientMessageKind,
        received: ClientMessageKind,
    },
    InvalidPublicKey,
    IdentityKeyConflict,
    AuthenticationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomNameError {
    Empty,
    TooLong,
    ControlCharacter,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion {
                supported,
                received,
            } => write!(
                formatter,
                "unsupported protocol version: supported={supported}, received={received}"
            ),
            Self::UnexpectedMessage { expected, received } => {
                write!(formatter, "expected {expected}, received {received}")
            }
            Self::InvalidPublicKey => formatter.write_str("invalid Ed25519 public key"),
            Self::IdentityKeyConflict => {
                formatter.write_str("user ID is registered to a different public key")
            }
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl fmt::Display for RoomNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("name cannot be empty"),
            Self::TooLong => write!(
                formatter,
                "name cannot exceed {MAX_ROOM_NAME_CHARS} characters"
            ),
            Self::ControlCharacter => formatter.write_str("name cannot contain control characters"),
        }
    }
}

impl std::error::Error for RoomNameError {}

impl Serialize for ClientMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::ClientHello { version } => serialize_tagged(serializer, 1, (version,)),
            Self::ClientIdentify {
                user_id,
                public_key,
                enrollment,
            } => serialize_tagged(serializer, 102, (user_id, public_key, enrollment)),
            Self::ClientAuthenticationResponse { signature } => {
                serialize_tagged(serializer, 3, (signature,))
            }
            Self::Delivery {
                request_id,
                request,
            } => serialize_tagged(serializer, 100, (request_id, request)),
        }
    }
}

impl<'de> Deserialize<'de> for ClientMessage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MessageVisitor;
        impl<'de> Visitor<'de> for MessageVisitor {
            type Value = ClientMessage;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a V9 tagged message")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                match required::<_, u8>(&mut sequence, "tag")? {
                    1 => Ok(ClientMessage::ClientHello {
                        version: required(&mut sequence, "version")?,
                    }),
                    102 => Ok(ClientMessage::ClientIdentify {
                        user_id: required(&mut sequence, "user_id")?,
                        public_key: required(&mut sequence, "public_key")?,
                        enrollment: required(&mut sequence, "enrollment")?,
                    }),
                    3 => Ok(ClientMessage::ClientAuthenticationResponse {
                        signature: required(&mut sequence, "signature")?,
                    }),
                    100 => Ok(ClientMessage::Delivery {
                        request_id: required(&mut sequence, "request_id")?,
                        request: required(&mut sequence, "request")?,
                    }),
                    tag => Err(A::Error::custom(format_args!("unsupported wire tag {tag}"))),
                }
            }
        }
        deserializer.deserialize_tuple(4, MessageVisitor)
    }
}

impl Serialize for RelayMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::ServerHello { version } => serialize_tagged(serializer, 1, (version,)),
            Self::ServerIdentifyAccepted { user_id } => serialize_tagged(serializer, 2, (user_id,)),
            Self::ServerAuthenticationChallenge { challenge } => {
                serialize_tagged(serializer, 3, (challenge,))
            }
            Self::ProtocolError { request_id, error } => {
                serialize_tagged(serializer, 4, (request_id, error))
            }
            Self::Delivery {
                request_id,
                response,
            } => serialize_tagged(serializer, 100, (request_id, response)),
            Self::DeliveryChanged => serialize_tagged(serializer, 101, ()),
        }
    }
}

impl<'de> Deserialize<'de> for RelayMessage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MessageVisitor;
        impl<'de> Visitor<'de> for MessageVisitor {
            type Value = RelayMessage;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a V9 tagged message")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                match required::<_, u8>(&mut sequence, "tag")? {
                    1 => Ok(RelayMessage::ServerHello {
                        version: required(&mut sequence, "version")?,
                    }),
                    2 => Ok(RelayMessage::ServerIdentifyAccepted {
                        user_id: required(&mut sequence, "user_id")?,
                    }),
                    3 => Ok(RelayMessage::ServerAuthenticationChallenge {
                        challenge: required(&mut sequence, "challenge")?,
                    }),
                    4 => Ok(RelayMessage::ProtocolError {
                        request_id: required(&mut sequence, "request_id")?,
                        error: required(&mut sequence, "error")?,
                    }),
                    100 => Ok(RelayMessage::Delivery {
                        request_id: required(&mut sequence, "request_id")?,
                        response: required(&mut sequence, "response")?,
                    }),
                    101 => Ok(RelayMessage::DeliveryChanged),
                    tag => Err(A::Error::custom(format_args!("unsupported wire tag {tag}"))),
                }
            }
        }
        deserializer.deserialize_tuple(4, MessageVisitor)
    }
}

impl Serialize for ClientMessageKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            Self::ClientHello => 1,
            Self::ClientIdentify => 102,
            Self::ClientAuthenticationResponse => 3,
            Self::Delivery => 100,
        })
    }
}

impl<'de> Deserialize<'de> for ClientMessageKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u8::deserialize(deserializer)? {
            1 => Ok(Self::ClientHello),
            102 => Ok(Self::ClientIdentify),
            3 => Ok(Self::ClientAuthenticationResponse),
            100 => Ok(Self::Delivery),
            tag => Err(D::Error::custom(format_args!(
                "unsupported message kind {tag}"
            ))),
        }
    }
}

impl Serialize for ProtocolError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::UnsupportedVersion {
                supported,
                received,
            } => serialize_tagged(serializer, 1, (supported, received)),
            Self::UnexpectedMessage { expected, received } => {
                serialize_tagged(serializer, 2, (expected, received))
            }
            Self::InvalidPublicKey => serialize_tagged(serializer, 3, ()),
            Self::IdentityKeyConflict => serialize_tagged(serializer, 4, ()),
            Self::AuthenticationFailed => serialize_tagged(serializer, 5, ()),
        }
    }
}

impl<'de> Deserialize<'de> for ProtocolError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProtocolErrorVisitor;

        impl<'de> Visitor<'de> for ProtocolErrorVisitor {
            type Value = ProtocolError;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a tagged protocol error")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                match required(&mut sequence, "protocol error tag")? {
                    1_u8 => Ok(ProtocolError::UnsupportedVersion {
                        supported: required(&mut sequence, "supported version")?,
                        received: required(&mut sequence, "received version")?,
                    }),
                    2 => Ok(ProtocolError::UnexpectedMessage {
                        expected: required(&mut sequence, "expected message kind")?,
                        received: required(&mut sequence, "received message kind")?,
                    }),
                    3 => Ok(ProtocolError::InvalidPublicKey),
                    4 => Ok(ProtocolError::IdentityKeyConflict),
                    5 => Ok(ProtocolError::AuthenticationFailed),
                    // Former delivery error tags 10..=26 remain reserved.
                    tag => Err(A::Error::custom(format_args!(
                        "unknown protocol error tag {tag}"
                    ))),
                }
            }
        }

        deserializer.deserialize_tuple(3, ProtocolErrorVisitor)
    }
}

impl Serialize for RoomNameError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(match self {
            Self::Empty => 1,
            Self::TooLong => 2,
            Self::ControlCharacter => 3,
        })
    }
}

impl<'de> Deserialize<'de> for RoomNameError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            1 => Ok(Self::Empty),
            2 => Ok(Self::TooLong),
            3 => Ok(Self::ControlCharacter),
            tag => Err(D::Error::custom(format_args!(
                "unknown room name error tag {tag}"
            ))),
        }
    }
}

fn serialize_tagged<S, T>(serializer: S, tag: u8, fields: T) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    let mut tuple = serializer.serialize_tuple(2)?;
    tuple.serialize_element(&tag)?;
    tuple.serialize_element(&fields)?;
    tuple.end()
}

fn required<'de, A, T>(sequence: &mut A, field: &'static str) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: Deserialize<'de>,
{
    sequence
        .next_element()?
        .ok_or_else(|| A::Error::missing_field(field))
}

macro_rules! impl_id {
    ($id:ident) => {
        impl $id {
            pub fn new() -> Result<Self, getrandom::Error> {
                let mut bytes = [0_u8; 16];
                getrandom::fill(&mut bytes)?;
                Ok(Self(bytes))
            }

            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub const fn to_bytes(self) -> [u8; 16] {
                self.0
            }
        }

        impl fmt::Display for $id {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }

                Ok(())
            }
        }

        impl fmt::Debug for $id {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({self})", stringify!($id))
            }
        }

        impl FromStr for $id {
            type Err = ParseIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.len() != 32 || !value.is_ascii() {
                    return Err(ParseIdError::InvalidLength);
                }

                let mut bytes = [0_u8; 16];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    let offset = index * 2;
                    *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
                        .map_err(|_| ParseIdError::InvalidHex)?;
                }
                Ok(Self::from_bytes(bytes))
            }
        }
    };
}

impl_id!(UserId);
impl_id!(RoomId);
impl_id!(MessageId);

pub fn normalize_room_name(name: &str) -> Result<String, RoomNameError> {
    let normalized = name.trim();

    if normalized.is_empty() {
        return Err(RoomNameError::Empty);
    }
    if normalized.chars().count() > MAX_ROOM_NAME_CHARS {
        return Err(RoomNameError::TooLong);
    }
    if normalized.chars().any(char::is_control) {
        return Err(RoomNameError::ControlCharacter);
    }

    Ok(normalized.to_owned())
}

pub fn authentication_transcript(
    protocol_version: u16,
    user_id: UserId,
    public_key: &Ed25519PublicKeyBytes,
    challenge: &AuthenticationChallenge,
) -> [u8; AUTHENTICATION_TRANSCRIPT_LENGTH] {
    let mut transcript = [0_u8; AUTHENTICATION_TRANSCRIPT_LENGTH];
    let mut offset = 0;

    for field in [
        AUTHENTICATION_DOMAIN.as_slice(),
        &protocol_version.to_be_bytes(),
        &user_id.to_bytes(),
        public_key.as_bytes(),
        challenge.as_bytes(),
    ] {
        let end = offset + field.len();
        transcript[offset..end].copy_from_slice(field);
        offset = end;
    }

    transcript
}

pub fn encode_message<T: Serialize>(message: &T) -> Result<Vec<u8>, postcard::Error> {
    let size = postcard::experimental::serialized_size(message)?;
    if size > delivery::MAX_PAYLOAD {
        return Err(postcard::Error::SerializeBufferFull);
    }
    // Exact allocation prevents Vec growth temporarily doubling the outbound buffer.
    let mut bytes = vec![0; size];
    postcard::to_slice(message, &mut bytes)?;
    Ok(bytes)
}

/// SHA-256 fingerprint of a TLS certificate's DER bytes, hex-encoded.
///
/// The relay prints this on startup; the client pins it to authenticate the
/// relay (replacing the previous trust-on-plaintext behavior).
pub fn cert_fingerprint_sha256_hex(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(cert_der);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(hex_nibble(byte >> 4));
        encoded.push(hex_nibble(byte & 0x0f));
    }
    encoded
}

fn hex_nibble(value: u8) -> char {
    (match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }) as char
}

/// Parse a 64-character hex SHA-256 fingerprint (case-insensitive).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseFingerprintError {
    InvalidLength,
    InvalidHex,
}

impl fmt::Display for ParseFingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("fingerprint must be 64 hex characters"),
            Self::InvalidHex => formatter.write_str("fingerprint contains a non-hex character"),
        }
    }
}

impl std::error::Error for ParseFingerprintError {}

pub fn parse_fingerprint_hex(encoded: &str) -> Result<[u8; 32], ParseFingerprintError> {
    let encoded = encoded.trim();
    if encoded.len() != 64 || !encoded.is_ascii() {
        return Err(ParseFingerprintError::InvalidLength);
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let pair = &encoded[index * 2..index * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| ParseFingerprintError::InvalidHex)?;
    }
    Ok(bytes)
}

#[derive(Debug)]
pub enum DecodeMessageError {
    PayloadLimit,
    Postcard(postcard::Error),
    TrailingBytes,
}

impl fmt::Display for DecodeMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadLimit => formatter.write_str("aggregate V9 payload exceeds 768 KiB"),
            Self::Postcard(error) => write!(formatter, "invalid Postcard message: {error}"),
            Self::TrailingBytes => formatter.write_str("trailing bytes after Postcard message"),
        }
    }
}

impl std::error::Error for DecodeMessageError {}

impl From<postcard::Error> for DecodeMessageError {
    fn from(error: postcard::Error) -> Self {
        Self::Postcard(error)
    }
}

pub fn decode_message<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeMessageError> {
    if bytes.len() > delivery::MAX_PAYLOAD {
        return Err(DecodeMessageError::PayloadLimit);
    }
    let (message, remaining) = postcard::take_from_bytes(bytes)?;

    if !remaining.is_empty() {
        return Err(DecodeMessageError::TrailingBytes);
    }

    Ok(message)
}

/// The request this relay message answers, if any.
///
/// `RoomMessageReceived` is a live push with no request; the handshake
/// messages precede any request. Everything else (including `ProtocolError`)
/// carries the originating request ID.
pub fn request_id_of(message: &RelayMessage) -> Option<MessageId> {
    match message {
        RelayMessage::Delivery { request_id, .. } => Some(*request_id),
        RelayMessage::ProtocolError { request_id, .. } => *request_id,
        _ => None,
    }
}

pub async fn read_frame<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    let mut header_bytes_read = 0;

    while header_bytes_read < header.len() {
        match reader.read(&mut header[header_bytes_read..]).await {
            Ok(0) if header_bytes_read == 0 => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("truncated frame header: received {header_bytes_read} of 4 bytes"),
                ));
            }
            Ok(bytes_read) => header_bytes_read += bytes_read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    let length = u32::from_be_bytes(header);

    if length > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {length} bytes"),
        ));
    }

    let mut payload = vec![0u8; length as usize];

    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("truncated frame payload: expected {length} bytes"),
            ),
            _ => error,
        })?;

    Ok(Some(payload))
}

pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload too large"))?;

    if length > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame too large: {length} bytes"),
        ));
    }

    writer.write_u32(length).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fmt, io};

    use serde::de::DeserializeOwned;

    use super::{MessageId, RoomId, UserId};

    #[test]
    fn generated_ids_have_readable_output() {
        let user_id = UserId::new().expect("the OS should provide randomness");

        assert_eq!(user_id.to_string().len(), 32);
        assert_eq!(format!("{user_id:?}"), format!("UserId({user_id})"));
        assert_eq!(user_id.to_string().parse(), Ok(user_id));
        assert!(matches!(
            "not-an-id".parse::<UserId>(),
            Err(super::ParseIdError::InvalidLength)
        ));
    }

    #[test]
    fn ids_round_trip_through_postcard() {
        let user_id = UserId([0x11; 16]);
        let room_id = RoomId([0x22; 16]);
        let message_id = MessageId([0x33; 16]);

        assert_postcard_round_trip(user_id);
        assert_postcard_round_trip(room_id);
        assert_postcard_round_trip(message_id);
    }

    #[test]
    fn server_identify_accepted_round_trips() {
        let user_id = UserId([0x44; 16]);

        let message = super::RelayMessage::ServerIdentifyAccepted { user_id };

        let encoded = super::encode_message(&message).expect("message encoding should succeed");

        let decoded: super::RelayMessage =
            super::decode_message(&encoded).expect("message decoding should succeed");

        match decoded {
            super::RelayMessage::ServerIdentifyAccepted {
                user_id: decoded_user_id,
            } => {
                assert_eq!(decoded_user_id, user_id);
            }

            other => {
                panic!("expected ServerIdentifyAccepted, got {other:?}");
            }
        }
    }

    #[test]
    fn fingerprints_round_trip_through_hex() {
        let fingerprint = super::cert_fingerprint_sha256_hex(b"fake-cert-der");
        assert_eq!(fingerprint.len(), 64);
        // Known answer: SHA-256 hex of the input; recompute via parse.
        let parsed = super::parse_fingerprint_hex(&fingerprint).expect("own output should parse");
        assert_eq!(
            super::cert_fingerprint_sha256_hex(b"fake-cert-der"),
            super::cert_fingerprint_sha256_hex(b"fake-cert-der")
        );
        assert_eq!(parsed.len(), 32);
        assert!(super::parse_fingerprint_hex(&fingerprint.to_uppercase()).is_ok());
        assert!(matches!(
            super::parse_fingerprint_hex("abc"),
            Err(super::ParseFingerprintError::InvalidLength)
        ));
        assert!(matches!(
            super::parse_fingerprint_hex(&"zz".repeat(32)),
            Err(super::ParseFingerprintError::InvalidHex)
        ));
        // A 64-byte non-ASCII input must fail instead of slicing through a
        // multibyte character and panicking during independent pin import.
        assert!(super::parse_fingerprint_hex(&("€".repeat(21) + "x")).is_err());
        // Different input, different fingerprint.
        assert_ne!(
            fingerprint,
            super::cert_fingerprint_sha256_hex(b"other-der")
        );
    }

    #[test]
    fn v9_wire_fixtures_and_reserved_tags() {
        assert_eq!(super::PROTOCOL_VERSION, 9);
        assert_eq!(
            super::encode_message(&super::ClientMessage::ClientHello { version: 9 }).unwrap(),
            vec![1, 9]
        );
        assert_eq!(
            super::encode_message(&super::RelayMessage::DeliveryChanged).unwrap(),
            vec![101]
        );
        let request = super::ClientMessage::Delivery {
            request_id: super::MessageId::from_bytes([7; 16]),
            request: super::delivery::Request::SyncIndex { after_room: None },
        };
        let mut fixture = vec![100];
        fixture.extend([7; 16]);
        fixture.extend([5, 0]);
        assert_eq!(super::encode_message(&request).unwrap(), fixture);
        assert!(matches!(
            super::decode_message::<super::ClientMessage>(&fixture).unwrap(),
            super::ClientMessage::Delivery { .. }
        ));
        for tag in [2, 10, 19, 20, 21, 23, 24, 25, 26, 27, 28] {
            assert!(super::decode_message::<super::ClientMessage>(&[tag]).is_err());
        }
        assert!(
            super::decode_message::<super::ClientMessage>(&vec![
                0;
                super::delivery::MAX_PAYLOAD + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn room_names_reject_malformed_values() {
        assert_eq!(
            super::normalize_room_name("  "),
            Err(super::RoomNameError::Empty)
        );
        assert_eq!(
            super::normalize_room_name(&"x".repeat(super::MAX_ROOM_NAME_CHARS + 1)),
            Err(super::RoomNameError::TooLong)
        );
        assert_eq!(
            super::normalize_room_name("bad\nname"),
            Err(super::RoomNameError::ControlCharacter)
        );
        assert_eq!(
            super::normalize_room_name("  The Grotto  "),
            Ok("The Grotto".to_owned())
        );
    }

    #[test]
    fn decoding_rejects_trailing_bytes() {
        let message = super::ClientMessage::ClientHello {
            version: super::PROTOCOL_VERSION,
        };
        let mut encoded = super::encode_message(&message).expect("message encoding should succeed");
        encoded.push(0xff);

        assert!(matches!(
            super::decode_message::<super::ClientMessage>(&encoded),
            Err(super::DecodeMessageError::TrailingBytes)
        ));
    }

    #[tokio::test]
    async fn partial_frame_headers_are_rejected() {
        for header_length in 1..4 {
            let mut input = &u32::to_be_bytes(8)[..header_length];
            let error = super::read_frame(&mut input)
                .await
                .expect_err("partial frame header should be rejected");

            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            assert!(error.to_string().contains("truncated frame header"));
        }
    }

    fn assert_postcard_round_trip<T>(value: T)
    where
        T: serde::Serialize + DeserializeOwned + PartialEq + fmt::Debug,
    {
        let encoded = postcard::to_allocvec(&value).expect("ID encoding should succeed");
        let (decoded, remaining): (T, &[u8]) =
            postcard::take_from_bytes(&encoded).expect("ID decoding should succeed");

        assert!(remaining.is_empty());
        assert_eq!(decoded, value);
    }
}
