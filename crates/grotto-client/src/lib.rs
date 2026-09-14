use std::{
    env,
    io::{self, BufRead, Write},
    path::PathBuf,
    sync::Arc,
    thread,
};

pub mod contacts;
mod delivery;
pub mod identity;
pub mod metrics;
pub mod mls_session;
pub mod mls_storage;
mod private_file;
pub mod store;

use grotto_protocol::{
    ClientMessage, Ed25519PublicKeyBytes, Ed25519SignatureBytes, MAX_MESSAGE_BODY_BYTES,
    PROTOCOL_VERSION, RelayMessage, RoomId, UserId, authentication_transcript, decode_message,
    encode_message, normalize_room_name, read_frame, write_frame,
};

use ed25519_dalek::{Signature, Signer};
use grotto_mls::{MlsKeyMaterial, generate_key_material, new_client_with_providers};
use mls_session::MlsSession;
use store::ClientStore;

use tokio::{net::TcpStream, sync::mpsc};
use tokio_rustls::client::TlsStream;

const INPUT_CHANNEL_CAPACITY: usize = 16;
const DEFAULT_RELAY_ADDRESS: &str = "127.0.0.1:8080";

enum UserCommand {
    SetFetchGrant {
        requester: UserId,
        allowed: bool,
    },
    ContactExport,
    ContactImport {
        card: String,
        fingerprint: String,
    },
    ListContacts,
    CreateRoom(String),
    PublishKeyPackages(usize),
    AddToRoom {
        room_id: RoomId,
        user_id: UserId,
    },
    ListRooms,
    SendRoomMessage {
        room_id: RoomId,
        body: Vec<u8>,
    },
    FetchRoomHistory {
        room_id: RoomId,
        before_sequence: Option<u64>,
    },
    SyncWelcomes,
}

pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("grotto-client-service".into())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })
                .and_then(|runtime| runtime.block_on(run_inner()));
            let _ = sender.send(result);
        })?;
    receiver.await?
}

async fn run_inner() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments.first().is_some_and(|arg| arg == "--help") {
        println!(
            "{}\nOffline: --contact-export | --contact-import <card> <independent-fingerprint>\nFirst connection requires GROTTO_ENROLLMENT_TOKEN from the relay operator.",
            command_usage()
        );
        return Ok(());
    }
    let store_path = env::var_os("GROTTO_CLIENT_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or(identity::default_store_path()?);
    if let Some(parent) = store_path.parent() {
        for legacy in ["identity.key", "identity.toml", "mls.db"] {
            if parent.join(legacy).symlink_metadata().is_ok() {
                return Err("legacy client state found; choose a fresh directory (no migrations are performed)".into());
            }
        }
    }
    let store = Arc::new(ClientStore::open(&store_path)?);
    let identity = store.identity()?;
    println!("Local message store: {}", store_path.display());
    let user_id = identity.user_id();

    // Long-lived MLS signing identity, bound to the Grotto user ID.
    let mls_keys = match store.load_mls_identity()? {
        Some((public, secret)) => MlsKeyMaterial { public, secret },
        None => {
            let keys = generate_key_material()?;
            store.save_mls_identity(&keys.public, &keys.secret)?;
            println!("Generated new MLS identity.");
            keys
        }
    };
    if env::var_os("GROTTO_MLS_DB_PATH").is_some() {
        return Err(
            "separate MLS databases are unsupported; use a fresh unified client database".into(),
        );
    }
    let own_card = contacts::ContactCard::own(&store)?;
    own_card.import(&store, &own_card.fingerprint())?;
    match arguments.first().map(String::as_str) {
        Some("--contact-export") if arguments.len() == 1 => {
            println!(
                "Contact card: {}\nFingerprint: {}\nUser ID: {}\nTransport key fingerprint: {}",
                own_card.encode(),
                own_card.fingerprint(),
                own_card.user,
                grotto_protocol::cert_fingerprint_sha256_hex(&own_card.transport_key)
            );
            return Ok(());
        }
        Some("--contact-import") if arguments.len() == 3 => {
            contacts::ContactCard::parse(&arguments[1])?.import(&store, &arguments[2])?;
            println!("Contact verified");
            return Ok(());
        }
        Some(_) => return Err("invalid arguments; use --help".into()),
        None => {}
    }
    let mut input = spawn_terminal_input();
    let mut delay = 1u64;
    loop {
        let started = std::time::Instant::now();
        let connected =
            tokio::time::timeout(std::time::Duration::from_secs(10), connect(&identity)).await;
        let result = match connected {
            Ok(Ok(socket)) => {
                let provider = mls_storage::MlsStorage(store.clone());
                let client = new_client_with_providers(
                    &user_id.to_bytes(),
                    mls_keys.clone(),
                    provider.clone(),
                    provider,
                    contacts::VerifiedIdentityProvider(store.clone()),
                );
                delivery::run(
                    socket,
                    store.clone(),
                    MlsSession::new(client),
                    user_id,
                    &mut input,
                )
                .await
            }
            Ok(Err(error)) => Err(error),
            Err(error) => Err(Box::new(error) as Box<dyn std::error::Error + Send + Sync>),
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) if retryable(error.as_ref()) => {
                if input.is_closed() && input.is_empty() {
                    return Ok(());
                }
                if started.elapsed() > std::time::Duration::from_secs(30) {
                    delay = 1;
                }
                let mut jitter = [0];
                getrandom::fill(&mut jitter)?;
                let millis = (delay * 1000 + u64::from(jitter[0]) * delay * 2).min(30_000);
                eprintln!("Connection lost; retrying in {millis} ms");
                tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
                delay = (delay * 2).min(30);
            }
            Err(error) => return Err(error),
        }
    }
}

fn disconnected() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "relay disconnected")
}
fn retryable(error: &(dyn std::error::Error + 'static)) -> bool {
    error.is::<tokio::time::error::Elapsed>()
        || error.downcast_ref::<io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::NotConnected
            )
        })
}

async fn connect(
    identity: &identity::ClientIdentity,
) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let user_id = identity.user_id();
    let relay_address =
        env::var("GROTTO_RELAY_ADDRESS").unwrap_or_else(|_| DEFAULT_RELAY_ADDRESS.to_owned());
    let tcp = TcpStream::connect(&relay_address).await?;

    println!("Connected to Grotto relay at {relay_address}");

    let tls = tls::connect(&relay_address, tcp).await?;
    println!("Relay TLS fingerprint (sha256): {}", tls.fingerprint);
    if tls.newly_pinned {
        println!("Pinned new relay identity (trust-on-first-use).");
        println!("Verify the fingerprint out of band on first connect.");
    }
    let mut socket: TlsStream<TcpStream> = tls.stream;

    let hello = ClientMessage::ClientHello {
        version: PROTOCOL_VERSION,
    };

    let encoded = encode_message(&hello)?;

    write_frame(&mut socket, &encoded).await?;

    let Some(response) = read_frame(&mut socket).await? else {
        return Err(disconnected().into());
    };

    let response: RelayMessage = decode_message(&response)?;

    match response {
        RelayMessage::ServerHello { version } => {
            if version != PROTOCOL_VERSION {
                return Err(format!(
                    "unsupported protocol version: relay={version}, client={PROTOCOL_VERSION}"
                )
                .into());
            }

            println!("Handshake complete. Protocol version: {version}");
        }

        RelayMessage::ProtocolError { error, .. } => return Err(error.into()),

        other => {
            return Err(format!("unexpected handshake message: {other:?}").into());
        }
    }

    let signing_key = identity.signing_key();
    let verifying_key = signing_key.verifying_key();

    let public_key = Ed25519PublicKeyBytes::new(verifying_key.to_bytes());

    println!("Public identity key: {:02x?}", verifying_key.to_bytes());

    let enrollment = env::var("GROTTO_ENROLLMENT_TOKEN")
        .ok()
        .map(|text| grotto_protocol::parse_fingerprint_hex(&text))
        .transpose()?;
    let client_identify = ClientMessage::ClientIdentify {
        user_id,
        public_key,
        enrollment,
    };

    let encoded = encode_message(&client_identify)?;

    write_frame(&mut socket, &encoded).await?;

    let Some(response) = read_frame(&mut socket).await? else {
        return Err(disconnected().into());
    };

    let response: RelayMessage = decode_message(&response)?;

    let challenge = match response {
        RelayMessage::ServerAuthenticationChallenge { challenge } => challenge,

        RelayMessage::ProtocolError { error, .. } => return Err(error.into()),

        other => {
            return Err(
                format!("expected ServerAuthenticationChallenge, received: {other:?}").into(),
            );
        }
    };

    let transcript = authentication_transcript(PROTOCOL_VERSION, user_id, &public_key, &challenge);
    let signature: Signature = signing_key.sign(&transcript);

    let response = ClientMessage::ClientAuthenticationResponse {
        signature: Ed25519SignatureBytes::new(signature.to_bytes()),
    };

    let encoded = encode_message(&response)?;

    write_frame(&mut socket, &encoded).await?;

    // Authentication response sent; now wait for acceptance.
    let Some(response) = read_frame(&mut socket).await? else {
        return Err(disconnected().into());
    };

    let response: RelayMessage = decode_message(&response)?;

    match response {
        RelayMessage::ServerIdentifyAccepted {
            user_id: accepted_user_id,
        } => {
            if accepted_user_id != user_id {
                return Err(format!(
                    "relay acknowledged wrong user ID: expected {user_id}, got {accepted_user_id}"
                )
                .into());
            }

            println!("Identity accepted. User ID: {accepted_user_id}");
        }

        RelayMessage::ProtocolError { error, .. } => return Err(error.into()),

        other => {
            return Err(format!("unexpected identity response: {other:?}").into());
        }
    }

    Ok(socket)
}

mod tls {
    use std::{env, net::IpAddr, path::Path, path::PathBuf, str::FromStr, sync::Arc};

    use grotto_protocol::{cert_fingerprint_sha256_hex, parse_fingerprint_hex};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
    use tokio::net::TcpStream;
    use tokio_rustls::{TlsConnector, client::TlsStream};

    use crate::identity::default_identity_directory;

    const PIN_FILE_NAME: &str = "relay_pins";

    pub struct TlsConnection {
        pub stream: TlsStream<TcpStream>,
        pub fingerprint: String,
        pub newly_pinned: bool,
    }

    /// TLS-connect to the relay and authenticate it by certificate fingerprint.
    ///
    /// Pin source, in order: `GROTTO_RELAY_FINGERPRINT` env, then a per-address
    /// trust-on-first-use file next to the client identity. Fails closed on
    /// mismatch before any application bytes are sent.
    pub async fn connect(
        relay_address: &str,
        tcp: TcpStream,
    ) -> Result<TlsConnection, Box<dyn std::error::Error + Send + Sync>> {
        let verifier = Arc::new(FingerprintVerifier::default());
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = server_name_for(relay_address)?;
        let stream = connector.connect(server_name, tcp).await?;

        let presented = verifier.take().ok_or("TLS peer presented no certificate")?;
        let fingerprint = cert_fingerprint_sha256_hex(&presented);

        let mut newly_pinned = false;
        if let Ok(pinned) = env::var("GROTTO_RELAY_FINGERPRINT") {
            let pinned = pinned.trim().to_lowercase();
            parse_fingerprint_hex(&pinned)
                .map_err(|error| format!("invalid GROTTO_RELAY_FINGERPRINT: {error}"))?;
            if pinned != fingerprint {
                return Err(format!(
                    "relay fingerprint mismatch: expected {pinned}, presented {fingerprint}"
                )
                .into());
            }
        } else {
            newly_pinned = ensure_pinned(&pin_file()?, relay_address, &fingerprint)?;
        }

        Ok(TlsConnection {
            stream,
            fingerprint,
            newly_pinned,
        })
    }

    fn server_name_for(address: &str) -> Result<ServerName<'static>, String> {
        let host = address
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(address);
        let host = host.trim_matches(|c| c == '[' || c == ']');
        if let Ok(ip) = IpAddr::from_str(host) {
            return Ok(ServerName::IpAddress(ip.into()));
        }
        ServerName::try_from(host.to_owned()).map_err(|_| format!("invalid relay hostname: {host}"))
    }

    fn pin_file() -> Result<PathBuf, crate::identity::IdentityError> {
        if let Ok(path) = env::var("GROTTO_RELAY_PIN_PATH") {
            return Ok(PathBuf::from(path));
        }
        default_identity_directory().map(|dir| dir.join(PIN_FILE_NAME))
    }

    /// Check `addr fingerprint` lines; append on first sight (TOFU).
    /// Returns true when a new pin was recorded.
    fn ensure_pinned(
        path: &Path,
        addr: &str,
        fingerprint: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        use std::io::{Read, Seek, Write};
        let mut file = crate::private_file::open_locked(path)?;
        if file.metadata()?.len() > 64 * 1024 {
            return Err("relay pin file exceeds its size budget".into());
        }
        let mut existing = String::new();
        file.read_to_string(&mut existing)?;
        if !existing.is_empty() && !existing.ends_with('\n') {
            return Err("incomplete relay pin record".into());
        }
        for line in existing.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 2 || parse_fingerprint_hex(fields[1]).is_err() {
                return Err("malformed relay pin record".into());
            }
        }
        for line in existing.lines() {
            let mut parts = line.split_whitespace();
            if parts.next() == Some(addr) {
                match parts.next() {
                    Some(pinned) if pinned == fingerprint => return Ok(false),
                    _ => {
                        return Err(format!(
                            "relay fingerprint mismatch for {addr}: pinned entry differs. \
                             Verify out of band, then delete {} or set GROTTO_RELAY_FINGERPRINT.",
                            path.display()
                        )
                        .into());
                    }
                }
            }
        }
        let line = format!("{addr} {fingerprint}\n");
        if existing.len() + line.len() > 64 * 1024 {
            return Err("relay pin file exceeds its size budget".into());
        }
        file.seek(std::io::SeekFrom::End(0))?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
        Ok(true)
    }

    /// Pinning-only verifier: captures the end-entity cert for a fingerprint
    /// check after the handshake. CertificateVerify signatures are not
    /// re-checked against PKI; authentication comes from the pin comparison
    /// in [`connect`], which aborts before any application data flows.
    /// Encryption still comes from the TLS key exchange.
    #[derive(Debug, Default)]
    struct FingerprintVerifier {
        captured: std::sync::Mutex<Option<Vec<u8>>>,
    }

    impl FingerprintVerifier {
        fn take(&self) -> Option<Vec<u8>> {
            self.captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        }
    }

    impl ServerCertVerifier for FingerprintVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            *self
                .captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(end_entity.as_ref().to_vec());
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
            ]
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{ensure_pinned, server_name_for};

        #[test]
        fn server_names_cover_ip_and_dns() {
            assert!(matches!(
                server_name_for("127.0.0.1:8080"),
                Ok(rustls::pki_types::ServerName::IpAddress(_))
            ));
            assert!(matches!(
                server_name_for("localhost:8080"),
                Ok(rustls::pki_types::ServerName::DnsName(_))
            ));
            assert!(server_name_for("not a host!!!:1").is_err());
        }

        #[test]
        fn pins_are_per_address_and_fail_closed() {
            let dir = tempfile::tempdir().expect("temporary directory should be created");
            let path = dir.path().join("private/relay_pins");
            let fp_a = "aa".repeat(32);
            let fp_b = "bb".repeat(32);

            assert!(ensure_pinned(&path, "127.0.0.1:8080", &fp_a).expect("first pin"));
            assert!(!ensure_pinned(&path, "127.0.0.1:8080", &fp_a).expect("same pin"));
            assert!(ensure_pinned(&path, "example.com:8080", &fp_b).expect("other addr"));
            assert!(ensure_pinned(&path, "127.0.0.1:8080", &fp_b).is_err());
        }

        #[test]
        fn verifier_captures_presented_cert() {
            use rustls::client::danger::ServerCertVerifier;
            use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

            let verifier = super::FingerprintVerifier::default();
            let der = vec![1_u8, 2, 3, 4];
            let cert = CertificateDer::from(der.clone());
            let name = ServerName::try_from("localhost").expect("dns name");
            verifier
                .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .expect("capture should succeed");
            assert_eq!(verifier.take(), Some(der));
            assert_eq!(verifier.take(), None);
        }
    }
}

fn terminal_safe(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

fn parse_command(input: &str) -> Result<Option<UserCommand>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }

    if input == "/contact export" {
        return Ok(Some(UserCommand::ContactExport));
    }
    if input == "/contacts" {
        return Ok(Some(UserCommand::ListContacts));
    }
    if let Some(arguments) = input.strip_prefix("/contact import ") {
        let fields: Vec<_> = arguments.split_whitespace().collect();
        if fields.len() != 2 {
            return Err(
                "Usage: /contact import <card> <independently-verified-fingerprint>".into(),
            );
        }
        return Ok(Some(UserCommand::ContactImport {
            card: fields[0].into(),
            fingerprint: fields[1].into(),
        }));
    }
    if let Some(name) = input.strip_prefix("/create") {
        if !name.is_empty() && !name.starts_with(char::is_whitespace) {
            return Err(command_usage().to_owned());
        }
        return normalize_room_name(name)
            .map(UserCommand::CreateRoom)
            .map(Some)
            .map_err(|error| format!("Cannot create room: {error}"));
    }
    if let Some(arguments) = input.strip_prefix("/send") {
        if !arguments.is_empty() && !arguments.starts_with(char::is_whitespace) {
            return Err(command_usage().to_owned());
        }
        let arguments = arguments.trim_start();
        let Some(separator) = arguments.find(char::is_whitespace) else {
            return Err(command_usage().to_owned());
        };
        let room_id = arguments[..separator]
            .parse()
            .map_err(|error| format!("Invalid room ID: {error}"))?;
        let body = arguments[separator..].trim_start().as_bytes().to_vec();
        if body.is_empty() {
            return Err("Cannot send an empty message".to_owned());
        }
        if body.len() > MAX_MESSAGE_BODY_BYTES {
            return Err(format!(
                "Message cannot exceed {MAX_MESSAGE_BODY_BYTES} bytes"
            ));
        }
        return Ok(Some(UserCommand::SendRoomMessage { room_id, body }));
    }
    if let Some(arguments) = input.strip_prefix("/publish") {
        if !arguments.is_empty() && !arguments.starts_with(char::is_whitespace) {
            return Err(command_usage().to_owned());
        }
        let arguments = arguments.trim();
        let count = if arguments.is_empty() {
            5
        } else {
            arguments
                .parse::<usize>()
                .map_err(|_| command_usage().to_owned())?
        };
        if count == 0 || count > 64 {
            return Err("Publish count must be 1 to 64".to_owned());
        }
        return Ok(Some(UserCommand::PublishKeyPackages(count)));
    }
    if input == "/rooms" {
        return Ok(Some(UserCommand::ListRooms));
    }
    if input == "/welcomes" {
        return Ok(Some(UserCommand::SyncWelcomes));
    }

    if let Some((allowed, arguments)) = input
        .strip_prefix("/contact grant ")
        .map(|s| (true, s))
        .or_else(|| input.strip_prefix("/contact revoke ").map(|s| (false, s)))
    {
        return Ok(Some(UserCommand::SetFetchGrant {
            requester: arguments
                .trim()
                .parse()
                .map_err(|_| "invalid contact user ID")?,
            allowed,
        }));
    }
    let mut parts = input.split_whitespace();
    match parts.next() {
        Some("/add") => {
            let room_id = parse_room_id(&mut parts)?;
            let user_id = parts
                .next()
                .ok_or_else(command_usage)?
                .parse()
                .map_err(|error| format!("Invalid user ID: {error}"))?;
            if parts.next().is_some() {
                return Err(command_usage().to_owned());
            }
            Ok(Some(UserCommand::AddToRoom { room_id, user_id }))
        }
        Some("/history") => {
            let room_id = parse_room_id(&mut parts)?;
            let before_sequence = parts
                .next()
                .map(str::parse)
                .transpose()
                .map_err(|error| format!("Invalid message sequence: {error}"))?;
            if parts.next().is_some() {
                return Err(command_usage().to_owned());
            }
            Ok(Some(UserCommand::FetchRoomHistory {
                room_id,
                before_sequence,
            }))
        }
        _ => Err(command_usage().to_owned()),
    }
}

fn parse_room_id<'a>(parts: &mut impl Iterator<Item = &'a str>) -> Result<RoomId, String> {
    parts
        .next()
        .ok_or_else(command_usage)?
        .parse()
        .map_err(|error| format!("Invalid room ID: {error}"))
}

fn command_usage() -> &'static str {
    "Commands: /contact export, /contact import <card> <independent-fingerprint>, /contacts, /contact grant <user-id>, /contact revoke <user-id>, /create <name>, /rooms, /publish [count], /add <room-id> <user-id>, /welcomes, /send <room-id> <message>, /history <room-id> [before-sequence]"
}

fn spawn_terminal_input() -> mpsc::Receiver<io::Result<String>> {
    let (sender, receiver) = mpsc::channel(INPUT_CHANNEL_CAPACITY);

    thread::spawn(move || {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        loop {
            print!("> ");
            if let Err(error) = io::stdout().flush() {
                let _ = sender.blocking_send(Err(error));
                break;
            }

            let Some(line) = lines.next() else {
                break;
            };

            if sender.blocking_send(line).is_err() {
                break;
            }
        }
    });

    receiver
}

#[cfg(test)]
mod session_tests {
    #[test]
    fn terminal_output_escapes_controls() {
        assert_eq!(super::terminal_safe("hello\u{1b}[31m"), "hello�[31m");
    }
}
