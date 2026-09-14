use std::{
    collections::{HashMap, HashSet},
    env, io,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

pub mod delivery;
mod enrollment;
pub mod limits;
pub mod metrics;
mod private_file;
mod shutdown;
pub mod storage;
pub mod worker;

use ed25519_dalek::{Signature, VerifyingKey};

use grotto_protocol::{
    AuthenticationChallenge, ClientMessage, ClientMessageKind, Ed25519PublicKeyBytes,
    PROTOCOL_VERSION, ProtocolError, RelayMessage, UserId, authentication_transcript,
    decode_message, encode_message, read_frame,
};

use storage::{Registration, RelayState, StorageError};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio::{net::TcpListener, sync::mpsc};
use worker::DatabaseWorker;

#[cfg(test)]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RELAY_ADDRESS: &str = "127.0.0.1:8080";
const OUTBOUND_CHANNEL_CAPACITY: usize = 64;
/// Inbound frames waiting for dispatch. Bounded so a stalled dispatch loop
/// applies TCP backpressure instead of buffering without limit.
const INBOUND_CHANNEL_CAPACITY: usize = 32;
#[cfg(test)]
const FRAME_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(test)]
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle connections need not send heartbeats. Once a frame starts, however,
/// its header and body must both finish within one deadline.
#[cfg(test)]
async fn read_session_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    deadline: Duration,
) -> io::Result<Option<Vec<u8>>> {
    use tokio::io::AsyncReadExt;
    let mut first = [0];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let mut frame_reader = first.as_slice().chain(reader);
    timeout(deadline, read_frame(&mut frame_reader))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frame completion timed out"))?
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    timeout(
        Duration::from_secs(limits::runtime().write_seconds),
        grotto_protocol::write_frame(writer, bytes),
    )
    .await
    .map_err(|_| {
        metrics::increment(&metrics::TIMEOUTS);
        io::Error::new(io::ErrorKind::TimedOut, "socket write timed out")
    })?
}

enum InboundEvent {
    Message(ClientMessage, PayloadLease),
    Disconnected,
    Error(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Debug for InboundEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message, _) => formatter.debug_tuple("Message").field(message).finish(),
            Self::Disconnected => formatter.write_str("Disconnected"),
            Self::Error(error) => formatter
                .debug_tuple("Error")
                .field(&error.to_string())
                .finish(),
        }
    }
}

/// Owns frame-decoding state for the connection's lifetime. Never cancelled,
/// so partially-read frames are always completed, never reinterpreted.
struct PayloadLease {
    _global: tokio::sync::OwnedSemaphorePermit,
    _connection: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(test)]
async fn read_inbound_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    sender: mpsc::Sender<InboundEvent>,
) {
    read_inbound_with_budget(
        reader,
        sender,
        Arc::new(tokio::sync::Semaphore::new(64 * 1024 * 1024)),
    )
    .await;
}

async fn read_inbound_with_budget<R: AsyncRead + Unpin>(
    reader: &mut R,
    sender: mpsc::Sender<InboundEvent>,
    budget: Arc<tokio::sync::Semaphore>,
) {
    use tokio::io::AsyncReadExt;
    let connection = Arc::new(tokio::sync::Semaphore::new(1));
    loop {
        // One payload operation per connection. Reserve its peak decode/encode
        // working set before any frame allocation; keep it through DB and write.
        let mut first = [0];
        let event = match reader.read(&mut first).await {
            Ok(0) => InboundEvent::Disconnected,
            Err(error) => InboundEvent::Error(error.into()),
            Ok(_) => {
                let result = timeout(
                    Duration::from_secs(limits::runtime().frame_seconds),
                    async {
                        let lease = PayloadLease {
                            _global: budget.clone().acquire_many_owned(2 * 1024 * 1024).await?,
                            _connection: connection.clone().acquire_owned().await?,
                        };
                        let mut stream = first.as_slice().chain(&mut *reader);
                        let frame = read_frame(&mut stream).await?.ok_or_else(|| {
                            io::Error::new(io::ErrorKind::UnexpectedEof, "missing frame")
                        })?;
                        let message = decode_message(&frame)?;
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((message, lease))
                    },
                )
                .await;
                match result {
                    Ok(Ok((message, lease))) => InboundEvent::Message(message, lease),
                    Ok(Err(error)) => InboundEvent::Error(error),
                    Err(error) => {
                        metrics::increment(&metrics::TIMEOUTS);
                        InboundEvent::Error(error.into())
                    }
                }
            }
        };
        let terminal = !matches!(event, InboundEvent::Message(..));
        if sender.send(event).await.is_err() || terminal {
            break;
        }
    }
}

struct ConnectionHub {
    payload_budget: Arc<tokio::sync::Semaphore>,
    rates: Mutex<HashMap<UserId, (std::time::Instant, f64)>>,
    active_identities: Mutex<HashSet<UserId>>,
    next_connection_id: AtomicU64,
    connections: Mutex<HashMap<UserId, HashMap<u64, mpsc::Sender<RelayMessage>>>>,
}

impl Default for ConnectionHub {
    fn default() -> Self {
        Self {
            payload_budget: Arc::new(tokio::sync::Semaphore::new(limits::runtime().payload_bytes)),
            rates: Mutex::new(HashMap::new()),
            active_identities: Mutex::new(HashSet::new()),
            next_connection_id: AtomicU64::new(0),
            connections: Mutex::new(HashMap::new()),
        }
    }
}

impl ConnectionHub {
    fn admit_request(&self, user: UserId) -> bool {
        let now = std::time::Instant::now();
        let config = limits::runtime();
        let mut rates = self
            .rates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        rates.retain(|_, (last, _)| now.duration_since(*last).as_secs() < 60);
        let (last, tokens) = rates
            .entry(user)
            .or_insert((now, config.request_burst as f64));
        *tokens = (*tokens
            + now.duration_since(*last).as_secs_f64() * config.requests_per_second as f64)
            .min(config.request_burst as f64);
        *last = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }

    fn register(
        self: &Arc<Self>,
        user_id: UserId,
    ) -> io::Result<(ConnectionRegistration, mpsc::Receiver<RelayMessage>)> {
        if !self
            .active_identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(user_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "identity already has an active session",
            ));
        }
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(OUTBOUND_CHANNEL_CAPACITY);
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        connections
            .entry(user_id)
            .or_default()
            .insert(connection_id, sender);
        Ok((
            ConnectionRegistration {
                hub: Arc::clone(self),
                user_id,
                connection_id,
            },
            receiver,
        ))
    }

    /// Fan out a live message. Sends happen outside the hub lock; a
    /// connection whose queue is full or closed is evicted so it reconnects
    /// and heals via sync (findings #5/#6). Eviction is safe: connection IDs
    /// are never reused, and anything unacknowledged is redelivered on sync.
    fn notify(&self, recipients: &[UserId], message: RelayMessage) {
        let targets: Vec<(UserId, u64, mpsc::Sender<RelayMessage>)> = {
            let connections = self
                .connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut targets = Vec::new();
            for recipient in recipients {
                if let Some(user_connections) = connections.get(recipient) {
                    targets.extend(
                        user_connections
                            .iter()
                            .map(|(id, sender)| (*recipient, *id, sender.clone())),
                    );
                }
            }
            targets
        };
        let mut failed = Vec::new();
        for (user_id, connection_id, sender) in targets {
            if matches!(message, RelayMessage::DeliveryChanged)
                && sender.capacity() < sender.max_capacity()
            {
                continue;
            }
            if sender.is_closed() || sender.capacity() == 0 {
                failed.push((user_id, connection_id));
                continue;
            }
            if sender.try_send(message.clone()).is_err() {
                failed.push((user_id, connection_id));
            }
        }
        if !failed.is_empty() {
            let mut connections = self
                .connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (user_id, connection_id) in failed {
                if let Some(user_connections) = connections.get_mut(&user_id) {
                    user_connections.remove(&connection_id);
                    if user_connections.is_empty() {
                        connections.remove(&user_id);
                    }
                }
            }
        }
    }

    fn unregister(&self, user_id: UserId, connection_id: u64) {
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(user_connections) = connections.get_mut(&user_id) {
            user_connections.remove(&connection_id);
            if user_connections.is_empty() {
                connections.remove(&user_id);
            }
        }
    }
}

struct ConnectionRegistration {
    hub: Arc<ConnectionHub>,
    user_id: UserId,
    connection_id: u64,
}

impl Drop for ConnectionRegistration {
    fn drop(&mut self) {
        self.hub.unregister(self.user_id, self.connection_id);
        self.hub
            .active_identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.user_id);
    }
}

/// Counts only unfinished handshakes; all exits release both IP and global capacity.
struct HandshakeLease {
    pending: Arc<Mutex<HashMap<std::net::IpAddr, usize>>>,
    ip: std::net::IpAddr,
    payload: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl HandshakeLease {
    fn acquire(
        pending: Arc<Mutex<HashMap<std::net::IpAddr, usize>>>,
        ip: std::net::IpAddr,
    ) -> Option<Self> {
        let mut counts = pending.lock().ok()?;
        if counts.values().sum::<usize>() >= limits::runtime().handshakes
            || counts.get(&ip).copied().unwrap_or(0) >= limits::runtime().handshakes_per_ip
        {
            return None;
        }
        *counts.entry(ip).or_default() += 1;
        drop(counts);
        Some(Self {
            pending,
            ip,
            payload: None,
        })
    }
}

impl Drop for HandshakeLease {
    fn drop(&mut self) {
        let mut counts = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

fn default_directory() -> io::Result<PathBuf> {
    if let Some(path) = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        return Ok(path.join("grotto-relay"));
    }
    env::var_os("HOME")
        .map(|path| PathBuf::from(path).join(".local/share/grotto-relay"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "HOME or absolute XDG_DATA_HOME is required",
            )
        })
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments.as_slice() == ["--help"] {
        println!(
            "Grotto relay protocol 9\nUsage: grotto-relay [--enroll USER_ID TRANSPORT_KEY_SHA256]\nEnrollment tokens expire after 24 hours. Issue tokens while the relay is stopped.\nState: GROTTO_DATABASE_PATH, GROTTO_TLS_CERT_PATH, GROTTO_TLS_KEY_PATH.\nSee SMOKE_TEST.md and STORAGE.md for enrollment, storage, and resource limits."
        );
        return Ok(());
    }
    limits::configure()?;
    let relay_address =
        env::var("GROTTO_RELAY_ADDRESS").unwrap_or_else(|_| DEFAULT_RELAY_ADDRESS.to_owned());

    let database_path = env::var_os("GROTTO_DATABASE_PATH")
        .map(PathBuf::from)
        .unwrap_or(default_directory()?.join("relay.db"));
    let local_state = RelayState::open(&database_path)?;
    if arguments.len() == 3 && arguments[0] == "--enroll" {
        let user = arguments[1].parse()?;
        let fingerprint = grotto_protocol::parse_fingerprint_hex(&arguments[2])?;
        println!(
            "Enrollment token: {}",
            local_state.issue_enrollment(user, fingerprint)?
        );
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err("usage: grotto-relay [--enroll USER_ID TRANSPORT_KEY_SHA256]".into());
    }
    let state = Arc::new(DatabaseWorker::start(
        local_state,
        limits::runtime().database_queue,
    )?);
    let listener = TcpListener::bind(&relay_address).await?;
    let hub = Arc::new(ConnectionHub::default());
    let tls = Arc::new(tls::load_or_generate_identity()?);
    let connections = Arc::new(tokio::sync::Semaphore::new(limits::runtime().connections));
    let handshakes = Arc::new(Mutex::new(HashMap::new()));

    println!(
        "Grotto relay listening on {relay_address} using {}",
        database_path.display()
    );
    println!("Relay TLS fingerprint (sha256): {}", tls.fingerprint);
    println!("Clients must pin it via GROTTO_RELAY_FINGERPRINT.");

    let signals = shutdown::Signals::install()?;
    let (shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(false);
    let mut shutdown_tick = tokio::time::interval(Duration::from_millis(100));
    let mut sessions = tokio::task::JoinSet::new();
    let mut metrics_tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        let accepted = tokio::select! {
            accepted=listener.accept()=>accepted,
            _=metrics_tick.tick()=>{metrics::report();continue;},
            _=shutdown_tick.tick()=>{if signals.requested(){break;}continue;},
            _=sessions.join_next(),if !sessions.is_empty()=>{continue;},
        };
        let (socket, addr) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("Accept error (relay keeps running): {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let Ok(connection) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let Some(mut handshake) = HandshakeLease::acquire(handshakes.clone(), addr.ip()) else {
            continue;
        };
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(limits::runtime().handshake_seconds);
        println!("Client connected: {addr}");

        let state = Arc::clone(&state);
        let hub = Arc::clone(&hub);
        let tls = Arc::clone(&tls);

        let mut shutdown = shutdown_receiver.clone();
        sessions.spawn(async move {
            let _connection = connection;
            handshake.payload = match tokio::select! { result=tokio::time::timeout_at(
                deadline,
                hub.payload_budget
                    .clone()
                    .acquire_many_owned(2 * 1024 * 1024),
            )
            =>result, _=shutdown.changed()=>return }
            {
                Ok(Ok(permit)) => Some(permit),
                _ => {
                    metrics::increment(&metrics::TIMEOUTS);
                    return;
                }
            };
            let handshake_result=tokio::select! {result=tokio::time::timeout_at(deadline,tls.acceptor.accept(socket))=>result,_=shutdown.changed()=>return};
            let socket = match handshake_result {
                Ok(Ok(socket)) => socket,
                Ok(Err(error)) => {
                    eprintln!("TLS handshake failed for {addr}: {error}");
                    return;
                }
                Err(_) => {
                    eprintln!("TLS handshake timed out for {addr}");
                    return;
                }
            };
            if let Err(err) = handle_connection(socket, state, hub, deadline, Some(handshake),Some(shutdown)).await
            {
                eprintln!("Connection error from {addr}: {err}");
            }
        });
    }
    let _ = shutdown_sender.send(true);
    while sessions.join_next().await.is_some() {}
    metrics::report();
    Ok(())
}

mod tls {
    use std::{
        env, fs, io,
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
        path::PathBuf,
        sync::Arc,
    };

    use grotto_protocol::cert_fingerprint_sha256_hex;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::TlsAcceptor;

    const DEFAULT_CERT_PATH: &str = "grotto-tls-cert.pem";
    const DEFAULT_KEY_PATH: &str = "grotto-tls-key.pem";

    pub struct TlsIdentity {
        pub acceptor: TlsAcceptor,
        pub fingerprint: String,
    }

    pub fn load_or_generate_identity() -> Result<TlsIdentity, Box<dyn std::error::Error>> {
        let cert_path = env::var_os("GROTTO_TLS_CERT_PATH")
            .map(PathBuf::from)
            .unwrap_or(super::default_directory()?.join(DEFAULT_CERT_PATH));
        let key_path = env::var_os("GROTTO_TLS_KEY_PATH")
            .map(PathBuf::from)
            .unwrap_or(super::default_directory()?.join(DEFAULT_KEY_PATH));
        load_or_generate_at(&cert_path, &key_path)
    }

    fn load_or_generate_at(
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<TlsIdentity, Box<dyn std::error::Error>> {
        crate::private_file::ensure_parent(cert_path)?;
        crate::private_file::ensure_parent(key_path)?;
        let cert_exists = cert_path.try_exists()?;
        let key_exists = key_path.try_exists()?;
        if cert_exists != key_exists {
            return Err(
                "incomplete TLS identity: refusing to replace an existing certificate or key"
                    .into(),
            );
        }
        if !cert_exists {
            let (cert_pem, key_pem, _) = generate_self_signed()?;
            write_with_mode(cert_path, cert_pem.as_bytes(), 0o600)?;
            write_with_mode(key_path, key_pem.as_bytes(), 0o600)?;
            eprintln!(
                "Generated new relay TLS identity: {} {}",
                cert_path.display(),
                key_path.display()
            );
        }
        let cert_pem = read_private(cert_path).map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("reading {}: {source}", cert_path.display()),
            )
        })?;
        let key_pem = read_private(key_path).map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("reading {}: {source}", key_path.display()),
            )
        })?;
        load_from_pem(&cert_pem, &key_pem)
    }

    fn write_with_mode(
        path: &Path,
        contents: &[u8],
        mode: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(())
    }

    fn read_private(path: &Path) -> io::Result<Vec<u8>> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        // SAFETY: geteuid takes no arguments and cannot affect Rust memory.
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TLS identity must be a regular owner-only file",
            ));
        }
        if metadata.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS identity file too large",
            ));
        }
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS identity file too large",
            ));
        }
        Ok(bytes)
    }

    /// Generate a self-signed cert covering loopback names.
    /// Returns (cert PEM, key PEM, cert DER).
    fn generate_self_signed() -> Result<(String, String, Vec<u8>), Box<dyn std::error::Error>> {
        let certified_key = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ])
        .map_err(|error| format!("generating self-signed cert: {error}"))?;
        let cert_der = certified_key.cert.der().to_vec();
        let cert_pem = certified_key.cert.pem();
        let key_pem = certified_key.key_pair.serialize_pem();
        Ok((cert_pem, key_pem, cert_der))
    }

    fn load_from_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<TlsIdentity, Box<dyn std::error::Error>> {
        let mut cert_reader = cert_pem;
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("parsing TLS certificate PEM: {error}"))?;
        if certs.is_empty() {
            return Err("TLS certificate PEM contains no certificates".into());
        }
        let fingerprint = cert_fingerprint_sha256_hex(certs[0].as_ref());

        let mut key_reader = key_pem;
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|error| format!("parsing TLS key PEM: {error}"))?
            .ok_or("TLS key PEM contains no private key")?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|error| format!("building TLS server config: {error}"))?;
        Ok(TlsIdentity {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            fingerprint,
        })
    }

    #[cfg(test)]
    mod tests {
        use grotto_protocol::cert_fingerprint_sha256_hex;

        use super::{generate_self_signed, load_from_pem, load_or_generate_at};

        #[test]
        fn incomplete_and_unsafe_tls_identities_are_never_replaced() {
            use std::os::unix::fs::{PermissionsExt, symlink};
            let dir = crate::private_test_directory().unwrap();
            let cert = dir.path().join("cert.pem");
            let key = dir.path().join("key.pem");
            load_or_generate_at(&cert, &key).unwrap();
            let original_cert = std::fs::read(&cert).unwrap();
            let original_key = std::fs::read(&key).unwrap();
            std::fs::remove_file(&cert).unwrap();
            assert!(load_or_generate_at(&cert, &key).is_err());
            assert_eq!(original_key, std::fs::read(&key).unwrap());
            std::fs::write(&cert, original_cert).unwrap();
            std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_or_generate_at(&cert, &key).is_err());
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = dir.path().join("link.pem");
            symlink(&key, &link).unwrap();
            assert!(load_or_generate_at(&cert, &link).is_err());
            assert_eq!(original_key, std::fs::read(&key).unwrap());
        }

        #[test]
        fn generated_cert_loads_and_fingerprint_matches() {
            let (cert_pem, key_pem, cert_der) =
                generate_self_signed().expect("cert generation should succeed");
            let identity =
                load_from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).expect("cert should load");
            assert_eq!(identity.fingerprint, cert_fingerprint_sha256_hex(&cert_der));
        }

        #[test]
        fn identity_persists_across_reloads() {
            let dir =
                crate::private_test_directory().expect("temporary directory should be created");
            let cert_path = dir.path().join("cert.pem");
            let key_path = dir.path().join("key.pem");

            let first =
                load_or_generate_at(&cert_path, &key_path).expect("first load should succeed");
            let second =
                load_or_generate_at(&cert_path, &key_path).expect("second load should succeed");
            assert_eq!(first.fingerprint, second.fingerprint);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let key_mode = std::fs::metadata(&key_path)
                    .expect("key metadata should be readable")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(key_mode, 0o600);
            }
        }
    }
}

fn verify_authentication_signature(
    verifying_key: &VerifyingKey,
    user_id: UserId,
    public_key: &Ed25519PublicKeyBytes,
    challenge: &AuthenticationChallenge,
    signature_bytes: &grotto_protocol::Ed25519SignatureBytes,
) -> Result<(), ed25519_dalek::SignatureError> {
    let signature = Signature::from_bytes(signature_bytes.as_bytes());
    let transcript = authentication_transcript(PROTOCOL_VERSION, user_id, public_key, challenge);

    verifying_key.verify_strict(&transcript, &signature)
}

async fn read_handshake_frame<S>(socket: &mut S, expected: &str) -> io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    timeout(
        Duration::from_secs(limits::runtime().handshake_seconds),
        read_frame(socket),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out waiting for {expected}"),
        )
    })?
}

async fn send_protocol_error<S>(
    socket: &mut S,
    error: ProtocolError,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    send_request_error(socket, None, error).await
}

async fn send_request_error<S>(
    socket: &mut S,
    request_id: Option<grotto_protocol::MessageId>,
    error: ProtocolError,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let encoded = encode_message(&RelayMessage::ProtocolError { request_id, error })?;
    write_frame(socket, &encoded).await?;
    Ok(())
}

type AuthenticatedSession = (UserId, ConnectionRegistration, mpsc::Receiver<RelayMessage>);

async fn authenticate<S>(
    mut socket: &mut S,
    state: &Arc<DatabaseWorker>,
    hub: &Arc<ConnectionHub>,
) -> Result<Option<AuthenticatedSession>, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The first message from every client must be a ClientHello.
    let Some(frame) = read_handshake_frame(&mut socket, "ClientHello").await? else {
        println!("Client disconnected before handshake");
        return Ok(None);
    };

    let message: ClientMessage = decode_message(&frame)?;

    match message {
        ClientMessage::ClientHello { version } => {
            if version != PROTOCOL_VERSION {
                let error = ProtocolError::UnsupportedVersion {
                    supported: PROTOCOL_VERSION,
                    received: version,
                };
                send_protocol_error(&mut socket, error).await?;
                return Err(error.into());
            }

            println!("Client handshake accepted. Protocol version: {version}");

            let response = RelayMessage::ServerHello {
                version: PROTOCOL_VERSION,
            };

            let encoded = encode_message(&response)?;

            write_frame(&mut socket, &encoded).await?;
        }

        other => {
            let error = ProtocolError::UnexpectedMessage {
                expected: ClientMessageKind::ClientHello,
                received: other.kind(),
            };
            send_protocol_error(&mut socket, error).await?;
            return Err(error.into());
        }
    }

    let Some(frame) = read_handshake_frame(&mut socket, "ClientIdentify").await? else {
        println!("Client disconnected before identification");
        return Ok(None);
    };

    let message: ClientMessage = decode_message(&frame)?;

    let (user_id, public_key, enrollment) = match message {
        ClientMessage::ClientIdentify {
            user_id,
            public_key,
            enrollment,
        } => (user_id, public_key, enrollment),

        other => {
            let error = ProtocolError::UnexpectedMessage {
                expected: ClientMessageKind::ClientIdentify,
                received: other.kind(),
            };
            send_protocol_error(&mut socket, error).await?;
            return Err(error.into());
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(public_key.as_bytes()) {
        Ok(verifying_key) => verifying_key,
        Err(_) => {
            let error = ProtocolError::InvalidPublicKey;
            send_protocol_error(&mut socket, error).await?;
            return Err(error.into());
        }
    };

    let challenge = AuthenticationChallenge::generate()?;

    let response = RelayMessage::ServerAuthenticationChallenge { challenge };

    let encoded = encode_message(&response)?;

    write_frame(&mut socket, &encoded).await?;

    let Some(frame) = read_handshake_frame(&mut socket, "ClientAuthenticationResponse").await?
    else {
        println!("Client disconnected before authentication");
        return Ok(None);
    };

    let message: ClientMessage = decode_message(&frame)?;

    let signature_bytes = match message {
        ClientMessage::ClientAuthenticationResponse { signature } => signature,

        other => {
            let error = ProtocolError::UnexpectedMessage {
                expected: ClientMessageKind::ClientAuthenticationResponse,
                received: other.kind(),
            };
            send_protocol_error(&mut socket, error).await?;
            return Err(error.into());
        }
    };

    if verify_authentication_signature(
        &verifying_key,
        user_id,
        &public_key,
        &challenge,
        &signature_bytes,
    )
    .is_err()
    {
        let error = ProtocolError::AuthenticationFailed;
        send_protocol_error(&mut socket, error).await?;
        return Err(error.into());
    }

    println!("Authenticated identity for {user_id}");

    let registration = match state
        .execute(move |registration_state| {
            registration_state.register_enrolled_identity(user_id, public_key, enrollment)
        })
        .await?
    {
        Ok(registration) => registration,
        Err(error) => {
            if matches!(error, StorageError::IdentityKeyConflict) {
                send_protocol_error(&mut socket, ProtocolError::IdentityKeyConflict).await?;
            }
            if matches!(error, StorageError::EnrollmentRequired) {
                send_protocol_error(&mut socket, ProtocolError::AuthenticationFailed).await?;
            }
            return Err(error.into());
        }
    };

    match registration {
        Registration::New => println!("Registered identity for {user_id}"),
        Registration::Existing => println!("Known identity authenticated as {user_id}"),
    }

    let (registration, outbound_receiver) = match hub.register(user_id) {
        Ok(session) => session,
        Err(error) => {
            send_protocol_error(&mut socket, ProtocolError::AuthenticationFailed).await?;
            return Err(error.into());
        }
    };
    let response = RelayMessage::ServerIdentifyAccepted { user_id };

    let encoded = encode_message(&response)?;

    write_frame(&mut socket, &encoded).await?;

    Ok(Some((user_id, registration, outbound_receiver)))
}

async fn wait_shutdown(receiver: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    match receiver {
        Some(receiver) => {
            if !*receiver.borrow() {
                let _ = receiver.changed().await;
            }
        }
        None => std::future::pending().await,
    }
}

async fn handle_connection<S>(
    mut socket: S,
    state: Arc<DatabaseWorker>,
    hub: Arc<ConnectionHub>,
    deadline: tokio::time::Instant,
    handshake: Option<HandshakeLease>,
    mut shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some((user_id, _registration, mut outbound_receiver)) =
        tokio::select! {result=tokio::time::timeout_at(deadline, authenticate(&mut socket, &state, &hub))=>result,_=wait_shutdown(&mut shutdown)=>return Ok(())}
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authentication timed out"))??
    else {
        return Ok(());
    };
    drop(handshake);

    // Handshake succeeded. The stream splits here: a dedicated reader task
    // owns frame-decoding state for its whole lifetime, so an outbound
    // notification can never cancel a partially-read frame (finding #2).
    // This loop is the single writer.
    let (mut socket_reader, mut socket) = tokio::io::split(socket);
    let (inbound_sender, mut inbound_receiver) = mpsc::channel(INBOUND_CHANNEL_CAPACITY);
    let mut reader_tasks = tokio::task::JoinSet::new();
    let payload_budget = hub.payload_budget.clone();
    reader_tasks.spawn(async move {
        read_inbound_with_budget(&mut socket_reader, inbound_sender, payload_budget).await;
    });

    let result = async {
    loop {
        tokio::select! {
            _=wait_shutdown(&mut shutdown)=>break,
            inbound = inbound_receiver.recv() => {
                let Some(event) = inbound else {
                    return Err("inbound reader task ended".into());
                };
                let (message,lease) = match event {
                    InboundEvent::Message(message,lease) => (message,lease),
                    InboundEvent::Disconnected => {
                        println!("Client disconnected");
                        break;
                    }
                    InboundEvent::Error(error) => return Err(error),
                };

                match message {
            ClientMessage::Delivery { request_id, request } => {
                if !hub.admit_request(user_id) {
                    metrics::increment(&metrics::QUEUE_PRESSURE);
                    write_frame(&mut socket,&encode_message(&RelayMessage::Delivery {request_id,response:grotto_protocol::delivery::Response::Rejected(grotto_protocol::delivery::Rejection::Overloaded)})?).await?;
                    continue;
                }
                let recovery=matches!(request,grotto_protocol::delivery::Request::FetchRoomEvents {..}|grotto_protocol::delivery::Request::FetchWelcomes {..}|grotto_protocol::delivery::Request::SyncIndex {..});
                let result = tokio::select! {result=state.execute(move |state| (state.deliver(user_id, request_id, request),lease))=>result,_=wait_shutdown(&mut shutdown)=>break};
                let (response,_lease) = match result {
                    Ok((Ok(response),lease)) => (response,Some(lease)),
                    Ok((Err(error),lease)) => { if recovery {metrics::increment(&metrics::RECOVERY_FAILURES);} eprintln!("Delivery storage failure: {error}"); (grotto_protocol::delivery::Response::Rejected(grotto_protocol::delivery::Rejection::Internal),Some(lease)) }
                    Err(_) => (grotto_protocol::delivery::Response::Rejected(grotto_protocol::delivery::Rejection::Overloaded),None),
                };
                if matches!(response, grotto_protocol::delivery::Response::AppendAccepted { .. }) {
                    let recipients: Vec<_> = hub.active_identities.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().copied().collect();
                    hub.notify(&recipients, RelayMessage::DeliveryChanged);
                }
                let encoded = encode_message(&RelayMessage::Delivery { request_id, response })?;
                tokio::select! {result=write_frame(&mut socket, &encoded)=>result?,_=wait_shutdown(&mut shutdown)=>break};
            }
            other => {
                let error = ProtocolError::UnexpectedMessage {
                    expected: ClientMessageKind::Delivery,
                    received: other.kind(),
                };
                send_protocol_error(&mut socket, error).await?;
            }
                }
            }
            outbound = outbound_receiver.recv() => {
                let Some(outbound) = outbound else {
                    // Either the hub is gone or this connection was evicted
                    // for lagging; either way the client reconnects and heals
                    // via sync.
                    return Err("outbound channel closed (evicted or hub gone)".into());
                };
                let encoded = encode_message(&outbound)?;
                tokio::select! {result=write_frame(&mut socket, &encoded)=>result?,_=wait_shutdown(&mut shutdown)=>break};
            }
        }
    }

    Ok(())
    }.await;
    // JoinSet also aborts the reader if the entire session future is dropped.
    // On ordinary failure, wait for it to release the socket before returning.
    reader_tasks.shutdown().await;
    result
}

#[cfg(test)]
fn private_test_directory() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::{Signature, Signer, SigningKey};

    use grotto_protocol::{
        AuthenticationChallenge, ClientMessage, Ed25519PublicKeyBytes, Ed25519SignatureBytes,
        MessageId, PROTOCOL_VERSION, RelayMessage, UserId, authentication_transcript,
        encode_message,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc;

    use super::{ConnectionHub, InboundEvent, read_inbound_loop, verify_authentication_signature};

    #[test]
    fn handshake_admission_releases_capacity_and_removes_ip_entries() {
        use super::HandshakeLease;
        let pending = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let ip = "127.0.0.1".parse().unwrap();
        let mut leases = Vec::new();
        for _ in 0..4 {
            leases.push(HandshakeLease::acquire(pending.clone(), ip).unwrap());
        }
        assert!(HandshakeLease::acquire(pending.clone(), ip).is_none());
        for octet in 2..=4 {
            for _ in 0..4 {
                leases.push(
                    HandshakeLease::acquire(
                        pending.clone(),
                        format!("127.0.0.{octet}").parse().unwrap(),
                    )
                    .unwrap(),
                );
            }
        }
        assert!(HandshakeLease::acquire(pending.clone(), "127.0.0.5".parse().unwrap()).is_none());
        leases.pop();
        assert!(HandshakeLease::acquire(pending.clone(), "127.0.0.5".parse().unwrap()).is_some());
        drop(leases);
        assert!(pending.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_deadline_is_shared_across_messages() {
        let dir = crate::private_test_directory().unwrap();
        let state = Arc::new(
            super::DatabaseWorker::start(
                super::RelayState::open(&dir.path().join("relay.db")).unwrap(),
                128,
            )
            .unwrap(),
        );
        let (mut client, server) = tokio::io::duplex(1024);
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(super::handle_connection(
            server,
            state,
            Arc::new(ConnectionHub::default()),
            started + super::HANDSHAKE_TIMEOUT,
            None,
            None,
        ));
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        grotto_protocol::write_frame(
            &mut client,
            &encode_message(&ClientMessage::ClientHello {
                version: PROTOCOL_VERSION,
            })
            .unwrap(),
        )
        .await
        .unwrap();
        grotto_protocol::read_frame(&mut client)
            .await
            .unwrap()
            .unwrap();
        assert!(task.await.unwrap().is_err());
        assert_eq!(started.elapsed(), super::HANDSHAKE_TIMEOUT);
        assert!(
            grotto_protocol::read_frame(&mut client)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn partial_header_and_body_have_one_completion_deadline() {
        for prefix in [vec![0], vec![0, 0, 0, 8, 1]] {
            let (mut writer, mut reader) = tokio::io::duplex(32);
            writer.write_all(&prefix).await.unwrap();
            let start = tokio::time::Instant::now();
            let error = super::read_session_frame(&mut reader, super::FRAME_TIMEOUT)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            assert_eq!(start.elapsed(), super::FRAME_TIMEOUT);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_time_does_not_consume_frame_deadline() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        let task = tokio::spawn(async move {
            super::read_session_frame(&mut reader, super::FRAME_TIMEOUT).await
        });
        tokio::time::sleep(super::FRAME_TIMEOUT * 3).await;
        assert!(!task.is_finished());
        writer.write_all(&[0, 0, 0, 1, 42]).await.unwrap();
        assert_eq!(task.await.unwrap().unwrap(), Some(vec![42]));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_writer_times_out() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let error = super::write_frame(&mut writer, &[42]).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn eviction_joins_reader_and_releases_socket() {
        use grotto_protocol::{decode_message, read_frame};
        use tokio::io::AsyncReadExt;
        let dir = crate::private_test_directory().unwrap();
        let state = Arc::new(
            super::DatabaseWorker::start(
                super::RelayState::open(&dir.path().join("relay.db")).unwrap(),
                8,
            )
            .unwrap(),
        );
        let hub = test_hub();
        let server_hub = hub.clone();
        let (mut client, server) = tokio::io::duplex(4096);
        state
            .execute(|state| {
                state
                    .lock_connection()
                    .unwrap()
                    .execute(
                        "INSERT INTO identities VALUES(?1,?2)",
                        rusqlite::params![
                            UserId::from_bytes([73; 16]).to_bytes().as_slice(),
                            SigningKey::from_bytes(&[31; 32])
                                .verifying_key()
                                .to_bytes()
                                .as_slice()
                        ],
                    )
                    .unwrap();
            })
            .await
            .unwrap();
        let session = tokio::spawn(super::handle_connection(
            server,
            state,
            server_hub,
            tokio::time::Instant::now() + super::HANDSHAKE_TIMEOUT,
            None,
            None,
        ));
        let user_id = UserId::from_bytes([73; 16]);
        let key = SigningKey::from_bytes(&[31; 32]);
        let public_key = Ed25519PublicKeyBytes::new(key.verifying_key().to_bytes());
        for message in [
            ClientMessage::ClientHello {
                version: PROTOCOL_VERSION,
            },
            ClientMessage::ClientIdentify {
                user_id,
                public_key,
                enrollment: None,
            },
        ] {
            super::write_frame(&mut client, &encode_message(&message).unwrap())
                .await
                .unwrap();
            let response: RelayMessage =
                decode_message(&read_frame(&mut client).await.unwrap().unwrap()).unwrap();
            if let RelayMessage::ServerAuthenticationChallenge { challenge } = response {
                let transcript =
                    authentication_transcript(PROTOCOL_VERSION, user_id, &public_key, &challenge);
                let response = ClientMessage::ClientAuthenticationResponse {
                    signature: Ed25519SignatureBytes::new(key.sign(&transcript).to_bytes()),
                };
                super::write_frame(&mut client, &encode_message(&response).unwrap())
                    .await
                    .unwrap();
                let accepted: RelayMessage =
                    decode_message(&read_frame(&mut client).await.unwrap().unwrap()).unwrap();
                assert!(matches!(
                    accepted,
                    RelayMessage::ServerIdentifyAccepted { .. }
                ));
            }
        }
        // Registration happens immediately after the acceptance write.
        tokio::task::yield_now().await;
        let ids = connection_ids(&hub, user_id);
        assert_eq!(ids.len(), 1);
        hub.unregister(user_id, ids[0]);
        assert!(
            super::timeout(super::WRITE_TIMEOUT, session)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let mut byte = [0];
        assert_eq!(
            super::timeout(super::WRITE_TIMEOUT, client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[test]
    fn authentication_rejects_a_tampered_signature() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let challenge =
            AuthenticationChallenge::generate().expect("the OS should provide randomness");
        let user_id = UserId::from_bytes([3_u8; 16]);
        let public_key = Ed25519PublicKeyBytes::new(verifying_key.to_bytes());
        let transcript =
            authentication_transcript(PROTOCOL_VERSION, user_id, &public_key, &challenge);

        let valid_signature: Signature = signing_key.sign(&transcript);

        let valid_signature_bytes = Ed25519SignatureBytes::new(valid_signature.to_bytes());

        assert!(
            verify_authentication_signature(
                &verifying_key,
                user_id,
                &public_key,
                &challenge,
                &valid_signature_bytes,
            )
            .is_ok()
        );

        let mut tampered_bytes = valid_signature.to_bytes();
        tampered_bytes[0] ^= 1;

        let tampered_signature = Ed25519SignatureBytes::new(tampered_bytes);

        assert!(
            verify_authentication_signature(
                &verifying_key,
                user_id,
                &public_key,
                &challenge,
                &tampered_signature,
            )
            .is_err()
        );
    }

    fn test_hub() -> Arc<ConnectionHub> {
        Arc::new(ConnectionHub::default())
    }

    fn ping(request_id: MessageId) -> RelayMessage {
        RelayMessage::Delivery {
            request_id,
            response: grotto_protocol::delivery::Response::Acknowledged,
        }
    }

    fn connection_ids(hub: &ConnectionHub, user_id: UserId) -> Vec<u64> {
        hub.connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&user_id)
            .map(|connections| connections.keys().copied().collect())
            .unwrap_or_default()
    }

    #[test]
    fn second_session_is_rejected_until_first_registration_is_released() {
        let hub = test_hub();
        let user = UserId::from_bytes([71; 16]);
        let (registration, _receiver) = hub.register(user).unwrap();
        assert!(hub.register(user).is_err());
        hub.unregister(user, registration.connection_id);
        assert!(
            hub.register(user).is_err(),
            "eviction must retain the identity lease until session teardown"
        );
        drop(registration);
        assert!(hub.register(user).is_ok());
    }

    #[test]
    fn closed_connections_are_pruned_on_notify() {
        let hub = test_hub();
        let user_id = UserId::from_bytes([9_u8; 16]);
        let (_registration, receiver) = hub.register(user_id).unwrap();
        drop(receiver);

        hub.notify(&[user_id], ping(MessageId::from_bytes([1_u8; 16])));

        assert!(connection_ids(&hub, user_id).is_empty());
    }

    #[tokio::test]
    async fn lagged_connections_are_evicted_while_draining_survive() {
        let hub = test_hub();
        let user_id = UserId::from_bytes([9_u8; 16]);
        let (closed_registration, closed_receiver) = hub.register(user_id).unwrap();
        drop(closed_receiver);
        let lagged_user = UserId::from_bytes([10; 16]);
        let healthy_user = UserId::from_bytes([11; 16]);
        let (lagged_registration, _lagged_receiver) = hub.register(lagged_user).unwrap();
        let (healthy_registration, mut healthy_receiver) = hub.register(healthy_user).unwrap();

        let drain = tokio::spawn(async move {
            let mut received = 0_usize;
            while healthy_receiver.recv().await.is_some() {
                received += 1;
            }
            received
        });

        for round in 0..200 {
            hub.notify(
                &[user_id, lagged_user, healthy_user],
                ping(MessageId::from_bytes([2_u8; 16])),
            );
            if round % 2 == 0 {
                tokio::task::yield_now().await;
            }
        }
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        let remaining: Vec<_> = [user_id, lagged_user, healthy_user]
            .into_iter()
            .flat_map(|user| connection_ids(&hub, user))
            .collect();
        assert!(
            !remaining.contains(&closed_registration.connection_id),
            "closed connection should be pruned"
        );
        assert!(
            !remaining.contains(&lagged_registration.connection_id),
            "lagged connection should be evicted, remaining: {remaining:?}"
        );
        assert!(
            remaining.contains(&healthy_registration.connection_id),
            "draining connection should survive, remaining: {remaining:?}"
        );

        drop(closed_registration);
        drop(lagged_registration);
        drop(healthy_registration);
        drop(hub);
        drain.abort();
    }

    #[tokio::test]
    async fn fragmented_frames_decode_intact_without_cancellation() {
        // Bytes arrive one at a time; the reader owns framing state until the
        // frame completes, so no interleaving notification can corrupt it.
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let (sender, mut receiver) = mpsc::channel(8);
        let task = tokio::spawn(async move { read_inbound_loop(&mut reader, sender).await });

        let request_id = MessageId::new().expect("the OS should provide randomness");
        let frame = encode_message(&ClientMessage::Delivery {
            request_id,
            request: grotto_protocol::delivery::Request::SyncIndex { after_room: None },
        })
        .expect("message encoding should succeed");
        let mut wire = (frame.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&frame);
        for byte in wire {
            writer
                .write_all(&[byte])
                .await
                .expect("duplex write should succeed");
        }

        match receiver.recv().await.expect("reader should deliver") {
            InboundEvent::Message(
                ClientMessage::Delivery {
                    request_id: received,
                    ..
                },
                _,
            ) => assert_eq!(received, request_id),
            other => panic!("expected sync message, got {other:?}"),
        }

        drop(writer);
        match receiver.recv().await.expect("reader should deliver") {
            InboundEvent::Disconnected => {}
            other => panic!("expected disconnect, got {other:?}"),
        }
        task.await.expect("reader task should finish");
    }

    #[tokio::test]
    async fn oversized_frames_surface_as_reader_errors() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        let (sender, mut receiver) = mpsc::channel(8);
        let task = tokio::spawn(async move { read_inbound_loop(&mut reader, sender).await });

        writer
            .write_all(&u32::MAX.to_be_bytes())
            .await
            .expect("duplex write should succeed");
        match receiver.recv().await.expect("reader should deliver") {
            InboundEvent::Error(_) => {}
            other => panic!("expected error event, got {other:?}"),
        }
        task.await.expect("reader task should finish");
    }
}
