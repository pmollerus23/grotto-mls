//! Transactional storage admission and physical recovery reserve.
use crate::storage::StorageError;
use grotto_protocol::{
    UserId,
    delivery::{MAX_PAYLOAD, Request},
};
use rusqlite::{Transaction, params};
use std::{os::unix::ffi::OsStrExt, path::Path};
#[derive(Clone, Debug)]
pub struct StorageLimits {
    pub global: u64,
    pub sender: u64,
    pub room: u64,
    pub reserve: u64,
}
impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            global: 1024 * 1024 * 1024,
            sender: 100 * 1024 * 1024,
            room: 100 * 1024 * 1024,
            reserve: 64 * 1024 * 1024,
        }
    }
}
impl StorageLimits {
    pub fn environment() -> Result<Self, StorageError> {
        let mut limits = Self::default();
        for (name, value) in [
            ("GROTTO_STORAGE_GLOBAL_BYTES", &mut limits.global),
            ("GROTTO_STORAGE_SENDER_BYTES", &mut limits.sender),
            ("GROTTO_STORAGE_ROOM_BYTES", &mut limits.room),
            ("GROTTO_RECOVERY_RESERVE_BYTES", &mut limits.reserve),
        ] {
            if let Ok(text) = std::env::var(name) {
                *value = text
                    .parse()
                    .map_err(|_| StorageError::InvalidStoredData("invalid storage limit"))?;
            }
        }
        Ok(limits)
    }
    pub fn admit(
        &self,
        tx: &Transaction<'_>,
        path: &Path,
        user: UserId,
        request: &Request,
    ) -> Result<bool, StorageError> {
        // Reads, receipts, and saved-result retries are handled before admission.
        let wire = grotto_protocol::encode_message(request)
            .map_err(|_| StorageError::InvalidStoredData("cannot encode request"))?;
        if wire.len() > MAX_PAYLOAD {
            return Ok(false);
        }
        // Include rows, indexes, result journal and (for appends) the Welcome copy.
        let required = (wire.len() as u64)
            .saturating_mul(3)
            .saturating_add(16 * 1024);
        let page_size: u64 = tx.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let page_count: u64 = tx.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let logical = page_size.saturating_mul(page_count);
        if logical.saturating_add(required) > self.global {
            return Ok(false);
        }
        let mut wal_path = path.as_os_str().to_os_string();
        wal_path.push("-wal");
        let wal = match std::fs::symlink_metadata(Path::new(&wal_path)) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(StorageError::File(e)),
        };
        if logical.saturating_add(wal).saturating_add(required)
            > self.global.saturating_add(self.reserve)
        {
            return Ok(false);
        }
        let used: u64 = tx.query_row(
            "SELECT coalesce((SELECT bytes FROM usage_sender WHERE user_id=?1),0)",
            [user.to_bytes().as_slice()],
            |r| r.get(0),
        )?;
        if used.saturating_add(required) > self.sender {
            return Ok(false);
        }
        if let Request::AppendRoomOperation(operation) = request {
            let used: u64 = tx.query_row(
                "SELECT coalesce((SELECT bytes FROM usage_room WHERE room=?1),0)",
                params![operation.room.to_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if used.saturating_add(required) > self.room {
                return Ok(false);
            }
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = std::ffi::CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| StorageError::InvalidStoredData("invalid database path"))?;
        let mut space = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: NUL-terminated live path and valid writable statvfs output.
        if unsafe { libc::statvfs(parent.as_ptr(), space.as_mut_ptr()) } != 0 {
            return Err(StorageError::File(std::io::Error::last_os_error()));
        }
        // SAFETY: statvfs succeeded and initialized its output.
        let space = unsafe { space.assume_init() };
        Ok((space.f_bavail as u128) * (space.f_frsize as u128)
            >= u128::from(self.reserve.saturating_add(required)))
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeLimits {
    pub connections: usize,
    pub handshakes: usize,
    pub handshakes_per_ip: usize,
    pub database_queue: usize,
    pub handshake_seconds: u64,
    pub frame_seconds: u64,
    pub write_seconds: u64,
    pub requests_per_second: usize,
    pub request_burst: usize,
    pub payload_bytes: usize,
}
impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            connections: 128,
            handshakes: 16,
            handshakes_per_ip: 4,
            database_queue: 128,
            handshake_seconds: 10,
            frame_seconds: 15,
            write_seconds: 10,
            requests_per_second: 20,
            request_burst: 40,
            payload_bytes: 64 * 1024 * 1024,
        }
    }
}
static RUNTIME: std::sync::OnceLock<RuntimeLimits> = std::sync::OnceLock::new();
pub fn runtime() -> &'static RuntimeLimits {
    RUNTIME.get_or_init(RuntimeLimits::default)
}
pub fn configure() -> Result<(), StorageError> {
    let mut config = RuntimeLimits::default();
    for (name, value) in [
        ("GROTTO_MAX_CONNECTIONS", &mut config.connections),
        ("GROTTO_MAX_HANDSHAKES", &mut config.handshakes),
        (
            "GROTTO_MAX_HANDSHAKES_PER_IP",
            &mut config.handshakes_per_ip,
        ),
        ("GROTTO_DATABASE_QUEUE", &mut config.database_queue),
        (
            "GROTTO_REQUESTS_PER_SECOND",
            &mut config.requests_per_second,
        ),
        ("GROTTO_REQUEST_BURST", &mut config.request_burst),
        ("GROTTO_PAYLOAD_BYTES", &mut config.payload_bytes),
    ] {
        if let Ok(text) = std::env::var(name) {
            *value = text
                .parse()
                .map_err(|_| StorageError::InvalidStoredData("invalid runtime limit"))?;
        }
        if *value == 0 || *value > u32::MAX as usize {
            return Err(StorageError::InvalidStoredData(
                "runtime limit out of range",
            ));
        }
    }
    for (name, value) in [
        ("GROTTO_HANDSHAKE_SECONDS", &mut config.handshake_seconds),
        ("GROTTO_FRAME_SECONDS", &mut config.frame_seconds),
        ("GROTTO_WRITE_SECONDS", &mut config.write_seconds),
    ] {
        if let Ok(text) = std::env::var(name) {
            *value = text
                .parse()
                .map_err(|_| StorageError::InvalidStoredData("invalid deadline"))?;
        }
        if *value == 0 || *value > 3600 {
            return Err(StorageError::InvalidStoredData("deadline out of range"));
        }
    }
    if config.payload_bytes < 2 * 1024 * 1024 {
        return Err(StorageError::InvalidStoredData(
            "payload budget needs at least one 2 MiB operation",
        ));
    }
    let _ = RUNTIME.set(config);
    Ok(())
}
