//! V9 SQLite repository. Unknown formats are rejected; no migrations run.
use rusqlite::Connection;
use std::{fmt, path::Path, sync::Mutex, time::Duration};

pub struct RelayState {
    connection: Mutex<Connection>,
    _file_lock: std::fs::File,
    pub(crate) path: std::path::PathBuf,
    pub(crate) limits: crate::limits::StorageLimits,
}

impl RelayState {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        Self::open_with_limits(path, crate::limits::StorageLimits::environment()?)
    }

    pub fn open_with_limits(
        path: &Path,
        limits: crate::limits::StorageLimits,
    ) -> Result<Self, StorageError> {
        let file_lock = crate::private_file::open_locked(path).map_err(StorageError::File)?;
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        initialize(&connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
            _file_lock: file_lock,
            path: path.to_owned(),
            limits,
        })
    }

    pub(crate) fn lock_connection(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Connection>, StorageError> {
        self.connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)
    }
}

fn initialize(connection: &Connection) -> Result<(), StorageError> {
    // Inspect before writing anything: existing databases are never migrated.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let application: i64 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let objects: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if version == 9 && application == 0x4752523a {
        return Ok(());
    }
    if version != 0 || application != 0 || objects != 0 {
        return Err(StorageError::InvalidStoredData(
            "unsupported relay schema; choose a fresh database (no migrations)",
        ));
    }
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS schema_meta(id INTEGER PRIMARY KEY CHECK(id = 1), version INTEGER NOT NULL);
             INSERT OR IGNORE INTO schema_meta (id, version) VALUES (1, 9);
             CREATE TABLE IF NOT EXISTS identities(
                 user_id BLOB PRIMARY KEY CHECK(length(user_id) = 16),
                 public_key BLOB NOT NULL CHECK(length(public_key) = 32)
             );
             CREATE TABLE IF NOT EXISTS rooms(
                 room_id BLOB PRIMARY KEY CHECK(length(room_id) = 16),
                 name TEXT NOT NULL,
                 created_by BLOB NOT NULL CHECK(length(created_by) = 16),
                 created_at INTEGER NOT NULL DEFAULT(unixepoch())
             );
             CREATE TABLE IF NOT EXISTS room_subscribers(
                 room_id BLOB NOT NULL CHECK(length(room_id) = 16),
                 user_id BLOB NOT NULL CHECK(length(user_id) = 16),
                 PRIMARY KEY (room_id, user_id)
             );
             CREATE TABLE IF NOT EXISTS key_packages(
                 user_id BLOB NOT NULL CHECK(length(user_id) = 16),
                 key_package BLOB NOT NULL,
                 published_at INTEGER NOT NULL DEFAULT(unixepoch())
             );
             CREATE TABLE enrollment_tokens(hash BLOB PRIMARY KEY, user_id BLOB NOT NULL, fingerprint BLOB NOT NULL, expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE usage_sender(user_id BLOB PRIMARY KEY, bytes INTEGER NOT NULL);
             CREATE TABLE usage_room(room BLOB PRIMARY KEY, bytes INTEGER NOT NULL);
             CREATE TABLE delivery_requests(user_id BLOB NOT NULL, request_id BLOB NOT NULL, hash BLOB NOT NULL, response BLOB NOT NULL, PRIMARY KEY(user_id,request_id));
             CREATE TABLE delivery_events(room BLOB NOT NULL, sequence INTEGER NOT NULL, event_id BLOB NOT NULL UNIQUE, sender BLOB NOT NULL, record BLOB NOT NULL, PRIMARY KEY(room,sequence));
             CREATE TABLE delivery_welcomes(cursor INTEGER PRIMARY KEY AUTOINCREMENT, recipient BLOB NOT NULL, record BLOB NOT NULL);
             CREATE TABLE fetch_grants(recipient BLOB NOT NULL, requester BLOB NOT NULL, PRIMARY KEY(recipient,requester));
             CREATE TABLE package_allocations(requester BLOB NOT NULL, recipient BLOB NOT NULL, allocated_at INTEGER NOT NULL);
             CREATE INDEX subscribers_by_user ON room_subscribers(user_id,room_id);
             CREATE INDEX welcomes_by_recipient ON delivery_welcomes(recipient,cursor);
             CREATE INDEX packages_by_user ON key_packages(user_id,published_at);
             CREATE INDEX allocations_by_recipient ON package_allocations(recipient,allocated_at,requester);
             CREATE INDEX rooms_by_creator ON rooms(created_by);
             PRAGMA user_version = 9;
             PRAGMA application_id = 1196577338;
             COMMIT;",
        )
        .map_err(StorageError::Database)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registration {
    New,
    Existing,
}
#[derive(Debug)]
pub enum StorageError {
    File(std::io::Error),
    Database(rusqlite::Error),
    InvalidStoredData(&'static str),
    LockPoisoned,
    Random(String),
    IdentityKeyConflict,
    EnrollmentRequired,
}
impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(e) => write!(f, "relay file error: {e}"),
            Self::Database(e) => write!(f, "relay database error: {e}"),
            Self::InvalidStoredData(e) => write!(f, "invalid relay state: {e}"),
            Self::LockPoisoned => f.write_str("relay database lock poisoned"),
            Self::Random(e) => write!(f, "randomness failure: {e}"),
            Self::IdentityKeyConflict => f.write_str("identity key conflict"),
            Self::EnrollmentRequired => f.write_str("private enrollment required"),
        }
    }
}
impl std::error::Error for StorageError {}
impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_formats_are_preserved_and_current_format_reopens() {
        for (version, application) in [(8, 0), (9, 0x47525239), (10, 0x4752523a), (0, 0)] {
            let dir = crate::private_test_directory().unwrap();
            let path = dir.path().join("relay.db");
            let file = crate::private_file::open_locked(&path).unwrap();
            let db = Connection::open(&path).unwrap();
            db.execute_batch(&format!("CREATE TABLE sentinel(value); INSERT INTO sentinel VALUES ('preserve'); PRAGMA user_version={version}; PRAGMA application_id={application};")).unwrap();
            drop(db);
            drop(file);
            let before = std::fs::read(&path).unwrap();
            assert!(matches!(
                RelayState::open(&path),
                Err(StorageError::InvalidStoredData(_))
            ));
            assert_eq!(before, std::fs::read(&path).unwrap());
        }
        let dir = crate::private_test_directory().unwrap();
        let path = dir.path().join("relay.db");
        drop(RelayState::open(&path).unwrap());
        drop(RelayState::open(&path).unwrap());
    }
}
