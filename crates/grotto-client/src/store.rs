//! Unified owner-only client persistence. Schema 9 is a new format, not a
//! migration of the older split application/MLS stores. The transport identity,
//! verified contacts, MLS snapshots/epochs/private packages, exact outbox bytes,
//! processing states, authenticated plaintext, and acknowledgement intents use
//! one SQLite connection. `transaction()` supplies the synchronous application
//! boundary; MLS callbacks acquire short connection locks inside that boundary.
//!
//! Connections are unkeyed (plaintext SQLite), even when SQLCipher is compiled
//! in. An exclusive file lock prevents concurrent clients from opening the same
//! database. Unsupported schemas and unsafe files fail without being replaced.

use std::{path::Path, sync::Mutex, time::Duration};

use grotto_protocol::{MessageId, RoomId, StoredRoomMessage, UserId};
use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA_VERSION: i64 = 9;
const APPLICATION_ID: i64 = 0x4752433a;

/// Maximum message IDs per `AcknowledgeMessages` (mirrors the relay's
/// `MAX_ACKNOWLEDGED_MESSAGES`; larger batches are rejected).
pub const MAX_ACK_CHUNK: usize = 100;

/// MLS signing keypair bytes as `(public_key, secret_key)`.
pub type StoredKeyPair = (Vec<u8>, Vec<u8>);

pub struct ClientStore {
    connection: Mutex<Connection>,
    owner: Mutex<Option<std::thread::ThreadId>>,
    poisoned: std::sync::atomic::AtomicBool,
    _file_lock: std::fs::File,
    new_data_limit: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedMessage {
    pub message_id: MessageId,
    pub room_id: RoomId,
    pub sequence: u64,
    pub author: UserId,
    pub plaintext: Vec<u8>,
}

pub struct OutboxEntry {
    pub request_id: MessageId,
    pub kind: String,
    pub message: Vec<u8>,
}

impl ClientStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let file_lock =
            crate::private_file::open_locked(path).map_err(|source| StoreError::Io {
                context: "opening private client database".into(),
                source,
            })?;
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        initialize(&connection)?;
        let new_data_limit = std::env::var("GROTTO_CLIENT_STORAGE_BYTES")
            .ok()
            .map(|s| s.parse::<u64>())
            .transpose()
            .map_err(|_| StoreError::InvalidData("invalid client storage budget"))?
            .unwrap_or(1024 * 1024 * 1024);
        if new_data_limit < 128 * 1024 || new_data_limit > i64::MAX as u64 - 64 * 1024 * 1024 {
            return Err(StoreError::InvalidData(
                "client storage budget out of range",
            ));
        }
        let page_size: u64 = connection.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        connection.execute_batch(&format!(
            "PRAGMA max_page_count={}",
            (new_data_limit + 64 * 1024 * 1024) / page_size
        ))?;
        Ok(Self {
            connection: Mutex::new(connection),
            owner: Mutex::new(None),
            poisoned: std::sync::atomic::AtomicBool::new(false),
            _file_lock: file_lock,
            new_data_limit,
        })
    }

    pub fn admit_new_data(&self, bytes: usize) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let page_size: u64 = connection.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let pages: u64 = connection.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        if pages
            .saturating_mul(page_size)
            .saturating_add((bytes as u64).saturating_mul(3))
            .saturating_add(64 * 1024)
            > self.new_data_limit
        {
            return Err(StoreError::Quota);
        }
        Ok(())
    }

    pub(crate) fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        if self.poisoned.load(std::sync::atomic::Ordering::Acquire) {
            return Err(StoreError::LockPoisoned);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let owner = self.owner.lock().map_err(|_| StoreError::LockPoisoned)?;
        if owner.is_some_and(|id| id != std::thread::current().id()) {
            return Err(StoreError::InvalidData(
                "transaction belongs to another worker",
            ));
        }
        Ok(connection)
    }

    /// mls-rs may validate members on Rayon threads. Provider callbacks are
    /// synchronous with the service operation and acquire only this short lock.
    pub(crate) fn lock_provider(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        if self.poisoned.load(std::sync::atomic::Ordering::Acquire) {
            return Err(StoreError::LockPoisoned);
        }
        self.connection.lock().map_err(|_| StoreError::LockPoisoned)
    }

    /// A synchronous transaction shared by application and MLS provider calls.
    /// The guard is deliberately !Send: no transaction may cross await points.
    pub fn transaction(&self) -> Result<ClientTransaction<'_>, StoreError> {
        let connection = self.lock()?;
        let mut owner = self.owner.lock().map_err(|_| StoreError::LockPoisoned)?;
        if owner.is_some() {
            return Err(StoreError::InvalidData("nested client transaction"));
        }
        connection.execute_batch("BEGIN IMMEDIATE")?;
        *owner = Some(std::thread::current().id());
        Ok(ClientTransaction {
            store: self,
            done: false,
            _not_send: std::marker::PhantomData,
        })
    }

    pub fn identity(&self) -> Result<crate::identity::ClientIdentity, StoreError> {
        let transaction = self.transaction()?;
        let connection = self.lock()?;
        let existing: Option<(Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT user_id, seed FROM transport_identity WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (id, seed) = match existing {
            Some((id, seed)) => (
                parse_id::<UserId>(&id)?,
                seed.try_into()
                    .map_err(|_| StoreError::InvalidData("invalid identity seed"))?,
            ),
            None => {
                let id = UserId::new()
                    .map_err(|_| StoreError::InvalidData("identity randomness failed"))?;
                let mut seed = [0; 32];
                getrandom::fill(&mut seed)
                    .map_err(|_| StoreError::InvalidData("identity randomness failed"))?;
                connection.execute(
                    "INSERT INTO transport_identity VALUES(1,?1,?2)",
                    params![id.to_bytes().as_slice(), seed.as_slice()],
                )?;
                (id, seed)
            }
        };
        drop(connection);
        transaction.commit()?;
        Ok(crate::identity::ClientIdentity::from_seed(id, seed))
    }

    /// Store a received message. Returns true when it was not seen before
    /// (caller should display it only then).
    pub fn store_message(&self, message: &StoredRoomMessage) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        type EnvelopeRow = (Vec<u8>, u64, Vec<u8>, Vec<u8>);
        let existing: Option<EnvelopeRow> = connection
            .query_row(
                "SELECT room_id,sequence,sender_id,body FROM messages WHERE message_id=?1",
                [message.message_id.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((room, sequence, sender, body)) = existing {
            if room != message.room_id.to_bytes()
                || sequence != message.sequence
                || sender != message.sender_id.to_bytes()
                || body != message.body
            {
                return Err(StoreError::InvalidData(
                    "received event ID reused with different envelope",
                ));
            }
            return Ok(false);
        }
        let changed = connection.execute(
            "INSERT INTO messages
                 (message_id, room_id, sequence, sender_id, body)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                message.message_id.to_bytes().as_slice(),
                message.room_id.to_bytes().as_slice(),
                i64::try_from(message.sequence)
                    .map_err(|_| StoreError::InvalidData("message sequence out of range"))?,
                message.sender_id.to_bytes().as_slice(),
                message.body.as_slice(),
            ],
        )?;
        Ok(changed == 1)
    }

    /// Upsert a message, overwriting sequence and envelope metadata. Used for
    /// the sender's own echo: optimistic sends store a sequence-0 placeholder
    /// that the relay-assigned sequence replaces here.
    pub fn refresh_message(&self, message: &StoredRoomMessage) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO messages
                 (message_id, room_id, sequence, sender_id, body)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(message_id) DO UPDATE SET
                 sequence = excluded.sequence,
                 body = excluded.body",
            params![
                message.message_id.to_bytes().as_slice(),
                message.room_id.to_bytes().as_slice(),
                i64::try_from(message.sequence)
                    .map_err(|_| StoreError::InvalidData("message sequence out of range"))?,
                message.sender_id.to_bytes().as_slice(),
                message.body.as_slice(),
            ],
        )?;
        Ok(())
    }

    pub fn save_outbox(
        &self,
        request_id: MessageId,
        kind: &str,
        message: &[u8],
    ) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let existing: Option<(String, Vec<u8>)> = connection
            .query_row(
                "SELECT kind,message FROM outbox WHERE request_id=?1",
                [request_id.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((old_kind, old_message)) = existing
            && (old_kind != kind || old_message != message)
        {
            return Err(StoreError::InvalidData(
                "attempt ID reused with different payload",
            ));
        }
        connection.execute(
            "INSERT INTO outbox (request_id, kind, message) VALUES (?1, ?2, ?3) ON CONFLICT(request_id) DO NOTHING",
            params![request_id.to_bytes().as_slice(), kind, message,],
        )?;
        Ok(())
    }

    pub fn remove_outbox(&self, request_id: MessageId) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM outbox WHERE request_id = ?1",
            [request_id.to_bytes().as_slice()],
        )?;
        Ok(())
    }

    pub fn find_outbox(&self, id: MessageId) -> Result<Option<OutboxEntry>, StoreError> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT kind,message FROM outbox WHERE request_id=?1",
                [id.to_bytes().as_slice()],
                |row| {
                    Ok(OutboxEntry {
                        request_id: id,
                        kind: row.get(0)?,
                        message: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }
    pub fn outbox_page(&self, after: i64) -> Result<Vec<(i64, OutboxEntry)>, StoreError> {
        let connection = self.lock()?;
        let mut statement=connection.prepare("SELECT rowid,request_id,kind,message FROM outbox WHERE rowid>?1 ORDER BY rowid LIMIT 100")?;
        let rows = statement.query_map([after], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut entries = Vec::new();
        let mut bytes = 0;
        for row in rows {
            let (rowid, id, kind, message) = row?;
            if !entries.is_empty() && bytes + message.len() > 768 * 1024 {
                break;
            }
            bytes += message.len();
            entries.push((
                rowid,
                OutboxEntry {
                    request_id: parse_id::<MessageId>(&id)?,
                    kind,
                    message,
                },
            ));
        }
        Ok(entries)
    }

    #[cfg(test)]
    pub fn load_outbox(&self) -> Result<Vec<OutboxEntry>, StoreError> {
        Ok(self
            .outbox_page(0)?
            .into_iter()
            .map(|(_, entry)| entry)
            .collect())
    }

    pub fn set_processing(&self, message_id: MessageId, state: &str) -> Result<(), StoreError> {
        self.lock()?.execute("INSERT INTO processing VALUES(?1,?2) ON CONFLICT(message_id) DO UPDATE SET state=excluded.state", params![message_id.to_bytes().as_slice(), state])?;
        Ok(())
    }

    pub fn is_settled(&self, message_id: MessageId) -> Result<bool, StoreError> {
        Ok(self.lock()?.query_row("SELECT EXISTS(SELECT 1 FROM processing WHERE message_id=?1 AND state IN ('applied','rejected'))", [message_id.to_bytes().as_slice()], |row| row.get(0))?)
    }

    pub fn record_plaintext(
        &self,
        message: &StoredRoomMessage,
        author: UserId,
        plaintext: &[u8],
    ) -> Result<(), StoreError> {
        self.lock()?.execute("INSERT INTO authenticated_history VALUES(?1,?2,?3,?4,?5) ON CONFLICT(message_id) DO UPDATE SET sequence=excluded.sequence",
            params![message.message_id.to_bytes().as_slice(), message.room_id.to_bytes().as_slice(), message.sequence, author.to_bytes().as_slice(), plaintext])?;
        Ok(())
    }

    pub fn history(
        &self,
        room: RoomId,
        before: Option<u64>,
    ) -> Result<Vec<AuthenticatedMessage>, StoreError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare("SELECT message_id,sequence,author,plaintext FROM authenticated_history WHERE room_id=?1 AND (?2 IS NULL OR sequence<?2) ORDER BY sequence DESC,rowid DESC LIMIT 100")?;
        let rows = statement.query_map(params![room.to_bytes().as_slice(), before], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut messages = Vec::new();
        for row in rows {
            let (id, sequence, author, plaintext) = row?;
            messages.push(AuthenticatedMessage {
                message_id: parse_id(&id)?,
                room_id: room,
                sequence,
                author: parse_id(&author)?,
                plaintext,
            });
        }
        messages.reverse();
        Ok(messages)
    }

    pub fn record_pending_acks(&self, ids: &[(MessageId, RoomId)]) -> Result<(), StoreError> {
        let connection = self.lock()?;
        for (message_id, room_id) in ids {
            connection.execute(
                "INSERT OR IGNORE INTO pending_acks (message_id, room_id) VALUES (?1, ?2)",
                params![
                    message_id.to_bytes().as_slice(),
                    room_id.to_bytes().as_slice(),
                ],
            )?;
        }
        Ok(())
    }

    pub fn clear_pending_acks(&self, ids: &[MessageId]) -> Result<(), StoreError> {
        let connection = self.lock()?;
        for message_id in ids {
            connection.execute(
                "DELETE FROM pending_acks WHERE message_id = ?1",
                [message_id.to_bytes().as_slice()],
            )?;
        }
        Ok(())
    }

    pub fn load_pending_acks(&self) -> Result<Vec<(MessageId, RoomId)>, StoreError> {
        let connection = self.lock()?;
        let mut statement =
            connection.prepare("SELECT message_id, room_id FROM pending_acks ORDER BY rowid")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut ids = Vec::new();
        for row in rows {
            let (message_id, room_id) = row?;
            ids.push((
                parse_id::<MessageId>(&message_id)?,
                parse_id::<RoomId>(&room_id)?,
            ));
        }
        Ok(ids)
    }

    /// Lookup helper for tests: was this message stored?
    #[cfg(test)]
    fn has_message(&self, message_id: MessageId) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE message_id = ?1)",
            [message_id.to_bytes().as_slice()],
            |row| row.get(0),
        )?;
        Ok(present)
    }

    pub fn save_mls_identity(
        &self,
        public_key: &[u8],
        secret_key: &[u8],
    ) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let existing: Option<StoredKeyPair> = connection
            .query_row(
                "SELECT public_key,secret_key FROM mls_identity WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((public, secret)) = existing
            && (public != public_key || secret != secret_key)
        {
            return Err(StoreError::InvalidData(
                "MLS identity replacement is unsupported",
            ));
        }
        connection.execute(
            "INSERT INTO mls_identity (id, public_key, secret_key)
             VALUES (1, ?1, ?2) ON CONFLICT(id) DO NOTHING",
            params![public_key, secret_key],
        )?;
        Ok(())
    }

    pub fn load_mls_identity(&self) -> Result<Option<StoredKeyPair>, StoreError> {
        let connection = self.lock()?;
        let row: Option<(Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT public_key, secret_key FROM mls_identity WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(row)
    }

    pub fn upsert_room(&self, room_id: RoomId, name: &str, origin: &str) -> Result<(), StoreError> {
        let name = grotto_protocol::normalize_room_name(name)
            .map_err(|_| StoreError::InvalidData("invalid room name"))?;
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO rooms (room_id, name, origin) VALUES (?1, ?2, ?3)
             ON CONFLICT(room_id) DO UPDATE SET name = excluded.name",
            params![room_id.to_bytes().as_slice(), name, origin],
        )?;
        Ok(())
    }

    pub fn list_rooms(&self) -> Result<Vec<(RoomId, String, String)>, StoreError> {
        let connection = self.lock()?;
        let mut statement =
            connection.prepare("SELECT room_id, name, origin FROM rooms ORDER BY name")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut rooms = Vec::new();
        for row in rows {
            let (room_id, name, origin) = row?;
            rooms.push((parse_id::<RoomId>(&room_id)?, name, origin));
        }
        Ok(rooms)
    }

    pub fn room_name(&self, room_id: RoomId) -> Result<Option<String>, StoreError> {
        let connection = self.lock()?;
        let name: Option<String> = connection
            .query_row(
                "SELECT name FROM rooms WHERE room_id = ?1",
                [room_id.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(name)
    }

    pub fn record_pending_welcome_acks(
        &self,
        ids: &[(MessageId, RoomId)],
    ) -> Result<(), StoreError> {
        let connection = self.lock()?;
        for (welcome_id, room_id) in ids {
            connection.execute(
                "INSERT OR IGNORE INTO pending_welcome_acks (welcome_id, room_id)
                 VALUES (?1, ?2)",
                params![
                    welcome_id.to_bytes().as_slice(),
                    room_id.to_bytes().as_slice(),
                ],
            )?;
        }
        Ok(())
    }

    pub fn clear_pending_welcome_acks(&self, ids: &[MessageId]) -> Result<(), StoreError> {
        let connection = self.lock()?;
        for welcome_id in ids {
            connection.execute(
                "DELETE FROM pending_welcome_acks WHERE welcome_id = ?1",
                [welcome_id.to_bytes().as_slice()],
            )?;
        }
        Ok(())
    }

    pub fn load_pending_welcome_acks(&self) -> Result<Vec<(MessageId, RoomId)>, StoreError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT welcome_id, room_id FROM pending_welcome_acks ORDER BY rowid")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut ids = Vec::new();
        for row in rows {
            let (welcome_id, room_id) = row?;
            ids.push((
                parse_id::<MessageId>(&welcome_id)?,
                parse_id::<RoomId>(&room_id)?,
            ));
        }
        Ok(ids)
    }
}

pub struct ClientTransaction<'a> {
    store: &'a ClientStore,
    done: bool,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ClientTransaction<'_> {
    pub fn commit(mut self) -> Result<(), StoreError> {
        self.store.lock()?.execute_batch("COMMIT")?;
        *self
            .store
            .owner
            .lock()
            .map_err(|_| StoreError::LockPoisoned)? = None;
        self.done = true;
        Ok(())
    }
}

impl Drop for ClientTransaction<'_> {
    fn drop(&mut self) {
        if !self.done {
            if let Ok(connection) = self.store.lock() {
                // If rollback itself fails, close the connection to all further work.
                if connection.execute_batch("ROLLBACK").is_err() {
                    self.store
                        .poisoned
                        .store(true, std::sync::atomic::Ordering::Release);
                    return;
                }
            } else {
                return;
            }
            if let Ok(mut owner) = self.store.owner.lock() {
                *owner = None;
            }
        }
    }
}

fn initialize(connection: &Connection) -> Result<(), StoreError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StoreError::Database)?;
    let app_id: i64 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if version == SCHEMA_VERSION && app_id == APPLICATION_ID {
        return Ok(());
    }
    let objects: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if version != 0 || app_id != 0 || objects != 0 {
        return Err(StoreError::UnsupportedSchema(version));
    }
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE delivery_cursors(room BLOB PRIMARY KEY, sequence INTEGER NOT NULL);
             CREATE TABLE delivery_inbox(event_id BLOB PRIMARY KEY, room BLOB NOT NULL, sequence INTEGER NOT NULL, record BLOB NOT NULL, state TEXT NOT NULL DEFAULT 'received', UNIQUE(room,sequence));
             CREATE TABLE welcome_inbox(cursor INTEGER PRIMARY KEY, record BLOB NOT NULL, state TEXT NOT NULL DEFAULT 'received');
             CREATE TABLE delivery_meta(id INTEGER PRIMARY KEY, welcome_cursor INTEGER NOT NULL);
             INSERT INTO delivery_meta VALUES(1,0);
             CREATE TABLE delivery_intents(id BLOB PRIMARY KEY, room BLOB NOT NULL UNIQUE, target BLOB, plaintext BLOB, package BLOB, attempt BLOB);
             CREATE TABLE verified_contacts(user_id BLOB PRIMARY KEY CHECK(length(user_id)=16), mls_key BLOB NOT NULL CHECK(length(mls_key)=32), card BLOB NOT NULL CHECK(length(card)=145));
             CREATE TABLE transport_identity(id INTEGER PRIMARY KEY CHECK(id=1), user_id BLOB NOT NULL CHECK(length(user_id)=16), seed BLOB NOT NULL CHECK(length(seed)=32));
             CREATE TABLE mls_groups(group_id BLOB PRIMARY KEY, state BLOB NOT NULL);
             CREATE TABLE mls_epochs(group_id BLOB NOT NULL, epoch BLOB NOT NULL CHECK(length(epoch)=8), state BLOB NOT NULL, PRIMARY KEY(group_id,epoch));
             CREATE TABLE mls_packages(id BLOB PRIMARY KEY, package BLOB NOT NULL, init_key BLOB NOT NULL, leaf_key BLOB NOT NULL, expiration BLOB NOT NULL CHECK(length(expiration)=8));
             CREATE TABLE authenticated_history(message_id BLOB PRIMARY KEY, room_id BLOB NOT NULL, sequence INTEGER NOT NULL, author BLOB NOT NULL, plaintext BLOB NOT NULL);
             CREATE TABLE processing(message_id BLOB PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('received','blocked','applied','rejected')));
             CREATE TABLE IF NOT EXISTS messages(
                 message_id BLOB PRIMARY KEY CHECK(length(message_id) = 16),
                 room_id BLOB NOT NULL CHECK(length(room_id) = 16),
                 sequence INTEGER NOT NULL,
                 sender_id BLOB NOT NULL CHECK(length(sender_id) = 16),
                 body BLOB NOT NULL
             );
             CREATE UNIQUE INDEX messages_for_history ON messages(room_id, sequence) WHERE sequence > 0;
             CREATE TABLE IF NOT EXISTS outbox(
                 request_id BLOB PRIMARY KEY CHECK(length(request_id) = 16),
                 kind TEXT NOT NULL,
                 message BLOB NOT NULL,
                 created_at INTEGER NOT NULL DEFAULT(unixepoch())
             );
             CREATE TABLE IF NOT EXISTS pending_acks(
                 message_id BLOB PRIMARY KEY CHECK(length(message_id) = 16),
                 room_id BLOB NOT NULL CHECK(length(room_id) = 16)
             );
             CREATE TABLE IF NOT EXISTS mls_identity(
                 id INTEGER PRIMARY KEY CHECK(id = 1),
                 public_key BLOB NOT NULL,
                 secret_key BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS rooms(
                 room_id BLOB PRIMARY KEY CHECK(length(room_id) = 16),
                 name TEXT NOT NULL,
                 origin TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS pending_welcome_acks(
                 welcome_id BLOB PRIMARY KEY CHECK(length(welcome_id) = 16),
                 room_id BLOB NOT NULL CHECK(length(room_id) = 16)
             );",
        )
        .map_err(StoreError::Database)?;
    connection
        .execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}; PRAGMA application_id = {APPLICATION_ID}; COMMIT"))
        .map_err(StoreError::Database)?;
    Ok(())
}

fn parse_id<T>(bytes: &[u8]) -> Result<T, StoreError>
where
    T: FromBytes,
{
    T::from_bytes(bytes)
}

trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError>;
}

impl FromBytes for MessageId {
    fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        bytes
            .try_into()
            .map(Self::from_bytes)
            .map_err(|_| StoreError::InvalidData("stored message ID has wrong length"))
    }
}

impl FromBytes for RoomId {
    fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        bytes
            .try_into()
            .map(Self::from_bytes)
            .map_err(|_| StoreError::InvalidData("stored room ID has wrong length"))
    }
}

impl FromBytes for UserId {
    fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        bytes
            .try_into()
            .map(Self::from_bytes)
            .map_err(|_| StoreError::InvalidData("stored user ID has wrong length"))
    }
}

#[derive(Debug)]
pub enum StoreError {
    Quota,
    Database(rusqlite::Error),
    Io {
        context: String,
        source: std::io::Error,
    },
    LockPoisoned,
    InvalidData(&'static str),
    UnsupportedSchema(i64),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(source) => write!(formatter, "client store database error: {source}"),
            Self::Io { context, source } => write!(formatter, "{context}: {source}"),
            Self::LockPoisoned => formatter.write_str("client store lock poisoned"),
            Self::Quota => {
                formatter.write_str("client storage budget exhausted; new data rejected")
            }
            Self::InvalidData(reason) => write!(formatter, "invalid client store data: {reason}"),
            Self::UnsupportedSchema(version) => {
                write!(
                    formatter,
                    "unsupported client store schema version {version}"
                )
            }
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[cfg(test)]
mod tests {
    use grotto_protocol::{MessageId, MlsContentType, RoomId, StoredRoomMessage, UserId};

    use super::ClientStore;

    #[test]
    fn storage_budget_rejects_new_data_but_preserves_existing_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ClientStore::open(&dir.path().join("private/client.db")).unwrap();
        let identity = store.identity().unwrap().user_id();
        store.new_data_limit = 0;
        assert!(matches!(
            store.admit_new_data(1),
            Err(super::StoreError::Quota)
        ));
        assert_eq!(store.identity().unwrap().user_id(), identity);
        assert!(store.outbox_page(0).unwrap().is_empty());
    }

    fn test_message(sequence: u64) -> StoredRoomMessage {
        StoredRoomMessage {
            message_id: MessageId::from_bytes([0x11; 16]),
            room_id: RoomId::from_bytes([0x22; 16]),
            sequence,
            sender_id: UserId::from_bytes([0x33; 16]),
            epoch: 0,
            content_type: MlsContentType::Application,
            body: b"hello".to_vec(),
        }
    }

    fn test_message_with_id(id: u8, sequence: u64) -> StoredRoomMessage {
        StoredRoomMessage {
            message_id: MessageId::from_bytes([id; 16]),
            epoch: 0,
            content_type: MlsContentType::Application,
            ..test_message(sequence)
        }
    }

    #[test]
    fn identity_is_atomic_and_unknown_schemas_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/client.db");
        let store = ClientStore::open(&path).unwrap();
        let identity = store.identity().unwrap();
        drop(store);
        let store = ClientStore::open(&path).unwrap();
        let reloaded = store.identity().unwrap();
        assert_eq!(identity.user_id(), reloaded.user_id());
        assert_eq!(
            identity.signing_key().to_bytes(),
            reloaded.signing_key().to_bytes()
        );
        store
            .lock()
            .unwrap()
            .execute_batch("PRAGMA user_version=2")
            .unwrap();
        drop(store);
        let bytes = std::fs::read(&path).unwrap();
        assert!(matches!(
            ClientStore::open(&path),
            Err(super::StoreError::UnsupportedSchema(2))
        ));
        assert_eq!(bytes, std::fs::read(&path).unwrap());
    }

    #[test]
    fn outbox_attempts_cannot_be_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let store = ClientStore::open(&dir.path().join("private/client.db")).unwrap();
        let id = MessageId::from_bytes([91; 16]);
        store.save_outbox(id, "send", b"original").unwrap();
        store.save_outbox(id, "send", b"original").unwrap();
        assert!(store.save_outbox(id, "send", b"replacement").is_err());
        assert!(store.save_outbox(id, "create", b"original").is_err());
        assert_eq!(store.load_outbox().unwrap()[0].message, b"original");
    }

    #[test]
    fn stored_messages_deduplicate_across_reopen() {
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let path = dir.path().join("state/client.db");

        {
            let store = ClientStore::open(&path).expect("store should open");
            assert!(store.store_message(&test_message(1)).expect("store"));
            assert!(!store.store_message(&test_message(1)).expect("re-store"));
            assert!(
                store
                    .has_message(MessageId::from_bytes([0x11; 16]))
                    .expect("lookup")
            );
        }

        {
            let store = ClientStore::open(&path).expect("store should reopen");
            assert!(
                !store
                    .store_message(&test_message(1))
                    .expect("dedup after reopen"),
                "message seen before restart must not be new"
            );
            assert!(
                store
                    .store_message(&test_message_with_id(0x12, 2))
                    .expect("new id is new")
            );
        }
    }

    #[test]
    fn outbox_round_trips_in_order_and_removes() {
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let store =
            ClientStore::open(&dir.path().join("state/client.db")).expect("store should open");

        let first = MessageId::from_bytes([0x01; 16]);
        let second = MessageId::from_bytes([0x02; 16]);
        store
            .save_outbox(first, "SendRoomMessage", b"one")
            .expect("save");
        store
            .save_outbox(second, "CreateRoom", b"two")
            .expect("save");

        let entries = store.load_outbox().expect("load");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].request_id, first);
        assert_eq!(entries[0].kind, "SendRoomMessage");
        assert_eq!(entries[1].message, b"two");

        store.remove_outbox(first).expect("remove");
        let entries = store.load_outbox().expect("reload");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].request_id, second);
    }

    #[test]
    fn pending_acks_survive_restart_until_cleared() {
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let path = dir.path().join("state/client.db");
        let id = MessageId::from_bytes([0x09; 16]);
        let room = RoomId::from_bytes([0x08; 16]);

        {
            let store = ClientStore::open(&path).expect("store should open");
            store.record_pending_acks(&[(id, room)]).expect("record");
            store
                .record_pending_acks(&[(id, room)])
                .expect("idempotent record");
        }
        {
            let store = ClientStore::open(&path).expect("store should reopen");
            let pending = store.load_pending_acks().expect("load");
            assert_eq!(pending, vec![(id, room)]);
            store.clear_pending_acks(&[id]).expect("clear");
            assert!(store.load_pending_acks().expect("reload").is_empty());
        }
    }

    #[test]
    fn new_database_file_is_owner_only() {
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let path = dir.path().join("state/client.db");
        ClientStore::open(&path).expect("store should open");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("db metadata should be readable")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
