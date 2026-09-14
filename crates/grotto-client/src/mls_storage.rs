//! MLS provider callbacks on the application connection. Each callback holds a
//! short lock; the application owns BEGIN/COMMIT around the whole operation.
use crate::store::{ClientStore, StoreError};
use mls_rs_core::{
    error::IntoAnyError,
    group::{EpochRecord, GroupState, GroupStateStorage},
    key_package::{KeyPackageData, KeyPackageStorage},
};
use rusqlite::{OptionalExtension, params};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct MlsStorage(pub Arc<ClientStore>);

impl IntoAnyError for StoreError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

fn require_transaction(connection: &rusqlite::Connection) -> Result<(), StoreError> {
    if connection.is_autocommit() {
        Err(StoreError::InvalidData(
            "MLS write requires an application transaction",
        ))
    } else {
        Ok(())
    }
}

impl GroupStateStorage for MlsStorage {
    type Error = StoreError;
    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let bytes: Option<Vec<u8>> = self
            .0
            .lock_provider()?
            .query_row(
                "SELECT state FROM mls_groups WHERE group_id=?1",
                [group_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(bytes.map(Zeroizing::new))
    }
    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let bytes: Option<Vec<u8>> = self
            .0
            .lock_provider()?
            .query_row(
                "SELECT state FROM mls_epochs WHERE group_id=?1 AND epoch=?2",
                params![group_id, epoch_id.to_be_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(bytes.map(Zeroizing::new))
    }
    fn write(
        &mut self,
        state: GroupState,
        inserts: Vec<EpochRecord>,
        updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let connection = self.0.lock_provider()?;
        require_transaction(&connection)?;
        connection.execute("INSERT INTO mls_groups VALUES(?1,?2) ON CONFLICT(group_id) DO UPDATE SET state=excluded.state", params![state.id, state.data.as_slice()])?;
        for record in inserts.into_iter().chain(updates) {
            connection.execute("INSERT INTO mls_epochs VALUES(?1,?2,?3) ON CONFLICT(group_id,epoch) DO UPDATE SET state=excluded.state", params![state.id, record.id.to_be_bytes().as_slice(), record.data.as_slice()])?;
        }
        Ok(())
    }
    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let bytes: Option<Vec<u8>> = self.0.lock_provider()?.query_row(
            "SELECT MAX(epoch) FROM mls_epochs WHERE group_id=?1",
            [group_id],
            |row| row.get(0),
        )?;
        bytes
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| StoreError::InvalidData("invalid retained epoch"))
            })
            .transpose()
    }
}

impl KeyPackageStorage for MlsStorage {
    type Error = StoreError;
    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        let connection = self.0.lock_provider()?;
        require_transaction(&connection)?;
        connection.execute("DELETE FROM mls_packages WHERE id=?1", [id])?;
        Ok(())
    }
    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        let connection = self.0.lock_provider()?;
        require_transaction(&connection)?;
        connection.execute(
            "INSERT INTO mls_packages VALUES(?1,?2,?3,?4,?5)",
            params![
                id,
                pkg.key_package_bytes,
                pkg.init_key.as_ref(),
                pkg.leaf_node_key.as_ref(),
                pkg.expiration.to_be_bytes().as_slice()
            ],
        )?;
        Ok(())
    }
    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        type Row = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
        let row: Option<Row> = self
            .0
            .lock_provider()?
            .query_row(
                "SELECT package, init_key, leaf_key, expiration FROM mls_packages WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(package, init, leaf, expiration)| {
            let expiration = u64::from_be_bytes(
                expiration
                    .try_into()
                    .map_err(|_| StoreError::InvalidData("invalid package expiration"))?,
            );
            Ok(KeyPackageData::new(
                package,
                init.into(),
                leaf.into(),
                expiration,
            ))
        })
        .transpose()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        contacts::{ContactCard, VerifiedIdentityProvider},
        mls_session::{MlsSession, Processed},
    };
    use grotto_mls::{MlsKeyMaterial, generate_key_material, new_client_with_providers};
    use grotto_protocol::{MessageId, MlsContentType, RoomId, StoredRoomMessage};

    pub(crate) fn store(dir: &std::path::Path, name: &str) -> Arc<ClientStore> {
        let store = Arc::new(ClientStore::open(&dir.join(name).join("client.db")).unwrap());
        store.identity().unwrap();
        let keys = generate_key_material().unwrap();
        store.save_mls_identity(&keys.public, &keys.secret).unwrap();
        pin(&store, &store);
        store
    }
    pub(crate) fn pin(target: &ClientStore, owner: &ClientStore) {
        let card = ContactCard::own(owner).unwrap();
        card.import(target, &card.fingerprint()).unwrap();
    }
    pub(crate) fn session(
        store: &Arc<ClientStore>,
    ) -> MlsSession<impl mls_rs::client_builder::MlsConfig + use<>> {
        let (public, secret) = store.load_mls_identity().unwrap().unwrap();
        let identity = store.identity().unwrap();
        let provider = MlsStorage(store.clone());
        MlsSession::new(new_client_with_providers(
            &identity.user_id().to_bytes(),
            MlsKeyMaterial { public, secret },
            provider.clone(),
            provider,
            VerifiedIdentityProvider(store.clone()),
        ))
    }
    fn count(store: &ClientStore, table: &str) -> i64 {
        store
            .lock()
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn receive_test_message<C: mls_rs::client_builder::MlsConfig>(
        message: &StoredRoomMessage,
        mls: &mut MlsSession<C>,
        store: &ClientStore,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if store.is_settled(message.message_id)? {
            return Ok(());
        }
        store.store_message(message)?;
        let applied = mls.atomic(store, |mls| {
            let crate::mls_session::Processed::Application { plaintext, author } =
                mls.process(message.room_id, &message.body)?
            else {
                return Err("expected application".into());
            };
            store.record_plaintext(
                message,
                grotto_protocol::UserId::from_bytes(author.try_into().map_err(|_| "bad sender")?),
                &plaintext,
            )?;
            store.set_processing(message.message_id, "applied")?;
            store.record_pending_acks(&[(message.message_id, message.room_id)])?;
            Ok(())
        });
        if applied.is_err() {
            store.set_processing(message.message_id, "blocked")?;
        }
        Ok(())
    }

    #[test]
    fn rolled_back_encryption_reloads_ratchet_and_received_history_is_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let a = store(dir.path(), "alice");
        let b = store(dir.path(), "bob");
        pin(&a, &b);
        pin(&b, &a);
        let mut alice = session(&a);
        let mut bob = session(&b);
        let room = RoomId::from_bytes([61; 16]);
        alice.atomic(&a, |mls| mls.create_group(room)).unwrap();
        let kp = bob.atomic(&b, |mls| mls.generate_key_packages(1)).unwrap();
        let (_, _, welcome) = alice.atomic(&a, |mls| mls.build_add(room, &kp[0])).unwrap();
        bob.atomic(&b, |mls| mls.join(room, &welcome)).unwrap();
        a.lock().unwrap().execute_batch("CREATE TEMP TRIGGER fail_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(
            alice
                .atomic(&a, |mls| {
                    let (_, blob) = mls.encrypt_app(room, b"must roll back")?;
                    a.save_outbox(MessageId::from_bytes([2; 16]), "send", &blob)?;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(count(&a, "outbox"), 0);
        a.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_outbox")
            .unwrap();
        let (epoch, blob) = alice
            .atomic(&a, |mls| {
                let encrypted = mls.encrypt_app(room, b"survives rollback")?;
                a.save_outbox(MessageId::from_bytes([3; 16]), "send", &encrypted.1)?;
                Ok(encrypted)
            })
            .unwrap();
        let message = StoredRoomMessage {
            message_id: MessageId::from_bytes([3; 16]),
            room_id: room,
            sequence: 1,
            sender_id: a.identity().unwrap().user_id(),
            epoch,
            content_type: MlsContentType::Application,
            body: blob.clone(),
        };
        b.lock().unwrap().execute_batch("CREATE TEMP TRIGGER fail_history BEFORE INSERT ON authenticated_history BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        receive_test_message(&message, &mut bob, &b).unwrap();
        assert!(!b.is_settled(message.message_id).unwrap());
        assert_eq!(count(&b, "authenticated_history"), 0);
        assert_eq!(count(&b, "pending_acks"), 0);
        b.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_history")
            .unwrap();
        receive_test_message(&message, &mut bob, &b).unwrap();
        assert!(b.is_settled(message.message_id).unwrap());
        let snapshot = MlsStorage(b.clone()).state(&room.to_bytes()).unwrap();
        let history = b.history(room, None).unwrap();
        assert_eq!(history[0].plaintext, b"survives rollback");
        assert_eq!(history[0].author, a.identity().unwrap().user_id());
        for _ in 0..3 {
            receive_test_message(&message, &mut bob, &b).unwrap();
            assert_eq!(b.history(room, None).unwrap(), history);
            assert_eq!(
                MlsStorage(b.clone()).state(&room.to_bytes()).unwrap(),
                snapshot
            );
        }
        drop(bob);
        drop(b);
        let b = Arc::new(ClientStore::open(&dir.path().join("bob/client.db")).unwrap());
        assert_eq!(b.history(room, None).unwrap(), history);
        assert_eq!(
            MlsStorage(b.clone()).state(&room.to_bytes()).unwrap(),
            snapshot
        );
        let mut bob = session(&b);
        let (_, next) = alice
            .atomic(&a, |mls| mls.encrypt_app(room, b"next generation"))
            .unwrap();
        assert!(
            matches!(bob.atomic(&b, |mls| mls.process(room, &next)).unwrap(), Processed::Application { plaintext, .. } if plaintext == b"next generation")
        );
        assert_eq!(a.load_outbox().unwrap()[0].message, blob);
    }

    #[test]
    fn unknown_welcome_member_blocks_without_consuming_private_package() {
        let dir = tempfile::tempdir().unwrap();
        let a = store(dir.path(), "alice");
        let b = store(dir.path(), "bob");
        let c = store(dir.path(), "carol");
        pin(&a, &b);
        pin(&a, &c);
        pin(&b, &a);
        let mut alice = session(&a);
        let mut bob = session(&b);
        let mut carol = session(&c);
        let room = RoomId::from_bytes([62; 16]);
        alice.atomic(&a, |mls| mls.create_group(room)).unwrap();
        let ckp = carol
            .atomic(&c, |mls| mls.generate_key_packages(1))
            .unwrap();
        alice
            .atomic(&a, |mls| mls.build_add(room, &ckp[0]))
            .unwrap();
        let bkp = bob.atomic(&b, |mls| mls.generate_key_packages(1)).unwrap();
        let (_, _, welcome) = alice
            .atomic(&a, |mls| mls.build_add(room, &bkp[0]))
            .unwrap();
        assert!(bob.atomic(&b, |mls| mls.join(room, &welcome)).is_err());
        assert_eq!(count(&b, "mls_packages"), 1);
        assert_eq!(count(&b, "mls_groups"), 0);
        pin(&b, &c);
        bob.atomic(&b, |mls| mls.join(room, &welcome)).unwrap();
        assert_eq!(count(&b, "mls_packages"), 0);
        assert_eq!(count(&b, "mls_groups"), 1);
    }

    #[test]
    fn crash_child() {
        let Some(path) = std::env::var_os("GROTTO_TEST_CRASH_DATABASE") else {
            return;
        };
        let store = Arc::new(ClientStore::open(std::path::Path::new(&path)).unwrap());
        let mut mls = session(&store);
        let room = RoomId::from_bytes([63; 16]);
        mls.atomic(&store, |mls| {
            let (_, bytes) = mls.encrypt_app(room, b"durable crash attempt")?;
            store.save_outbox(MessageId::from_bytes([81; 16]), "crash-test", &bytes)?;
            if std::env::var("GROTTO_TEST_CRASH_POINT").unwrap() == "before-commit" {
                std::process::exit(77);
            }
            Ok(())
        })
        .unwrap();
        std::process::exit(77);
    }

    #[test]
    fn process_crashes_before_and_after_commit_preserve_ratchets_and_exact_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let a = store(dir.path(), "alice");
        let b = store(dir.path(), "bob");
        pin(&a, &b);
        pin(&b, &a);
        let mut alice = session(&a);
        let mut bob = session(&b);
        let room = RoomId::from_bytes([63; 16]);
        alice.atomic(&a, |mls| mls.create_group(room)).unwrap();
        let kp = bob.atomic(&b, |mls| mls.generate_key_packages(1)).unwrap();
        let (_, _, welcome) = alice.atomic(&a, |mls| mls.build_add(room, &kp[0])).unwrap();
        bob.atomic(&b, |mls| mls.join(room, &welcome)).unwrap();
        drop(alice);
        drop(a);
        let path = dir.path().join("alice/client.db");
        for point in ["before-commit", "after-commit"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "mls_storage::tests::crash_child"])
                .env("GROTTO_TEST_CRASH_DATABASE", &path)
                .env("GROTTO_TEST_CRASH_POINT", point)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(77));
            let a = Arc::new(ClientStore::open(&path).unwrap());
            let mut alice = session(&a);
            let attempts = a.load_outbox().unwrap();
            if point == "before-commit" {
                assert!(attempts.is_empty());
                let (_, bytes) = alice
                    .atomic(&a, |mls| mls.encrypt_app(room, b"after rollback"))
                    .unwrap();
                assert!(
                    matches!(bob.atomic(&b, |mls| mls.process(room,&bytes)).unwrap(), Processed::Application { plaintext, .. } if plaintext == b"after rollback")
                );
            } else {
                assert_eq!(attempts.len(), 1);
                assert_eq!(attempts[0].message, a.load_outbox().unwrap()[0].message);
                assert!(
                    matches!(bob.atomic(&b, |mls| mls.process(room,&attempts[0].message)).unwrap(), Processed::Application { plaintext, .. } if plaintext == b"durable crash attempt")
                );
            }
        }
    }

    #[test]
    fn key_package_generation_and_publication_roll_back_together() {
        let dir = tempfile::tempdir().unwrap();
        let a = store(dir.path(), "alice");
        let mut alice = session(&a);
        assert!(
            alice
                .atomic(
                    &a,
                    |mls| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                        mls.generate_key_packages(3)?;
                        Err("injected interruption before journal".into())
                    }
                )
                .is_err()
        );
        assert_eq!(count(&a, "mls_packages"), 0);
    }
}
