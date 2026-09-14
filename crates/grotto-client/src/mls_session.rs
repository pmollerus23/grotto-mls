//! MLS group state owned by the serialized client service thread.
//!
//! One MLS group maps 1:1 onto one relay room namespace: the MLS
//! `GroupId` is the 16 room-ID bytes. Production storage uses the unified
//! application connection; every mutation is followed by `write_to_storage`.
//! `atomic` commits MLS changes with application records, or clears in-memory
//! groups so subsequent operations reload rolled-back state.
//!
//! Production commits remain pending until their exact accepted event is processed
//! at the durable room cursor. Losing attempts are discarded only after a durable
//! conflict result, then rebuilt from their original intent.

use std::collections::HashMap;

use grotto_mls::{default_extensions, from_wire, to_wire};
use grotto_protocol::RoomId;
use mls_rs::{
    Client, IdentityProvider,
    client_builder::MlsConfig,
    error::MlsError,
    group::{Group, ReceivedMessage},
};

pub struct MlsSession<C: MlsConfig> {
    client: Client<C>,
    groups: HashMap<RoomId, Group<C>>,
}

pub enum Processed {
    Application { plaintext: Vec<u8>, author: Vec<u8> },
    Commit { epoch: u64 },
    Proposal { epoch: u64 },
    Ignored,
}

#[derive(Debug)]
pub enum ProcessingFault {
    Blocked,
    Rejected,
}
impl std::fmt::Display for ProcessingFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProcessingFault {}

type SessionError = Box<dyn std::error::Error + Send + Sync>;

fn mls_error(error: MlsError) -> SessionError {
    format!("MLS error: {error:?}").into()
}

impl<C: MlsConfig> MlsSession<C> {
    pub fn atomic<T>(
        &mut self,
        store: &crate::store::ClientStore,
        operation: impl FnOnce(&mut Self) -> Result<T, SessionError>,
    ) -> Result<T, SessionError> {
        let transaction = store.transaction()?;
        match operation(self).and_then(|value| {
            transaction.commit()?;
            Ok(value)
        }) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.groups.clear();
                Err(error)
            }
        }
    }

    pub fn new(client: Client<C>) -> Self {
        Self {
            client,
            groups: HashMap::new(),
        }
    }

    fn group_mut(&mut self, room: RoomId) -> Result<&mut Group<C>, SessionError> {
        if !self.groups.contains_key(&room) {
            // Every mutation is already durable; cap cached groups independently of room count.
            if self.groups.len() >= 8 {
                self.groups.clear();
            }
            let group = self
                .client
                .load_group(&room.to_bytes())
                .map_err(|_| format!("no local MLS group for room {room}"))?;
            for identity in group.roster().member_identities_iter() {
                self.client
                    .identity_provider()
                    .identity(identity, &mls_rs::ExtensionList::default())
                    .map_err(|_| "stored group contains an unverified or changed member")?;
            }
            self.groups.insert(room, group);
        }
        self.groups
            .get_mut(&room)
            .ok_or_else(|| "MLS group vanished".into())
    }

    pub fn has_group(&mut self, room: RoomId) -> bool {
        self.group_mut(room).is_ok()
    }

    /// Create the local group, or return the existing epoch on replay.
    pub fn create_group(&mut self, room: RoomId) -> Result<u64, SessionError> {
        if let Ok(group) = self.group_mut(room) {
            return Ok(group.current_epoch());
        }
        let (group_context, leaf_node) = default_extensions();
        let group = self
            .client
            .create_group_with_id(room.to_bytes().to_vec(), group_context, leaf_node, None)
            .map_err(mls_error)?;
        let epoch = group.current_epoch();
        self.groups.insert(room, group);
        self.persist(room)?;
        Ok(epoch)
    }

    pub fn contains_user(
        &mut self,
        room: RoomId,
        user: grotto_protocol::UserId,
    ) -> Result<bool, SessionError> {
        Ok(self
            .group_mut(room)?
            .roster()
            .member_identities_iter()
            .any(|identity| {
                identity
                    .credential
                    .as_basic()
                    .is_some_and(|credential| credential.identifier == user.to_bytes())
            }))
    }

    pub fn current_epoch(&mut self, room: RoomId) -> Result<u64, SessionError> {
        Ok(self.group_mut(room)?.current_epoch())
    }

    #[cfg(test)]
    pub fn encrypt_app(
        &mut self,
        room: RoomId,
        plaintext: &[u8],
    ) -> Result<(u64, Vec<u8>), SessionError> {
        // The sender ratchet advances on every encryption and must persist:
        // otherwise a restart reuses a generation the recipient already
        // consumed, and the message becomes undecryptable.
        let (epoch, bytes) = {
            let group = self.group_mut(room)?;
            let epoch = group.current_epoch();
            let message = group
                .encrypt_application_message(plaintext, vec![])
                .map_err(mls_error)?;
            (epoch, to_wire(&message)?)
        };
        self.persist(room)?;
        Ok((epoch, bytes))
    }

    /// Build an add-commit, apply it locally immediately, and persist.
    #[cfg(test)]
    pub fn build_add(
        &mut self,
        room: RoomId,
        key_package: &[u8],
    ) -> Result<(u64, Vec<u8>, Vec<u8>), SessionError> {
        let key_package = from_wire(key_package)?;
        let group = self.group_mut(room)?;
        let commit = group
            .commit_builder()
            .add_member(key_package)
            .map_err(mls_error)?
            .build()
            .map_err(mls_error)?;
        let commit_bytes = to_wire(&commit.commit_message)?;
        let welcome = commit
            .welcome_messages
            .first()
            .ok_or("add commit produced no welcome")?;
        let welcome_bytes = to_wire(welcome)?;
        group.apply_pending_commit().map_err(mls_error)?;
        drop(commit);
        let epoch = group.current_epoch();
        self.persist(room)?;
        Ok((epoch, commit_bytes, welcome_bytes))
    }

    /// Settle an acknowledged commit. Missing pending work means the commit
    /// was already applied (e.g. replay after a crash): success.
    #[cfg(test)]
    pub fn settle_commit(&mut self, room: RoomId) -> Result<(), SessionError> {
        let group = self.group_mut(room)?;
        match group.apply_pending_commit() {
            Ok(_) => {}
            Err(MlsError::PendingCommitNotFound) => {}
            Err(error) => return Err(mls_error(error)),
        }
        self.persist(room)
    }

    pub fn encrypt_bound(
        &mut self,
        room: RoomId,
        plaintext: &[u8],
        aad: Vec<u8>,
    ) -> Result<(u64, Vec<u8>), SessionError> {
        let group = self.group_mut(room)?;
        if group.has_pending_commit() {
            return Err("room has an unresolved commit".into());
        }
        let epoch = group.current_epoch();
        let message = group
            .encrypt_application_message(plaintext, aad)
            .map_err(mls_error)?;
        let bytes = to_wire(&message)?;
        self.persist(room)?;
        Ok((epoch, bytes))
    }

    pub fn build_pending_add(
        &mut self,
        room: RoomId,
        package: &[u8],
        aad: Vec<u8>,
    ) -> Result<(u64, Vec<u8>, Vec<u8>), SessionError> {
        let package = from_wire(package)?;
        let group = self.group_mut(room)?;
        if group.has_pending_commit() {
            return Err("room has an unresolved commit".into());
        }
        let epoch = group.current_epoch();
        let commit = group
            .commit_builder()
            .authenticated_data(aad)
            .add_member(package)
            .map_err(mls_error)?
            .build()
            .map_err(mls_error)?;
        let body = to_wire(&commit.commit_message)?;
        let welcome = to_wire(commit.welcome_messages.first().ok_or("missing Welcome")?)?;
        drop(commit);
        self.persist(room)?;
        Ok((epoch, body, welcome))
    }

    pub fn discard_pending(&mut self, room: RoomId) -> Result<(), SessionError> {
        self.group_mut(room)?.clear_pending_commit();
        self.persist(room)
    }

    pub fn apply_accepted_commit(&mut self, room: RoomId) -> Result<(), SessionError> {
        self.group_mut(room)?
            .apply_pending_commit()
            .map_err(mls_error)?;
        self.persist(room)
    }

    pub fn process_bound(
        &mut self,
        event: &grotto_protocol::delivery::Event,
    ) -> Result<Processed, SessionError> {
        use grotto_protocol::{MlsContentType, delivery::event_authenticated_data};
        let room = event.operation.room;
        let incoming = from_wire(&event.operation.body).map_err(|_| ProcessingFault::Rejected)?;
        if incoming.epoch() != Some(event.operation.epoch) {
            return Err(ProcessingFault::Rejected.into());
        }
        let provider = self.client.identity_provider();
        let group = self.group_mut(room)?;
        if incoming.epoch() != Some(group.current_epoch()) {
            return Err(if incoming
                .epoch()
                .is_some_and(|epoch| epoch > group.current_epoch())
            {
                ProcessingFault::Blocked
            } else {
                ProcessingFault::Rejected
            }
            .into());
        }
        let identities: HashMap<_, _> = group
            .roster()
            .members_iter()
            .map(|member| (member.index, member.signing_identity))
            .collect();
        let processed =
            group
                .process_incoming_message(incoming)
                .map_err(|error| -> SessionError {
                    match error {
                        MlsError::IdentityProviderError(_) => ProcessingFault::Blocked.into(),
                        MlsError::GroupStorageError(_) => mls_error(error),
                        _ => ProcessingFault::Rejected.into(),
                    }
                })?;
        let expected = event_authenticated_data(room, event.id, event.operation.parent);
        let (sender, aad, mut outcome) = match processed {
            ReceivedMessage::ApplicationMessage(description)
                if event.operation.content_type == MlsContentType::Application =>
            {
                (
                    description.sender_index,
                    description.authenticated_data.clone(),
                    Processed::Application {
                        plaintext: description.data().to_vec(),
                        author: event.sender.to_bytes().to_vec(),
                    },
                )
            }
            ReceivedMessage::Commit(description)
                if event.operation.content_type == MlsContentType::Commit
                    && !description.is_external =>
            {
                (
                    description.committer,
                    description.authenticated_data,
                    Processed::Commit {
                        epoch: group.current_epoch(),
                    },
                )
            }
            _ => return Err(ProcessingFault::Rejected.into()),
        };
        // Resolve against the roster before processing: commits may change indices.
        let actual = identities
            .get(&sender)
            .ok_or(ProcessingFault::Rejected)?
            .credential
            .as_basic()
            .ok_or(ProcessingFault::Rejected)?;
        if actual.identifier != event.sender.to_bytes() || aad != expected {
            return Err(ProcessingFault::Rejected.into());
        }
        if let Processed::Application { author, .. } = &mut outcome {
            *author = actual.identifier.clone();
        }
        for identity in group.roster().member_identities_iter() {
            provider
                .identity(identity, &mls_rs::ExtensionList::default())
                .map_err(|_| ProcessingFault::Blocked)?;
        }
        self.persist(room)?;
        Ok(outcome)
    }

    #[cfg(test)]
    pub fn process(&mut self, room: RoomId, bytes: &[u8]) -> Result<Processed, SessionError> {
        let incoming: mls_rs::MlsMessage = from_wire(bytes)?;
        let provider = self.client.identity_provider();
        let group = self.group_mut(room)?;
        if incoming.epoch() != Some(group.current_epoch()) {
            return Err("MLS event needs another epoch; ordered synchronization required".into());
        }
        let event = group
            .process_incoming_message(incoming)
            .map_err(mls_error)?;
        let processed = match event {
            ReceivedMessage::ApplicationMessage(description) => Processed::Application {
                plaintext: description.data().to_vec(),
                author: group
                    .member_at_index(description.sender_index)
                    .ok_or("authenticated MLS sender is not in roster")?
                    .signing_identity
                    .credential
                    .as_basic()
                    .ok_or("unsupported MLS credential")?
                    .identifier
                    .to_vec(),
            },
            ReceivedMessage::Commit(_) => Processed::Commit {
                epoch: group.current_epoch(),
            },
            ReceivedMessage::Proposal(_) => Processed::Proposal {
                epoch: group.current_epoch(),
            },
            _ => Processed::Ignored,
        };
        for identity in group.roster().member_identities_iter() {
            provider
                .identity(identity, &mls_rs::ExtensionList::default())
                .map_err(|_| "group contains an unverified or changed member")?;
        }
        self.persist(room)?;
        Ok(processed)
    }

    pub fn join(&mut self, room: RoomId, welcome_bytes: &[u8]) -> Result<u64, SessionError> {
        if self.has_group(room) {
            return self.current_epoch(room);
        }
        let welcome = from_wire(welcome_bytes)?;
        let (group, _) = self
            .client
            .join_group(None, &welcome, None)
            .map_err(mls_error)?;
        if group.group_id() != room.to_bytes().as_slice() {
            return Err("welcome is for a different group than the envelope claims".into());
        }
        for identity in group.roster().member_identities_iter() {
            self.client
                .identity_provider()
                .identity(identity, &mls_rs::ExtensionList::default())
                .map_err(|_| "welcome contains an unverified or changed member")?;
        }
        let epoch = group.current_epoch();
        self.groups.insert(room, group);
        self.persist(room)?;
        Ok(epoch)
    }

    pub fn generate_key_packages(&self, count: usize) -> Result<Vec<Vec<u8>>, SessionError> {
        let mut packages = Vec::with_capacity(count);
        for _ in 0..count {
            let (key_package_extensions, leaf_node_extensions) = default_extensions();
            let package = self
                .client
                .generate_key_package_message(key_package_extensions, leaf_node_extensions, None)
                .map_err(mls_error)?;
            packages.push(to_wire(&package)?);
        }
        Ok(packages)
    }

    fn persist(&mut self, room: RoomId) -> Result<(), SessionError> {
        self.group_mut(room)?.write_to_storage().map_err(mls_error)
    }
}

#[cfg(test)]
mod tests {
    use grotto_mls::{generate_key_material, new_memory_client_with};
    use grotto_protocol::RoomId;

    use super::{MlsSession, Processed};

    fn session(name: &[u8]) -> MlsSession<impl mls_rs::client_builder::MlsConfig> {
        let keys = generate_key_material().expect("keygen should succeed");
        let client = new_memory_client_with(name, keys).expect("client should build");
        MlsSession::new(client)
    }

    #[test]
    fn application_round_trips_between_two_sessions() {
        let mut alice = session(b"alice-user");
        let mut bob = session(b"bob-user");
        let room = RoomId::from_bytes([0x41; 16]);

        alice.create_group(room).expect("alice creates group");
        let bob_kp = bob.generate_key_packages(1).expect("bob key package");
        let (epoch, _commit, welcome) = alice.build_add(room, &bob_kp[0]).expect("alice adds bob");
        assert!(epoch >= 1);
        // Simulate the DS echo path: settle is a no-op after optimistic apply.
        alice.settle_commit(room).expect("settle succeeds");

        let bob_epoch = bob.join(room, &welcome).expect("bob joins");
        assert_eq!(bob_epoch, alice.current_epoch(room).expect("epoch"));

        let (sent_epoch, blob) = alice
            .encrypt_app(room, b"hello mls")
            .expect("alice encrypts");
        assert_eq!(sent_epoch, bob_epoch);
        match bob.process(room, &blob).expect("bob decrypts") {
            Processed::Application { plaintext, .. } => assert_eq!(plaintext, b"hello mls"),
            _ => panic!("expected application message"),
        }

        // Bob's commit advances both sides through the same process path.
        let alice_kp2 = {
            let carol = session(b"carol-user");
            carol.generate_key_packages(1).expect("carol key package")
        };
        let (_, commit2, _) = bob.build_add(room, &alice_kp2[0]).expect("bob adds carol");
        match alice
            .process(room, &commit2)
            .expect("alice processes commit")
        {
            Processed::Commit { epoch } => {
                assert_eq!(epoch, bob.current_epoch(room).expect("epoch"));
            }
            _ => panic!("expected commit"),
        }
    }

    #[test]
    fn create_group_is_idempotent_for_replays() {
        let mut alice = session(b"alice-user");
        let room = RoomId::from_bytes([0x42; 16]);
        let first = alice.create_group(room).expect("create");
        let second = alice.create_group(room).expect("replay");
        assert_eq!(first, second);
    }

    /// Restarting the sender between messages must not reuse ratchet
    /// generations: every sent message stays decryptable.
    #[test]
    fn sender_ratchet_survives_restart() {
        use grotto_mls::{generate_key_material, new_file_client_with};

        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let alice_db = dir.path().join("alice.db");
        let bob_db = dir.path().join("bob.db");
        let alice_keys = generate_key_material().expect("keygen should succeed");
        let bob_keys = generate_key_material().expect("keygen should succeed");
        let room = RoomId::from_bytes([0x43; 16]);

        {
            let alice_client = new_file_client_with(&alice_db, b"alice", alice_keys.clone())
                .expect("alice client should build");
            let mut alice = MlsSession::new(alice_client);
            let bob_client = new_file_client_with(&bob_db, b"bob", bob_keys.clone())
                .expect("bob client should build");
            let mut bob = MlsSession::new(bob_client);
            alice.create_group(room).expect("alice creates group");
            let bob_kp = bob.generate_key_packages(1).expect("bob key package");
            let (_, _, welcome) = alice.build_add(room, &bob_kp[0]).expect("alice adds bob");
            bob.join(room, &welcome).expect("bob joins");
        }

        let blob_before = {
            let alice_client = new_file_client_with(&alice_db, b"alice", alice_keys.clone())
                .expect("alice client should reopen");
            let mut alice = MlsSession::new(alice_client);
            let (_, blob) = alice.encrypt_app(room, b"before restart").expect("encrypt");
            blob
        };
        let blob_after = {
            let alice_client = new_file_client_with(&alice_db, b"alice", alice_keys.clone())
                .expect("alice client should reopen again");
            let mut alice = MlsSession::new(alice_client);
            let (_, blob) = alice.encrypt_app(room, b"after restart").expect("encrypt");
            blob
        };

        let bob_client = new_file_client_with(&bob_db, b"bob", bob_keys.clone())
            .expect("bob client should reopen");
        let mut bob = MlsSession::new(bob_client);
        match bob.process(room, &blob_before).expect("decrypt first") {
            Processed::Application { plaintext, .. } => assert_eq!(plaintext, b"before restart"),
            _ => panic!("expected application message"),
        }
        match bob.process(room, &blob_after).expect("decrypt second") {
            Processed::Application { plaintext, .. } => assert_eq!(plaintext, b"after restart"),
            _ => panic!("expected application message"),
        }
    }
}
