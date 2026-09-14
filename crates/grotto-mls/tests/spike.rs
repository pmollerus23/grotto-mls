//! Phase 0 spike tests — mls-rs only.
//!
//! Success criteria:
//! 1. two-party join + app message round-trip works
//! 2. SQLite persistence round-trips via write_to_storage/load_group
//! 3. SQLCipher wrong passphrase fails instead of returning plaintext
//! 4. commit-conflict behavior is recorded (pending-commit errors)
//! 5. wire sizes fit the existing 1 MiB frame cap
//! 6. everything runs inside spawn_blocking (Tokio-safe, sync API)

use grotto_mls::{from_wire, new_encrypted_file_client, new_memory_client, to_wire};
use mls_rs::{ExtensionList, group::ReceivedMessage};

fn ext() -> (ExtensionList, ExtensionList) {
    (ExtensionList::default(), ExtensionList::default())
}

#[test]
fn two_party_join_and_app_msg() {
    let alice = new_memory_client("alice").expect("alice client");
    let bob = new_memory_client("bob").expect("bob client");

    let mut alice_group = alice
        .create_group(ext().0, ext().1, None)
        .expect("alice creates group");
    let bob_kp = bob
        .generate_key_package_message(ext().0, ext().1, None)
        .expect("bob key package");

    let commit = alice_group
        .commit_builder()
        .add_member(bob_kp)
        .expect("add builder")
        .build()
        .expect("build add commit");
    assert!(
        !commit.welcome_messages.is_empty(),
        "add commit must produce a welcome"
    );

    // Wire round-trip through our postcard-frame serialization helpers.
    let welcome_bytes = to_wire(&commit.welcome_messages[0]).expect("serialize welcome");
    let commit_bytes = to_wire(&commit.commit_message).expect("serialize commit");

    alice_group.apply_pending_commit().expect("alice applies");
    alice_group.write_to_storage().expect("alice persists");

    let (mut bob_group, _) = bob
        .join_group(
            None,
            &from_wire(&welcome_bytes).expect("parse welcome"),
            None,
        )
        .expect("bob joins");
    bob_group.write_to_storage().expect("bob persists");

    // Epochs must agree after join.
    assert_eq!(alice_group.current_epoch(), bob_group.current_epoch());

    // Application message alice -> bob.
    let ct = alice_group
        .encrypt_application_message(b"hello grotto", vec![])
        .expect("encrypt");
    let ct_bytes = to_wire(&ct).expect("serialize app msg");
    match bob_group
        .process_incoming_message(from_wire(&ct_bytes).expect("parse app msg"))
        .expect("bob decrypts")
    {
        ReceivedMessage::ApplicationMessage(d) => assert_eq!(d.data(), b"hello grotto"),
        other => panic!("expected application message, got {other:?}"),
    }
    bob_group
        .write_to_storage()
        .expect("bob persists after recv");

    // And back bob -> alice.
    let ct = bob_group
        .encrypt_application_message(b"hi alice", vec![])
        .expect("encrypt");
    match alice_group
        .process_incoming_message(ct)
        .expect("alice decrypts")
    {
        ReceivedMessage::ApplicationMessage(d) => assert_eq!(d.data(), b"hi alice"),
        other => panic!("expected application message, got {other:?}"),
    }

    // Sanity: the commit message parses as a commit on a third party is N/A
    // here, but at least the bytes are non-empty and framed.
    assert!(!commit_bytes.is_empty());
}

#[test]
fn sqlite_persistence_roundtrip() {
    let alice = new_memory_client("alice").expect("alice client");
    let bob = new_memory_client("bob").expect("bob client");

    let mut alice_group = alice.create_group(ext().0, ext().1, None).expect("create");
    let bob_kp = bob
        .generate_key_package_message(ext().0, ext().1, None)
        .expect("kp");
    let commit = alice_group
        .commit_builder()
        .add_member(bob_kp)
        .expect("builder")
        .build()
        .expect("commit");
    alice_group.apply_pending_commit().expect("apply");
    let gid = alice_group.group_id().to_vec();
    alice_group.write_to_storage().expect("persist");

    // Drop the group object, reload from SQLite via the same client.
    drop(alice_group);
    let mut reloaded = alice.load_group(&gid).expect("load_group after drop");
    assert_eq!(reloaded.group_id(), gid.as_slice());

    // Reloaded group can still encrypt (proves secret material survived).
    let (mut bob_group, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .expect("bob joins");
    let ct = reloaded
        .encrypt_application_message(b"after reload", vec![])
        .expect("encrypt after reload");
    match bob_group.process_incoming_message(ct).expect("decrypt") {
        ReceivedMessage::ApplicationMessage(d) => assert_eq!(d.data(), b"after reload"),
        other => panic!("expected app msg, got {other:?}"),
    }
}

#[test]
fn sqlcipher_wrong_passphrase_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("spike.db");

    // Create with the correct passphrase and force a write.
    {
        let client =
            new_encrypted_file_client("alice", &db, "correct-horse").expect("create client");
        client
            .generate_key_package_message(ext().0, ext().1, None)
            .expect("write kp");
    }

    // Reopen with a wrong passphrase: construction or the first
    // storage-backed op must fail (SQLCipher "file is not a database")
    // rather than return plaintext.
    {
        match new_encrypted_file_client("alice", &db, "wrong-passphrase") {
            Err(e) => {
                eprintln!("wrong passphrase rejected at open: {e}");
            }
            Ok(client) => {
                let res = client.generate_key_package_message(ext().0, ext().1, None);
                assert!(
                    res.is_err(),
                    "wrong passphrase must fail, got success (plaintext leak?)"
                );
            }
        }
    }

    // Correct passphrase still works.
    {
        let client = new_encrypted_file_client("alice", &db, "correct-horse").expect("reopen");
        client
            .generate_key_package_message(ext().0, ext().1, None)
            .expect("correct passphrase works");
    }
}

#[test]
fn commit_conflict_records_pending_behavior() {
    let alice = new_memory_client("alice").expect("alice");
    let bob = new_memory_client("bob").expect("bob");

    let mut alice_group = alice.create_group(ext().0, ext().1, None).expect("create");
    let bob_kp = bob
        .generate_key_package_message(ext().0, ext().1, None)
        .expect("kp");
    let commit = alice_group
        .commit_builder()
        .add_member(bob_kp)
        .expect("builder")
        .build()
        .expect("commit");
    alice_group.apply_pending_commit().expect("apply");
    let (mut bob_group, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .expect("join");

    // Both sides now create independent commits from the same epoch.
    let _alice_pending = alice_group
        .commit(b"alice change".to_vec())
        .expect("alice pending commit");
    assert!(
        alice_group.has_pending_commit(),
        "alice should hold a pending commit"
    );

    // Second commit while one is pending must be rejected (documents the
    // DS-linearization requirement: server accepts exactly one).
    let second = alice_group.commit(b"alice second".to_vec());
    assert!(
        second.is_err(),
        "second commit while pending must fail, got success"
    );
    eprintln!(
        "second-commit-while-pending error: {:?}",
        second.unwrap_err()
    );

    // Bob commits concurrently from the same epoch.
    let bob_commit = bob_group
        .commit(b"bob change".to_vec())
        .expect("bob pending commit");
    let bob_bytes = bob_commit.commit_message.to_bytes().expect("serialize");

    // Alice processes Bob's competing commit while holding her own pending:
    // mls-rs auto-clears the local pending (fork resolution by DS order).
    let event = alice_group
        .process_incoming_message(mls_rs::MlsMessage::from_bytes(&bob_bytes).expect("parse"))
        .expect("process competing commit");
    assert!(
        matches!(event, ReceivedMessage::Commit(_)),
        "expected commit event, got {event:?}"
    );
    assert!(
        !alice_group.has_pending_commit(),
        "loser's pending must be cleared after processing winner"
    );
    eprintln!("conflict behavior recorded: loser pending auto-cleared, retry required");
}

#[test]
fn wire_sizes_fit_frame_cap() {
    const MAX_FRAME: usize = 1024 * 1024; // grotto-protocol MAX_FRAME_SIZE
    const MAX_BODY: usize = 64 * 1024; // grotto-protocol MAX_MESSAGE_BODY_BYTES

    let alice = new_memory_client("alice").expect("alice");
    let bob = new_memory_client("bob").expect("bob");

    let mut alice_group = alice.create_group(ext().0, ext().1, None).expect("create");
    let bob_kp = bob
        .generate_key_package_message(ext().0, ext().1, None)
        .expect("kp");
    let kp_bytes = bob_kp.to_bytes().expect("kp bytes");
    let commit = alice_group
        .commit_builder()
        .add_member(bob_kp)
        .expect("builder")
        .build()
        .expect("commit");
    let commit_bytes = commit.commit_message.to_bytes().expect("commit bytes");
    let welcome_bytes = commit.welcome_messages[0]
        .to_bytes()
        .expect("welcome bytes");
    alice_group.apply_pending_commit().expect("apply");
    let (mut bob_group, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .expect("join");

    let small = alice_group
        .encrypt_application_message(b"hi", vec![])
        .expect("encrypt small")
        .to_bytes()
        .expect("bytes");
    let large_plaintext = vec![0x41_u8; MAX_BODY];
    let large = alice_group
        .encrypt_application_message(&large_plaintext, vec![])
        .expect("encrypt 64KiB")
        .to_bytes()
        .expect("bytes");

    eprintln!("=== mls-rs wire sizes (2 members, CURVE25519_AES128) ===");
    eprintln!("key_package : {} bytes", kp_bytes.len());
    eprintln!("commit      : {} bytes", commit_bytes.len());
    eprintln!("welcome     : {} bytes", welcome_bytes.len());
    eprintln!("app(small)  : {} bytes", small.len());
    eprintln!("app(64KiB)  : {} bytes", large.len());

    for (name, len) in [
        ("key_package", kp_bytes.len()),
        ("commit", commit_bytes.len()),
        ("welcome", welcome_bytes.len()),
        ("app(small)", small.len()),
        ("app(64KiB)", large.len()),
    ] {
        assert!(len < MAX_FRAME, "{name} ({len}B) exceeds 1MiB frame cap");
    }

    // Bob can decrypt the large message (ordering preserved for same sender).
    match bob_group
        .process_incoming_message(mls_rs::MlsMessage::from_bytes(&large).expect("parse"))
        .expect("decrypt large")
    {
        ReceivedMessage::ApplicationMessage(d) => assert_eq!(d.data(), large_plaintext),
        other => panic!("expected app msg, got {other:?}"),
    }
}

#[tokio::test]
async fn runs_inside_spawn_blocking() {
    // Proves the sync mls-rs API is Tokio-safe via spawn_blocking and that
    // no SQLite handle is held across `.await` by user code.
    let out = tokio::task::spawn_blocking(|| {
        let alice = new_memory_client("alice").expect("alice");
        let bob = new_memory_client("bob").expect("bob");
        let mut alice_group = alice.create_group(ext().0, ext().1, None).expect("create");
        let bob_kp = bob
            .generate_key_package_message(ext().0, ext().1, None)
            .expect("kp");
        let commit = alice_group
            .commit_builder()
            .add_member(bob_kp)
            .expect("builder")
            .build()
            .expect("commit");
        alice_group.apply_pending_commit().expect("apply");
        let (mut bob_group, _) = bob
            .join_group(None, &commit.welcome_messages[0], None)
            .expect("join");
        let ct = alice_group
            .encrypt_application_message(b"via blocking", vec![])
            .expect("encrypt");
        match bob_group.process_incoming_message(ct).expect("decrypt") {
            ReceivedMessage::ApplicationMessage(d) => {
                assert_eq!(d.data(), b"via blocking");
            }
            other => panic!("expected app msg, got {other:?}"),
        }
        alice_group.current_epoch()
    })
    .await
    .expect("spawn_blocking join");
    assert_eq!(out, 1, "epoch after one add-commit should be 1");
}
