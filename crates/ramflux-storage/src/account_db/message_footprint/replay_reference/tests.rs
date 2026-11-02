// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Replay-reference deletion, ambiguity and validation at the indexed storage boundary.
use crate::{AccountDb, AccountDbKey, AccountIndex, MessageReplayReference, StorageError};

#[test]
fn replay_reference_tracks_real_deletion_and_late_writes_across_restart() -> Result<(), StorageError>
{
    let (root, db) = crate::tests::test_db("replay-reference-delete")?;
    db.send_direct_message("thread", "message", "sender", b"private body")?;
    let digest = db.own_sent_index_digest("alias", "private-source-envelope")?;
    let key = format!("own-device/sent-alias/{digest}");
    db.persist_message_replay_reference(&key, Some("message"), Some(&digest), Some(&digest))?;
    let reference = |deleted| MessageReplayReference::Target {
        message_id: "message".into(),
        deleted,
        binding: Some(digest.clone()),
        scope: Some(digest.clone()),
    };
    assert_eq!(db.load_actor_state::<MessageReplayReference>(&key)?, Some(reference(false)));
    db.persist_message_actor_state("message", "own-device/send/private", &"private body")?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    assert_eq!(db.load_actor_state::<MessageReplayReference>(&key)?, Some(reference(true)));
    assert!(!db.actor_state_exists("own-device/send/private")?);
    db.persist_message_replay_reference(&key, Some("message"), Some(&digest), Some(&digest))?;
    assert_eq!(db.load_actor_state::<MessageReplayReference>(&key)?, Some(reference(true)));
    drop(db);
    let db = AccountDb::open(
        &AccountIndex::open(&root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    assert_eq!(db.load_actor_state::<MessageReplayReference>(&key)?, Some(reference(true)));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn replay_reference_ambiguity_detaches_the_old_target() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("replay-reference-ambiguity")?;
    db.send_direct_message("thread", "old", "sender", b"old body")?;
    db.send_direct_message("thread", "new", "sender", b"new body")?;
    let digest = db.own_sent_index_digest("ciphertext", "same-ciphertext")?;
    let key = format!("own-device/sent-ciphertext/{digest}");
    db.persist_message_replay_reference(&key, Some("old"), Some(&digest), None)?;
    db.persist_message_replay_reference(&key, None, None, None)?;
    db.delete_direct_message("thread", "old", "local", "delete-old")?;
    assert_eq!(
        db.load_actor_state::<MessageReplayReference>(&key)?,
        Some(MessageReplayReference::Ambiguous)
    );
    db.persist_message_replay_reference(&key, Some("new"), Some(&digest), None)?;
    // Late writes re-run erasure on the already deleted projection without deleting it twice.
    db.connection
        .execute("UPDATE direct_message_projection SET deleted=1 WHERE message_id='old'", [])?;
    assert!(matches!(
        db.load_actor_state::<MessageReplayReference>(&key)?,
        Some(MessageReplayReference::Target { deleted: false, .. })
    ));
    db.delete_direct_message("thread", "new", "local", "delete-new")?;
    assert!(matches!(
        db.load_actor_state::<MessageReplayReference>(&key)?,
        Some(MessageReplayReference::Target { deleted: true, .. })
    ));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn replay_reference_rejects_raw_keys_missing_targets_and_malformed_bindings()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("replay-reference-validation")?;
    db.send_direct_message("thread", "message", "sender", b"body")?;
    let digest = db.own_sent_index_digest("alias", "private-source-envelope")?;
    let key = format!("own-device/sent-alias/{digest}");
    for (key, message, binding) in [
        ("unrelated/key", Some("message"), None),
        ("own-device/sent-alias/raw-envelope", Some("message"), None),
        (key.as_str(), Some("missing"), None),
        (key.as_str(), Some("message"), Some("raw-source")),
        (key.as_str(), None, Some(digest.as_str())),
    ] {
        assert!(db.persist_message_replay_reference(key, message, binding, None).is_err());
        assert!(!db.actor_state_exists(key)?);
    }
    db.persist_actor_state("own-device/unrelated", &"ordinary state")?;
    assert_eq!(
        db.load_actor_state::<String>("own-device/unrelated")?.as_deref(),
        Some("ordinary state")
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
