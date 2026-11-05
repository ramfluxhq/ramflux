// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Registered target revocations survive; binding-only legacy inputs remain omittable.
use super::*;

fn count(db: &rusqlite::Connection, sql: &str) -> rusqlite::Result<u64> {
    db.query_row(sql, [], |r| r.get(0))
}

fn legacy_shape(db: &AccountDb) -> Result<(), StorageError> {
    db.send_direct_message("thread", "message", "peer", b"body")?;
    db.persist_actor_state(
        "attachment/reference/private-canary",
        &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
    )?;
    db.persist_client_record(
        "object",
        "private-canary",
        &json!({"owner":"peer","message_id":"message","manifest_hash":"manifest"}),
    )?;
    Ok(())
}

fn restriction(db: &rusqlite::Connection) -> rusqlite::Result<(u64, u64, u64, u64)> {
    Ok((
        count(
            db,
            "SELECT count(*) FROM object_index WHERE object_id='private-canary' AND tombstoned=1",
        )?,
        count(db, "SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'")?,
        count(
            db,
            "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:private-canary'",
        )?,
        count(
            db,
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/private-canary'",
        )?,
    ))
}

// A target produced by fresh normalization retains its actor-free registered
// revocation when an older archive is merged.
#[test]
fn probe_r3_target_registered_placeholder_without_actor_survives_merge() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r3-target-noactor")?;
    legacy_shape(&db)?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    let target_path = root.join("target.db");
    let saved = db.write_backup_snapshot(&target_path)?;
    // Produce the target through the real fresh normalizer, as a restored device would.
    let mut fresh = BackupDatabase::open_restore_input(
        &target_path,
        &saved.key,
        BackupOpenMode::PreNormalization,
    )?;
    fresh.normalize_backup_candidate()?;
    drop(fresh);
    let mut target = BackupDatabase::open_restore_input(
        &target_path,
        &saved.key,
        BackupOpenMode::PreNormalization,
    )?;
    let before = restriction(&target.db)?;
    assert_eq!(before, (1, 1, 1, 0), "fresh-produced target shape");
    let result = target.merge_backup_candidate(&input, &snapshot.key, || Ok(()));
    let after = restriction(&target.db)?;
    eprintln!("target before {before:?} merge {:?} after {after:?}", result.as_ref().map(|_| ()));
    match result {
        Ok(_) => assert_eq!(after, before, "target registered tombstone lost"),
        Err(e) => return Err(e.into()),
    }
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// A binding without a restriction footprint leaves the legacy placeholder omittable.
#[test]
fn probe_r3_original_e12_unowned_fixture_shape() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r3-e12-original")?;
    register(&db, "wire", "message")?;
    payload(&db, 5)?;
    let target_path = root.join("target.db");
    let saved = db.write_backup_snapshot(&target_path)?;
    db.connection.execute("UPDATE object_index SET tombstoned=1,ciphertext=x'',chunk_count=0,manifest_hash=zeroblob(32),chunk_manifest_hash=zeroblob(32),updated_at=20 WHERE object_id='wire'",[])?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    let source = BackupDatabase::open_restore_input(
        &input,
        &snapshot.key,
        BackupOpenMode::PreNormalization,
    )?;
    source.db.execute_batch(
        "DELETE FROM object_message_reference; DELETE FROM object_retention_reference;",
    )?;
    let shape = (
        count(&source.db, "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:wire'")?,
        count(
            &source.db,
            "SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'",
        )?,
        count(
            &source.db,
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB 'attachment/reference/*'",
        )?,
    );
    drop(source);
    let mut target = BackupDatabase::open(&target_path, &saved.key)?;
    target.db.execute_batch("DELETE FROM object_message_reference; DELETE FROM object_retention_reference; DELETE FROM object_index;")?;
    let result = target.merge_backup_candidate(&input, &snapshot.key, || Ok(()));
    eprintln!(
        "original E12 shape (binding,footprint,actor)={shape:?} result={:?}",
        result.as_ref().map(|_| ())
    );
    assert_eq!(shape, (1, 0, 0));
    result?;
    assert_eq!(
        count(&target.db, "SELECT count(*) FROM object_index WHERE object_id='wire'")?,
        0,
        "unowned legacy placeholder must be omitted"
    );
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Public owner erasure clears ordinary provenance with the final retention edge.
#[test]
fn probe_r3_public_erasure_leaves_no_binding_without_edges() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r3-public-erasure")?;
    register(&db, "wire", "message")?;
    payload(&db, 5)?;
    db.delete_direct_message("thread", "message", "local", "tomb-1")?;
    let edges: u64 =
        db.connection
            .query_row("SELECT count(*) FROM object_retention_reference", [], |r| r.get(0))?;
    let binding: u64 = db.connection.query_row(
        "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:wire'",
        [],
        |r| r.get(0),
    )?;
    eprintln!("after public delete: edges={edges} binding={binding}");
    assert!(!(edges == 0 && binding > 0), "public path leaves binding without edges");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// A legacy sender directory record creates provenance, without a restriction footprint.
#[test]
fn probe_r3_legacy_sender_placeholder_with_directory_binding() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r3-legacy-sender")?;
    db.send_direct_message("thread", "message", "peer", b"body")?;
    db.persist_client_record("object", "sent-x", &json!({"owner":"self","message_id":"message"}))?;
    let target_path = root.join("target.db");
    let saved = db.write_backup_snapshot(&target_path)?;
    db.connection.execute("INSERT INTO object_index(object_id,chunk_manifest_hash,object_state,total_cipher_size,chunk_count,created_at,updated_at,manifest_hash,nonce,ciphertext,tombstoned) VALUES('sent-x',zeroblob(32),'revoked',0,0,1,1,zeroblob(32),'',x'',1)",[])?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    let source = BackupDatabase::open_restore_input(
        &input,
        &snapshot.key,
        BackupOpenMode::PreNormalization,
    )?;
    let shape = (
        count(
            &source.db,
            "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:sent-x'",
        )?,
        count(&source.db, "SELECT count(*) FROM object_retention_reference")?,
        count(
            &source.db,
            "SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'",
        )?,
    );
    drop(source);
    let mut target = BackupDatabase::open_restore_input(
        &target_path,
        &saved.key,
        BackupOpenMode::PreNormalization,
    )?;
    let result = target.merge_backup_candidate(&input, &snapshot.key, || Ok(()));
    eprintln!(
        "legacy sender (binding,edges,footprint)={shape:?} result={:?}",
        result.as_ref().map(|_| ())
    );
    assert_eq!(shape, (1, 0, 0));
    result?;
    assert_eq!(
        count(&target.db, "SELECT count(*) FROM object_index WHERE object_id='sent-x'")?,
        0,
        "binding-only sender placeholder must be omitted"
    );
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
