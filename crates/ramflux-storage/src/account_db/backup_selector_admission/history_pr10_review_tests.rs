// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy restrictions must survive or refuse candidate normalization.
use super::*;

/// Real P1 legacy shape (`selector_legacy_tests::legacy_source`): an unowned
/// `attachment/reference/*` actor authorized by a client record, optionally followed by
/// the real missing-row revocation (tombstoned placeholder + enrollment).
fn legacy(db: &AccountDb, revoke: bool) -> Result<(), StorageError> {
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
    db.persist_actor_state(
        "attachment/reference-by-slot/private-canary",
        &json!("private-canary"),
    )?;
    if revoke {
        db.set_object_tombstoned_with_revocation(
            "private-canary",
            Some("peer"),
            Some("revoke"),
            1,
        )?;
    }
    Ok(())
}

fn state(db: &rusqlite::Connection) -> rusqlite::Result<(u64, u64, u64)> {
    Ok((
        db.query_row("SELECT count(*) FROM object_index WHERE object_id='private-canary' AND tombstoned=1", [], |r| r.get(0))?,
        db.query_row("SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/private-canary'", [], |r| r.get(0))?,
        db.query_row("SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'", [], |r| r.get(0))?,
    ))
}

/// Single-input normalization must keep the archive's own revocation tombstone.
#[test]
fn probe_pr10_fresh_normalization_keeps_legacy_revocation_tombstone() -> TestResult {
    let (root, db) = crate::tests::test_db("pr10-fresh-legacy")?;
    legacy(&db, true)?;
    let path = root.join("fresh.db");
    let saved = db.write_backup_snapshot(&path)?;
    let mut stage =
        BackupDatabase::open_restore_input(&path, &saved.key, BackupOpenMode::PreNormalization)?;
    let result = stage.normalize_backup_candidate();
    result?;
    assert_eq!(
        state(&stage.db)?.0,
        1,
        "normalization dropped the archive's own revocation tombstone"
    );
    drop(stage);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// Incoming-held revocation tombstone over a target that predates it: restriction is a union.
#[test]
fn probe_pr10_incoming_legacy_revocation_tombstone_survives_merge() -> TestResult {
    let (root, db) = crate::tests::test_db("pr10-merge-legacy")?;
    legacy(&db, false)?;
    let target_path = root.join("target.db");
    let saved = db.write_backup_snapshot(&target_path)?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    let mut target = BackupDatabase::open_restore_input(
        &target_path,
        &saved.key,
        BackupOpenMode::PreNormalization,
    )?;
    let result = target.merge_backup_candidate(&input, &snapshot.key, || Ok(()));
    match result {
        Ok(_) => {
            let actual = state(&target.db)?;
            assert_eq!((actual.0, actual.2), (1, 1), "incoming restriction lost");
        }
        Err(StorageError::ObjectOwnershipUnverified { .. }) => {
            assert_eq!(state(&target.db)?, (0, 1, 0), "refusal must roll back the private stage");
        }
        Err(error) => return Err(error.into()),
    }
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// Target-held legacy revocation tombstone over an archive that predates it (witness).
#[test]
fn probe_pr10_target_legacy_revocation_tombstone_survives_merge() -> TestResult {
    let (root, db) = crate::tests::test_db("pr10-merge-legacy-target")?;
    legacy(&db, false)?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    let target_path = root.join("target.db");
    let saved = db.write_backup_snapshot(&target_path)?;
    let mut target = BackupDatabase::open_restore_input(
        &target_path,
        &saved.key,
        BackupOpenMode::PreNormalization,
    )?;
    let result = target.merge_backup_candidate(&input, &snapshot.key, || Ok(()));
    if result.is_ok() {
        assert_eq!(
            state(&target.db)?.0,
            1,
            "target revocation tombstone omitted by candidate merge"
        );
    }
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
