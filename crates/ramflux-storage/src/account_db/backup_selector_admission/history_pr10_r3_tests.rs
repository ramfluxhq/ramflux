// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Registered placeholders remain restrictions after their actor is omitted.
use super::*;

fn legacy(db: &AccountDb) -> Result<(), StorageError> {
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
    Ok(())
}

fn count(db: &rusqlite::Connection, sql: &str) -> rusqlite::Result<u64> {
    db.query_row(sql, [], |r| r.get(0))
}

fn tomb_reg(db: &rusqlite::Connection) -> rusqlite::Result<(u64, u64, u64)> {
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
    ))
}

/// Shape: incoming placeholder carries its own revocation registration, but the
/// `attachment/reference/*` actor was removed (public `remove_actor_state`).
#[test]
fn probe_r2_incoming_registered_placeholder_without_actor() -> TestResult {
    for witness in ["both", "footprint", "binding"] {
        registered_without_actor(true, witness)?;
    }
    Ok(())
}

fn registered_without_actor(imported: bool, witness: &str) -> TestResult {
    let (root, db) =
        crate::tests::test_db(if imported { "p210r2-noactor" } else { "p210r2-never" })?;
    if imported {
        legacy(&db)?;
    } else {
        db.send_direct_message("thread", "message", "peer", b"body")?;
        db.persist_client_record(
            "object",
            "private-canary",
            &json!({"owner":"peer","message_id":"message","manifest_hash":"manifest"}),
        )?;
    }
    let target_path = root.join("target.db");
    let saved = db.write_backup_snapshot(&target_path)?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    db.remove_actor_state("attachment/reference/private-canary")?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    let source_db = BackupDatabase::open(&input, &snapshot.key)?;
    if witness == "footprint" {
        source_db.db.execute(
            "DELETE FROM message_copy_binding WHERE copy_id='object:private-canary'",
            [],
        )?;
    }
    if witness == "binding" {
        source_db
            .db
            .execute("DELETE FROM message_footprint WHERE kind='revocation_selector'", [])?;
    }
    let source = tomb_reg(&source_db.db)?;
    drop(source_db);
    assert_eq!(
        source,
        (1, u64::from(witness != "binding"), u64::from(witness != "footprint")),
        "source distinguishes restriction footprint from ordinary binding"
    );
    let mut target = BackupDatabase::open_restore_input(
        &target_path,
        &saved.key,
        BackupOpenMode::PreNormalization,
    )?;
    let before = tomb_reg(&target.db)?;
    let source_bytes = std::fs::read(&input)?;
    let result = target.merge_backup_candidate(&input, &snapshot.key, || Ok(()));
    assert_eq!(std::fs::read(&input)?, source_bytes);
    match result {
        Ok(_) => {
            let s = tomb_reg(&target.db)?;
            if witness == "binding" {
                assert_eq!((s.0, s.1), (0, 0), "binding-only legacy input must be omitted");
            } else {
                assert_eq!((s.0, s.1), (1, 1), "incoming registered tombstone lost");
            }
        }
        Err(StorageError::ObjectOwnershipUnverified { .. }) => {
            assert_ne!(witness, "binding", "binding-only input is omittable");
            assert_eq!(tomb_reg(&target.db)?, before);
        }
        Err(e) => return Err(e.into()),
    }
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// Shape: incoming deletes the message that carries the unowned reference.
#[test]
fn probe_r2_incoming_deleted_message_marker_survives() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r2-deleted")?;
    legacy(&db)?;
    let target_path = root.join("target.db");
    let saved = db.write_backup_snapshot(&target_path)?;
    db.delete_direct_message("thread", "message", "local", "tomb-1")?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    let mut target = BackupDatabase::open_restore_input(
        &target_path,
        &saved.key,
        BackupOpenMode::PreNormalization,
    )?;
    assert_eq!(
        count(
            &target.db,
            "SELECT count(*) FROM message_tombstone_projection WHERE message_id='message'"
        )?,
        0
    );
    let result = target.merge_backup_candidate(&input, &snapshot.key, || Ok(()));
    if result.is_ok() {
        assert_eq!(
            count(
                &target.db,
                "SELECT count(*) FROM message_tombstone_projection WHERE message_id='message'"
            )?,
            1
        );
        assert_eq!(
            count(
                &target.db,
                "SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/private-canary'"
            )?,
            0
        );
    } else if !matches!(result, Err(StorageError::ObjectOwnershipUnverified { .. })) {
        result?;
    }
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// Shape: incoming holds a fence plus a closed selector lookup next to the unowned actor.
#[test]
fn probe_r2_incoming_fence_and_lookup_survive() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r2-fence")?;
    legacy(&db)?;
    let target_path = root.join("target.db");
    let saved = db.write_backup_snapshot(&target_path)?;
    let principal: String = db.connection.query_row(
        "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let commitment = object_erasure_commitment(&principal, "wire", "manifest");
    let lookup = object_erasure_lookup(&principal, "private-canary");
    db.connection.execute("INSERT INTO object_erasure_fence VALUES(?1)", params![commitment])?;
    db.connection
        .execute("INSERT INTO object_erasure_lookup VALUES(?1,?2)", params![lookup, commitment])?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    let mut target = BackupDatabase::open_restore_input(
        &target_path,
        &saved.key,
        BackupOpenMode::PreNormalization,
    )?;
    let result = target.merge_backup_candidate(&input, &snapshot.key, || Ok(()));
    if result.is_ok() {
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM object_erasure_fence WHERE commitment=?1",
                [&commitment],
                |r| r.get::<_, u64>(0)
            )?,
            1,
            "fence lost"
        );
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM object_erasure_lookup WHERE lookup=?1",
                [&lookup],
                |r| r.get::<_, u64>(0)
            )?,
            1,
            "lookup lost"
        );
    } else if !matches!(result, Err(StorageError::ObjectOwnershipUnverified { .. })) {
        result?;
    }
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// Production producer of the no-actor shape: fresh normalization of a revoked legacy
/// archive keeps tombstone + registration and omits the unowned actor.
#[test]
fn probe_r2_fresh_normalization_yields_registered_placeholder_without_actor() -> TestResult {
    let (root, db) = crate::tests::test_db("p210r2-fresh-shape")?;
    legacy(&db)?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    let path = root.join("fresh.db");
    let saved = db.write_backup_snapshot(&path)?;
    let mut stage =
        BackupDatabase::open_restore_input(&path, &saved.key, BackupOpenMode::PreNormalization)?;
    stage.normalize_backup_candidate()?;
    let actor = count(
        &stage.db,
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/private-canary'",
    )?;
    let s = tomb_reg(&stage.db)?;
    assert_eq!((s.0, s.1, actor), (1, 1, 0));
    drop(stage);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
