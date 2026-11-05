// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deletion restrictions combine both input binding sets.
use super::*;

/// Target-only deletion authority (group tombstone / deleted-envelope marker) plus an
/// incoming-only copy binding must still veto the incoming candidate's reference.
fn incoming_binding_veto(kind: &str) -> TestResult {
    let (root, db) = crate::tests::test_db(&format!("probe-veto-{kind}"))?;
    let binding = if kind == "group" { "group:g:gm" } else { "envelope:deleted-envelope" };
    if kind == "group" {
        db.connection.execute("INSERT INTO group_message_tombstone_projection VALUES('g','gm','tombstone','peer','all',1,'deleted',10)", [])?;
    } else {
        let mac = db.account_mac(b"ramflux/deleted-envelope/v1", b"deleted-envelope")?;
        db.persist_actor_state(
            &format!("message/deleted-envelope/{mac}"),
            &json!({"deleted":true}),
        )?;
    }
    let path = root.join("target.db");
    let saved = db.write_backup_snapshot(&path)?;
    register(&db, "alias", "message")?;
    payload(&db, 1)?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    let source = BackupDatabase::open(&input, &snapshot.key)?;
    // The archive predates the deletion: only the target holds the authority.
    source.db.execute_batch("DELETE FROM group_message_tombstone_projection; DELETE FROM runtime_actor_state WHERE state_kind GLOB 'message/deleted-envelope/*';")?;
    source
        .db
        .execute("INSERT OR IGNORE INTO message_copy_binding VALUES(?1,'message')", [binding])?;
    drop(source);
    let mut target = BackupDatabase::open(&path, &saved.key)?;
    target.merge_backup_candidate(&input, &snapshot.key, || Ok(()))?;
    let owners: u64 = target.db.query_row(
        "SELECT count(*) FROM object_message_reference WHERE message_id='message'",
        [],
        |r| r.get(0),
    )?;
    let refs: u64 = target.db.query_row(
        "SELECT count(*) FROM object_retention_reference WHERE selector='alias'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        (owners, refs),
        (0, 0),
        "target-held deletion authority lost for incoming candidate"
    );
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn probe_group_tombstone_with_incoming_binding_vetoes_candidate() -> TestResult {
    incoming_binding_veto("group")
}
#[test]
fn probe_envelope_marker_with_incoming_binding_vetoes_candidate() -> TestResult {
    incoming_binding_veto("envelope")
}

fn archive_only_group_tombstone(second_generation: bool) -> TestResult {
    let (root, db) = crate::tests::test_db(&format!("archive-group-veto-{second_generation}"))?;
    // Only the target knows that this group copy belongs to the candidate owner.
    db.connection.execute("INSERT INTO message_copy_binding VALUES('group:g:gm','message')", [])?;
    let target_path = root.join("target.db");
    let selected = db.write_backup_snapshot(&target_path)?;
    db.connection.execute("DELETE FROM message_copy_binding", [])?;
    register(&db, "alias", "message")?;
    payload(&db, 1)?;
    db.connection.execute("INSERT INTO group_message_tombstone_projection VALUES('g','gm','tombstone','peer','all',1,'deleted',10)", [])?;
    let mut input = root.join("archive.db");
    let mut input_key = db.write_backup_snapshot(&input)?.key;

    if second_generation {
        // A first restore without the binding retains the candidate and the
        // archive restriction. Back it up through the production encrypted copy API.
        let restored_path = root.join("restored.db");
        let clean = BackupDatabase::open(&target_path, &selected.key)?;
        clean.copy_to(&restored_path, &selected.key)?;
        drop(clean);
        let mut restored = BackupDatabase::open(&restored_path, &selected.key)?;
        restored.db.execute("DELETE FROM message_copy_binding", [])?;
        restored.merge_backup_candidate(&input, &input_key, || Ok(()))?;
        assert_eq!(
            restored.db.query_row(
                "SELECT count(*) FROM object_retention_reference WHERE selector='alias'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            1
        );
        restored.check_integrity()?;
        let exported = root.join("restored-backup.db");
        let exported_key = crate::AccountDbKey::generate()?;
        restored.copy_to(&exported, &exported_key)?;
        drop(restored);
        input = exported;
        input_key = exported_key;
    }
    let source = BackupDatabase::open(&input, &input_key)?;
    assert_eq!(source.db.query_row("SELECT count(*) FROM group_message_tombstone_projection WHERE group_id='g' AND message_id='gm'", [], |r| r.get::<_, i64>(0))?, 1);
    assert_eq!(
        source.db.query_row(
            "SELECT count(*) FROM message_copy_binding WHERE copy_id='group:g:gm'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        source.db.query_row(
            "SELECT count(*) FROM object_retention_reference WHERE selector='alias'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    assert_eq!(source.db.query_row("SELECT count(*) FROM direct_message_projection WHERE message_id='message' AND deleted=1", [], |r| r.get::<_, i64>(0))?, 0);
    assert_eq!(source.db.query_row("SELECT (SELECT count(*) FROM message_tombstone_projection)+(SELECT count(*) FROM object_erasure_fence)+(SELECT count(*) FROM object_erasure_lookup)", [], |r| r.get::<_, i64>(0))?, 0);
    drop(source);
    let mut target = BackupDatabase::open(&target_path, &selected.key)?;
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM group_message_tombstone_projection",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(target.db.query_row("SELECT count(*) FROM message_copy_binding WHERE copy_id='group:g:gm' AND message_id='message'", [], |r| r.get::<_, i64>(0))?, 1);
    let before = std::fs::read(&input)?;
    target.merge_backup_candidate(&input, &input_key, || Ok(()))?;
    assert!(std::fs::read(&input)? == before, "merge changed the archive");
    let owners: i64 = target.db.query_row(
        "SELECT count(*) FROM object_message_reference WHERE message_id='message'",
        [],
        |r| r.get(0),
    )?;
    let references: i64 = target.db.query_row(
        "SELECT count(*) FROM object_retention_reference WHERE selector='alias'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!((owners, references), (0, 0), "archive-only group restriction lost");
    assert_eq!(target.db.query_row("SELECT count(*) FROM group_message_tombstone_projection WHERE group_id='g' AND message_id='gm'", [], |r| r.get::<_, i64>(0))?, 1);
    target.check_integrity()?;
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn archive_only_group_tombstone_with_target_binding_vetoes_candidate() -> TestResult {
    archive_only_group_tombstone(false)
}

#[test]
fn archive_only_group_tombstone_second_generation_vetoes_candidate() -> TestResult {
    archive_only_group_tombstone(true)
}
