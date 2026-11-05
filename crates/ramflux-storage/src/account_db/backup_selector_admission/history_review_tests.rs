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
