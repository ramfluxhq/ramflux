// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]

//! Target-only DM deletion authority must veto admission before later row cleanup.
use super::*;

fn target_only_dm_restriction(deleted_projection: bool) -> TestResult {
    let (root, db) = crate::tests::test_db(&format!("target-dm-veto-{deleted_projection}"))?;
    let target_path = root.join("target.db");
    let target_key = db.write_backup_snapshot(&target_path)?;
    register(&db, "alias", "message")?;
    payload(&db, 1)?;
    let input = root.join("incoming.db");
    let input_key = db.write_backup_snapshot(&input)?;
    let source = BackupDatabase::open(&input, &input_key.key)?;
    assert_eq!(
        source.db.query_row(
            "SELECT count(*) FROM object_retention_reference WHERE selector='alias'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        1
    );
    assert_eq!(source.db.query_row("SELECT (SELECT count(*) FROM message_tombstone_projection)+(SELECT count(*) FROM direct_message_projection WHERE deleted=1)+(SELECT count(*) FROM group_message_tombstone_projection)+(SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB 'message/deleted*')+(SELECT count(*) FROM object_erasure_fence)+(SELECT count(*) FROM object_erasure_lookup)", [], |r| r.get::<_, u64>(0))?, 0, "archive must contain no competing deletion authority");
    drop(source);
    let before = std::fs::read(&input)?;
    let mut target = BackupDatabase::open(&target_path, &target_key.key)?;
    if deleted_projection {
        target.db.execute_batch("INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,scrub_version,created_at) VALUES('thread','message','peer',x'',x'7b7d',1,0,0,10);")?;
    } else {
        target.db.execute_batch("INSERT INTO message_tombstone_projection VALUES('target-tombstone','thread','message','all',10);")?;
    }
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM message_tombstone_projection WHERE message_id='message'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        u64::from(!deleted_projection)
    );
    assert_eq!(target.db.query_row("SELECT count(*) FROM direct_message_projection WHERE message_id='message' AND deleted=1", [], |r| r.get::<_, u64>(0))?, u64::from(deleted_projection));
    assert_eq!(target.db.query_row("SELECT (SELECT count(*) FROM group_message_tombstone_projection)+(SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB 'message/deleted*')+(SELECT count(*) FROM object_erasure_fence)+(SELECT count(*) FROM object_erasure_lookup)+(SELECT count(*) FROM object_retention_reference)", [], |r| r.get::<_, u64>(0))?, 0, "target DM row must be the only veto");
    target.merge_backup_pipeline(
        &input,
        &input_key.key,
        (BackupMergeMode::FullAccount(None), true),
        &mut || Ok(()),
        |connection| {
            // Numeric-only trace: later deletion triggers must not mask an
            // incorrectly admitted owner. No private identifier enters TEMP.
            connection.execute_batch("CREATE TEMP TABLE target_dm_admission_count(value INTEGER NOT NULL); CREATE TEMP TRIGGER target_dm_admission_trace AFTER INSERT ON main.backup_reference_admission WHEN NEW.side='incoming' BEGIN INSERT INTO target_dm_admission_count VALUES(1); END;")?;
            Ok(())
        },
    )?;
    assert_eq!(
        target.db.query_row("SELECT count(*) FROM temp.target_dm_admission_count", [], |r| r
            .get::<_, u64>(0))?,
        0,
        "target-only DM restriction admitted an incoming candidate"
    );
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM object_message_reference WHERE message_id='message'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM object_retention_reference WHERE selector='alias'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    assert!(std::fs::read(&input)? == before, "restore changed the archive");
    target.check_integrity()?;
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn target_only_dm_tombstone_vetoes_incoming_candidate() -> TestResult {
    target_only_dm_restriction(false)
}

#[test]
fn target_only_deleted_dm_projection_vetoes_incoming_candidate() -> TestResult {
    target_only_dm_restriction(true)
}
