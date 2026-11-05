// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore must retain local selector identities across fenced graph deletion.
use crate::{BackupDatabase, ObjectReferenceAdmission, ObjectReferenceOwner};
use ramflux_crypto::{object_erasure_commitment, object_erasure_lookup};
use rusqlite::params;
use serde_json::json;

#[test]
fn e6_incoming_fence_captures_local_alias_before_delete() -> Result<(), Box<dyn std::error::Error>>
{
    for legacy_zero in [false, true] {
        let (root, live) = crate::tests::test_db("restore-local-alias-capture")?;
        let hash = register(&live, "local-alias")?;
        live.set_object_tombstoned("local-alias")?;
        let actor = "attachment/reference-by-slot/local";
        live.persist_actor_state(actor, &json!("local-alias"))?;
        live.register_object_reference_actor(&hash, actor)?;
        let path = root.join("target.db");
        let snapshot = live.write_backup_snapshot(&path)?;
        let mut target = BackupDatabase::open(&path, &snapshot.key)?;
        if legacy_zero {
            target.db.execute("UPDATE object_index SET manifest_hash=zeroblob(32),chunk_manifest_hash=zeroblob(32) WHERE object_id='local-alias'", [])?;
        }
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM object_index WHERE object_id='wire'",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        let commitment = object_erasure_commitment("principal", "wire", "manifest");
        let lookup = object_erasure_lookup("principal", "local-alias");
        observe_capture(&target.db)?;
        // A real newer snapshot carries the incoming fence but no local alias.
        live.delete_direct_message("thread", "message", "local", "delete")?;
        let incoming = root.join("incoming.db");
        let deleted = live.write_backup_snapshot(&incoming)?;
        let before = std::fs::read(&incoming)?;
        target.merge_backup_candidate(&incoming, &deleted.key, || Ok(()))?;
        let observations = target
            .db
            .prepare(
                "SELECT stage,captured,owners,payloads FROM capture_observation ORDER BY rowid",
            )?
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, u64>(2)?,
                    r.get::<_, u64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert!(
            observations.contains(&("before-delete".into(), 1, 1, 1)),
            "pre-delete capture missing: {observations:?}"
        );
        assert!(
            observations.contains(&("payload-entry".into(), 1, 0, 1)),
            "capture lost on shared-body entry: {observations:?}"
        );
        for table in [
            "object_retention_reference",
            "object_message_reference",
            "object_reference_actor",
            "object_retention_payload",
            "object_index",
            "object_reference_erasure_work",
            "object_erasure_work",
            "object_projection_erasure_work",
        ] {
            assert_eq!(
                target.db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, u64>(0))?,
                0,
                "{table}"
            );
        }
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM object_erasure_lookup WHERE lookup=?1 AND commitment=?2",
                params![lookup, commitment],
                |r| r.get::<_, u64>(0)
            )?,
            1
        );
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM runtime_actor_state WHERE state_kind=?1",
                [actor],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:local-alias'",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        assert_eq!(std::fs::read(&incoming)?, before);
        target.check_integrity()?;
        drop(target);
        drop(live);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn local_predelete_preserves_unfenced_pending_target_links()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, live) = crate::tests::test_db("restore-pending-target-links")?;
    let hash = register(&live, "pending-alias")?;
    let path = root.join("target.db");
    let target_snapshot = live.write_backup_snapshot(&path)?;
    let incoming = root.join("incoming.db");
    let source_snapshot = live.write_backup_snapshot(&incoming)?;
    let source = BackupDatabase::open(&incoming, &source_snapshot.key)?;
    // A partial input knows the message deletion without retaining its graph.
    source.db.execute_batch("DELETE FROM object_message_reference; DELETE FROM object_retention_reference; UPDATE direct_message_projection SET deleted=1;")?;
    drop(source);
    let before = std::fs::read(&incoming)?;
    let target = BackupDatabase::open(&path, &target_snapshot.key)?;
    target.db.execute(
        &format!(
            "ATTACH DATABASE ?1 AS incoming KEY \"x'{}'\"",
            source_snapshot.key.sqlcipher_hex()
        ),
        [&incoming.to_string_lossy()],
    )?;
    target.db.execute_batch("BEGIN IMMEDIATE;")?;
    super::prepare(&target.db)?;
    super::graph::classify(&target.db)?;
    assert_eq!(
        target
            .db
            .query_row("SELECT count(*) FROM backup_target_delete", [], |r| r.get::<_, u64>(0))?,
        1
    );
    assert_eq!(
        target
            .db
            .query_row("SELECT count(*) FROM object_erasure_fence", [], |r| r.get::<_, u64>(0))?,
        0
    );
    // Exercise the real production stage, stopping before the later final pass.
    target.merge_object_erasure(&mut || Ok(()))?;
    for table in ["object_message_reference", "object_retention_reference", "backup_target_delete"]
    {
        assert_eq!(
            target.db.query_row(
                &format!("SELECT count(*) FROM {table} WHERE reference_hash=?1"),
                [&hash],
                |r| r.get::<_, u64>(0)
            )?,
            1,
            "{table}"
        );
    }
    target.db.execute_batch("ROLLBACK; DETACH DATABASE incoming;")?;
    assert_eq!(std::fs::read(&incoming)?, before);
    drop(target);
    drop(live);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn register(live: &crate::AccountDb, selector: &str) -> Result<String, Box<dyn std::error::Error>> {
    live.send_direct_message("thread", "message", "peer", b"body")?;
    let reference = json!({"object_id":"wire","manifest_hash":"manifest","slot":selector});
    let hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.attachment.reference.v1",
        &ramflux_protocol::canonical_json_bytes(&reference)?,
    );
    live.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: &hash,
            wire_id: "wire",
            manifest_hash: "manifest",
            selector,
            message_id: "message",
            reference: &reference,
            metadata: &json!({"message_id":"message"}),
        },
    )?;
    Ok(hash)
}

fn observe_capture(db: &rusqlite::Connection) -> rusqlite::Result<()> {
    db.execute_batch(r"
CREATE TEMP TABLE capture_observation(stage TEXT, captured INTEGER, owners INTEGER, payloads INTEGER);
CREATE TEMP TRIGGER observe_local_delete BEFORE DELETE ON main.object_retention_reference
WHEN OLD.selector='local-alias' BEGIN
 INSERT INTO capture_observation SELECT 'before-delete',
 (SELECT count(*) FROM object_reference_erasure_work WHERE reference_hash=OLD.reference_hash),
 (SELECT count(*) FROM object_retention_reference WHERE reference_hash=OLD.reference_hash),
 (SELECT count(*) FROM object_erasure_work WHERE commitment=OLD.commitment);
END;
CREATE TEMP TRIGGER observe_payload_entry BEFORE UPDATE ON main.account_erasure_generation BEGIN
 INSERT INTO capture_observation SELECT 'payload-entry',
 (SELECT count(*) FROM object_reference_erasure_work WHERE selector='local-alias'),
 (SELECT count(*) FROM object_retention_reference WHERE selector='local-alias'),
 (SELECT count(*) FROM object_erasure_work WHERE wire_id='wire');
END;
")
}
