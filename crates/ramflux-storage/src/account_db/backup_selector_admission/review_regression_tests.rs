// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore regressions for actor authority and fences added after classification.
use super::super::backup_merge::BackupMergeMode;
use super::*;
use crate::{ObjectReferenceAdmission, ObjectReferenceOwner};
use serde_json::json;

fn register(
    live: &crate::AccountDb,
    selector: &str,
    message: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    live.send_direct_message("thread", message, "peer", b"body")?;
    let reference = json!({"object_id":"wire","manifest_hash":"manifest","slot":selector});
    let hash = blake3_256_base64url(
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
            message_id: message,
            reference: &reference,
            metadata: &json!({"message_id":message}),
        },
    )?;
    Ok(hash)
}

// A fence that appears after classification (e.g. merge_object_erasure's
// PAYLOAD_ERASE over erased target object_index rows) must still dominate.
#[test]
fn review_fence_after_classify_dominates_writer() -> Result<(), Box<dyn std::error::Error>> {
    super::tests::fixture("review-fence-late", |root, live, target, _, _| {
        register(live, "alias", "m-alias")?;
        let path = root.join("src.db");
        let snapshot = live.write_backup_snapshot(&path)?;
        let commitment = object_erasure_commitment("principal", "wire", "manifest");
        let result = target.merge_backup_pipeline(&path, &snapshot.key, (BackupMergeMode::FullAccount(None), true), &mut || Ok(()), |db| {
            graph::classify(db)?;
            db.execute_batch("DELETE FROM object_message_reference; DELETE FROM object_retention_reference; DELETE FROM object_reference_actor; DELETE FROM message_copy_binding; DELETE FROM message_footprint;")?;
            db.execute("INSERT INTO object_erasure_fence VALUES(?1) ON CONFLICT DO NOTHING", [&commitment])?;
            writer::merge(db)?;
            let refs: u64 = db.query_row("SELECT count(*) FROM object_retention_reference WHERE commitment=?1", [&commitment], |r| r.get(0))?;
            let owners: u64 = db.query_row("SELECT count(*) FROM object_message_reference", [], |r| r.get(0))?;
            let foot: u64 = db.query_row("SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'", [], |r| r.get(0))?;
            eprintln!("PROBE fence-late refs={refs} owners={owners} selector_footprints={foot}");
            assert_eq!(refs, 0, "reference to fenced commitment imported");
            assert_eq!(owners, 0, "owner edge to fenced commitment imported");
            assert_eq!(foot, 0, "modern writer created legacy footprint");
            for table in ["object_reference_actor", "message_copy_binding", "message_footprint"] {
                assert_eq!(db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r|r.get::<_,u64>(0))?, 0, "late fence: {table}");
            }
            Err(StorageError::AuthorizationRejected)
        });
        assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
        Ok(())
    })
}

fn crafted_actor(crafted: bool) -> Result<(), Box<dyn std::error::Error>> {
    super::tests::fixture(
        if crafted { "review-actor-crafted" } else { "review-actor-control" },
        |root, live, target, _, _| {
            let hash = register(live, "ok", "m-ok")?;
            if crafted {
                // Not produced by the SDK: binds a key belonging to another payload.
                live.register_object_reference_actor(&hash, "attachment/reference/victim")?;
            }
            let path = root.join("src.db");
            let snapshot = live.write_backup_snapshot(&path)?;
            let victim = object_erasure_commitment("principal", "victim-wire", "victim-manifest");
            let result = target.merge_backup_pipeline(&path, &snapshot.key, (BackupMergeMode::FullAccount(None), true), &mut || Ok(()), |db| {
            graph::classify(db)?;
            writer::merge(db)?;
            db.execute("INSERT INTO runtime_actor_state VALUES('attachment/reference/victim',x'7b7d') ON CONFLICT DO NOTHING", [])?;
            db.execute("INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class) VALUES(?1,'victim-wire','victim-manifest','victim-lookup','imported')", [&victim])?;
            db.execute("INSERT INTO object_payload_actor VALUES(?1,'attachment/reference/victim')", [&victim])?;
            db.execute("INSERT INTO object_erasure_work VALUES(?1,'victim-wire','victim-manifest')", [&victim])?;
            db.execute_batch(&super::super::object_retention::payload_erasure_body(db)?)?;
            let left: u64 = db.query_row("SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/victim'", [], |r| r.get(0))?;
            let fp: u64 = db.query_row("SELECT count(*) FROM message_footprint WHERE kind='actor' AND locator='attachment/reference/victim'", [], |r| r.get(0))?;
            eprintln!("PROBE crafted={crafted} victim_actor_left={left} victim_actor_footprints={fp}");
            assert_eq!(left, 0, "fenced payload actor survived erasure");
            assert_eq!(fp, 0, "unauthorized actor footprint survived");
            assert_eq!(db.query_row("SELECT count(*) FROM object_reference_actor WHERE state_kind='attachment/reference/victim'", [], |r|r.get::<_,u64>(0))?, 0, "unauthorized actor binding imported");
            assert_eq!(db.query_row("SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'", [], |r|r.get::<_,u64>(0))?, 0, "modern registration never creates legacy footprints");
            Err(StorageError::AuthorizationRejected)
        });
            assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
            Ok(())
        },
    )
}

#[test]
fn review_crafted_reference_actor_cannot_shield_victim() -> Result<(), Box<dyn std::error::Error>> {
    crafted_actor(true)
}
#[test]
fn review_control_victim_actor_erased() -> Result<(), Box<dyn std::error::Error>> {
    crafted_actor(false)
}

#[test]
fn late_fence_at_production_graph_write_excludes_incoming_graph()
-> Result<(), Box<dyn std::error::Error>> {
    super::tests::fixture("production-writer-late-fence", |_, _, target, path, key| {
        let result = target.merge_backup_pipeline(path, key,
            (BackupMergeMode::FullAccount(None), true), &mut || Ok(()), |db| {
                db.execute_batch("DELETE FROM object_message_reference; DELETE FROM object_retention_reference; DELETE FROM object_reference_actor; DELETE FROM message_copy_binding; DELETE FROM message_footprint; DELETE FROM object_retention_payload;")?;
                writer::FENCE_BEFORE_WRITE.set(true);
                Ok(())
            });
        writer::FENCE_BEFORE_WRITE.set(false);
        result?;
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM object_erasure_fence WHERE commitment=?1",
                [object_erasure_commitment("principal", "wire", "manifest")],
                |r| r.get::<_, u64>(0)
            )?,
            1
        );
        for table in [
            "object_retention_payload",
            "object_retention_reference",
            "object_message_reference",
            "object_reference_actor",
            "message_copy_binding",
            "message_footprint",
        ] {
            assert_eq!(
                target.db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, u64>(0))?,
                0,
                "production write: {table}"
            );
        }
        Ok(())
    })
}

#[test]
fn reference_actor_keys_require_exact_slot_or_bounded_ack_identity()
-> Result<(), Box<dyn std::error::Error>> {
    for wrapped in [false, true] {
        super::tests::fixture(
            &format!("reference-actor-keys-{wrapped}"),
            |root, live, target, _, _| {
                live.send_direct_message("thread", "actor-owner", "peer", b"body")?;
                let inner = json!({"object_id":"wire","manifest_hash":"manifest",
                "key_slot":{"object_id":"wire","slot_id":"actor-slot"},"total_chunks":2});
                let stored = if wrapped {
                    json!({"reference":inner,"message_id":"actor-owner"})
                } else {
                    inner.clone()
                };
                let hash = blake3_256_base64url(
                    "ramflux.attachment.reference.v1",
                    &ramflux_protocol::canonical_json_bytes(&inner)?,
                );
                live.register_object_reference(
                    ObjectReferenceAdmission::FreshMessage,
                    &ObjectReferenceOwner {
                        reference_hash: &hash,
                        wire_id: "wire",
                        manifest_hash: "manifest",
                        selector: "actor-alias",
                        message_id: "actor-owner",
                        reference: &stored,
                        metadata: &json!({"message_id":"actor-owner"}),
                    },
                )?;
                let slot = format!(
                    "attachment/reference-by-slot/{}",
                    blake3_256_base64url(
                        "ramflux.received.slot.selector.v2",
                        &ramflux_protocol::canonical_json_bytes(&inner["key_slot"])?
                    )
                );
                let ack = format!(
                    "attachment/ack/{}/",
                    blake3_256_base64url(
                        "ramflux.attachment.ack.progress.v1",
                        &ramflux_protocol::canonical_json_bytes(&inner)?
                    )
                );
                let allowed = [slot, format!("{ack}0"), format!("{ack}1")];
                let denied = [
                    "attachment/reference/victim".to_owned(),
                    "attachment/reference-by-slot/unrelated".into(),
                    format!("{ack}2"),
                    format!("{ack}01"),
                    format!("{ack}-1"),
                    "attachment/ack/unrelated/0".into(),
                ];
                for key in allowed.iter().chain(&denied) {
                    live.register_object_reference_actor(&hash, key)?;
                }
                let path = root.join("actor-source.db");
                let snapshot = live.write_backup_snapshot(&path)?;
                let result=target.merge_backup_pipeline(&path,&snapshot.key,
                (BackupMergeMode::FullAccount(None),true),&mut ||Ok(()), |db| {
                    graph::classify(db)?;
                    writer::merge(db)?;
                    for (keys,count) in [(&allowed[..],1_u64),(&denied[..],0)] {
                        for key in keys {
                            assert_eq!(db.query_row("SELECT count(*) FROM object_reference_actor WHERE reference_hash=?1 AND state_kind=?2",params![hash,key],|r|r.get::<_,u64>(0))?,count,"actor {key}");
                            assert_eq!(db.query_row("SELECT count(*) FROM message_footprint WHERE message_id='actor-owner' AND kind='actor' AND locator=?1",[key],|r|r.get::<_,u64>(0))?,count,"footprint {key}");
                        }
                    }
                    assert_eq!(db.query_row("SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'",[],|r|r.get::<_,u64>(0))?,0);
                    Err(StorageError::AuthorizationRejected)
                });
                assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
                Ok(())
            },
        )?;
    }
    Ok(())
}
