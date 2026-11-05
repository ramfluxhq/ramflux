// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Observe the actual graph writer before preservation and final deletion.
use super::super::backup_merge::BackupMergeMode;
use super::*;
use crate::{ObjectReferenceAdmission, ObjectReferenceOwner};
use serde_json::json;

#[test]
fn admitted_graph_writer_excludes_unadmitted_reference_edges()
-> Result<(), Box<dyn std::error::Error>> {
    super::tests::fixture("admitted-graph-writer", |root, live, target, _, _| {
        for selector in ["rejected-alias", "accepted-alias"] {
            let message = format!("message-{selector}");
            live.send_direct_message("thread", &message, "peer", b"body")?;
            let reference = json!({"object_id":"wire","manifest_hash":"manifest","slot":selector,"key_slot":{"object_id":"wire","slot_id":selector},"total_chunks":2});
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
                    message_id: &message,
                    reference: &reference,
                    metadata: &json!({"message_id":message}),
                },
            )?;
            let slot = blake3_256_base64url(
                "ramflux.received.slot.selector.v2",
                &ramflux_protocol::canonical_json_bytes(&reference["key_slot"])?,
            );
            live.register_object_reference_actor(
                &hash,
                &format!("attachment/reference-by-slot/{slot}"),
            )?;
            if selector == "accepted-alias" {
                live.send_direct_message("thread", "deleted-owner", "peer", b"body")?;
                live.register_object_reference(
                    ObjectReferenceAdmission::FreshMessage,
                    &ObjectReferenceOwner {
                        reference_hash: &hash,
                        wire_id: "wire",
                        manifest_hash: "manifest",
                        selector,
                        message_id: "deleted-owner",
                        reference: &reference,
                        metadata: &json!({"message_id":"deleted-owner"}),
                    },
                )?;
            }
        }
        let path = root.join("graph-source.db");
        let snapshot = live.write_backup_snapshot(&path)?;
        let before = std::fs::read(&path)?;
        let commitment = object_erasure_commitment("principal", "wire", "manifest");
        target.db.execute(
            "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
            params![object_erasure_lookup("principal", "rejected-alias"), commitment],
        )?;
        let marker = blake3_256_base64url("ramflux.deleted-message.v1", b"deleted-owner");
        target.db.execute(
            "INSERT INTO runtime_actor_state VALUES(?1,?2)",
            params![format!("message/deleted/{marker}"), b"true".as_slice()],
        )?;
        let result = target.merge_backup_pipeline(&path,&snapshot.key,
            (BackupMergeMode::FullAccount(None),true), &mut ||Ok(()), |db| {
                graph::classify(db)?;
                // Remove the fixture's target owners, so target presence cannot mask an import.
                db.execute_batch("DELETE FROM object_message_reference; DELETE FROM object_retention_reference; DELETE FROM object_reference_actor; DELETE FROM message_copy_binding; DELETE FROM message_footprint;
CREATE TABLE graph_insert_observation(selector TEXT NOT NULL);
CREATE TRIGGER graph_insert_observer AFTER INSERT ON object_retention_reference BEGIN INSERT INTO graph_insert_observation VALUES(NEW.selector); END;")?;
                writer::merge(db)?;
                assert_eq!(db.query_row("SELECT count(*) FROM object_message_reference WHERE message_id='deleted-owner'",[],|r|r.get::<_,u64>(0))?,0,"unadmitted owner of admitted hash");
                assert_eq!(db.query_row("SELECT count(*) FROM message_copy_binding WHERE message_id='deleted-owner'",[],|r|r.get::<_,u64>(0))?,0);
                assert_eq!(db.query_row("SELECT count(*) FROM message_footprint WHERE message_id='deleted-owner'",[],|r|r.get::<_,u64>(0))?,0);
                assert_eq!(db.query_row("SELECT count(*) FROM graph_insert_observation WHERE selector='rejected-alias'",[],|r|r.get::<_,u64>(0))?,0,"unadmitted reference was inserted before cleanup");
                for (selector, count) in [("rejected-alias",0_u64),("accepted-alias",1),("wire",1)] {
                    assert_eq!(db.query_row("SELECT count(*) FROM object_retention_reference WHERE selector=?1",[selector],|r|r.get::<_,u64>(0))?,count,"reference {selector}");
                    assert_eq!(db.query_row("SELECT count(*) FROM object_message_reference m JOIN object_retention_reference r USING(reference_hash) WHERE r.selector=?1",[selector],|r|r.get::<_,u64>(0))?,count,"owner {selector}");
                    assert_eq!(db.query_row("SELECT count(*) FROM message_copy_binding WHERE copy_id='object:'||?1",[selector],|r|r.get::<_,u64>(0))?,if selector == "wire" {2} else {count},"binding {selector}");
                    assert_eq!(db.query_row("SELECT count(*) FROM message_footprint WHERE kind='revocation_selector' AND json_extract(locator,'$.selector')=?1",[selector],|r|r.get::<_,u64>(0))?,0,"modern registration never creates legacy footprint {selector}");
                }
                for (selector, count) in [("rejected-alias",0_u64),("accepted-alias",1)] {
                    let slot = blake3_256_base64url("ramflux.received.slot.selector.v2",
                        &ramflux_protocol::canonical_json_bytes(&json!({"object_id":"wire","slot_id":selector}))?);
                    let actor = format!("attachment/reference-by-slot/{slot}");
                    assert_eq!(db.query_row("SELECT count(*) FROM object_reference_actor WHERE state_kind=?1",[&actor],|r|r.get::<_,u64>(0))?,count,"reference actor {selector}");
                    assert_eq!(db.query_row("SELECT count(*) FROM message_footprint WHERE kind='actor' AND locator=?1",[&actor],|r|r.get::<_,u64>(0))?,count,"actor footprint {selector}");
                }
                assert_eq!(db.query_row("SELECT count(*) FROM object_retention_payload WHERE commitment=?1",[&commitment],|r|r.get::<_,u64>(0))?,1,"shared unfenced payload survives");
                assert_eq!(db.query_row("SELECT owner_count FROM object_retention_payload WHERE commitment=?1",[&commitment],|r|r.get::<_,u64>(0))?,2,"only admitted owner edges are charged");
                Err(StorageError::AuthorizationRejected)
            });
        assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
        assert_eq!(std::fs::read(&path)?, before);
        Ok(())
    })
}
