// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy revocation vetoes survive candidate placeholder classification.
use crate::{
    AccountDb, BackupDatabase, BackupOpenMode, ObjectReferenceAdmission, ObjectReferenceOwner,
    ObjectWrite,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn legacy_owner(db: &AccountDb) -> TestResult {
    db.send_direct_message("thread", "message", "peer", b"body")?;
    db.persist_actor_state(
        "attachment/reference/wire",
        &json!({"reference":{"object_id":"wire","manifest_hash":"legacy-manifest"}}),
    )?;
    db.persist_client_record(
        "object",
        "wire",
        &json!({"owner":"peer","message_id":"message","manifest_hash":"legacy-manifest"}),
    )?;
    Ok(())
}

fn materialize(db: &AccountDb) -> TestResult {
    db.upsert_object(&ObjectWrite {
        object_id: "wire",
        manifest_hash: "legacy-manifest",
        nonce: "nonce",
        ciphertext: b"secret-ciphertext",
        plaintext_hash: "plain",
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&[7; 32]),
        object: &json!({}),
        updated_at: 5,
    })?;
    Ok(())
}

fn assert_veto(db: &BackupDatabase) -> TestResult {
    let state = db.db.query_row(
        "SELECT tombstoned,length(ciphertext) FROM object_index WHERE object_id='wire'",
        [],
        |r| Ok((r.get::<_, bool>(0)?, r.get::<_, u64>(1)?)),
    )?;
    assert_eq!(state, (true, 0), "revoked attachment resurrected");
    Ok(())
}

#[test]
fn review_probe_target_legacy_revocation_not_resurrected() -> TestResult {
    target_legacy_veto(None)
}

#[test]
fn review_spoofed_group_binding_cannot_drop_target_veto() -> TestResult {
    target_legacy_veto(Some("group:g:gm"))
}

#[test]
fn review_spoofed_envelope_binding_cannot_drop_target_veto() -> TestResult {
    target_legacy_veto(Some("envelope:deleted-envelope"))
}

fn target_legacy_veto(spoof: Option<&str>) -> TestResult {
    let (root, live) = crate::tests::test_db(&format!(
        "restore-legacy-target-veto-{}",
        spoof.unwrap_or("honest")
    ))?;
    legacy_owner(&live)?;
    materialize(&live)?;
    let input = root.join("live.db");
    let input_snapshot = live.write_backup_snapshot(&input)?;
    let source = BackupDatabase::open_restore_input(
        &input,
        &input_snapshot.key,
        BackupOpenMode::PreNormalization,
    )?;
    source.db.execute(
        "DELETE FROM runtime_actor_state WHERE state_kind='attachment/reference/wire'",
        [],
    )?;
    if let Some(binding) = spoof {
        source.db.execute("INSERT INTO message_copy_binding VALUES(?1,'message')", [binding])?;
    }
    drop(source);
    // Only the target knows these deletions; the archive invents their owner link.
    if spoof == Some("group:g:gm") {
        live.connection.execute("INSERT INTO group_message_tombstone_projection VALUES('g','gm','tombstone','peer','all',1,'deleted',10)", [])?;
    } else if spoof.is_some() {
        let mac = live.account_mac(b"ramflux/deleted-envelope/v1", b"deleted-envelope")?;
        live.persist_actor_state(
            &format!("message/deleted-envelope/{mac}"),
            &json!({"deleted":true}),
        )?;
    }
    live.connection.execute("DELETE FROM object_index WHERE object_id='wire'", [])?;
    live.set_object_tombstoned_with_revocation("wire", Some("peer"), Some("revoke"), 10)?;
    let path = root.join("target.db");
    let snapshot = live.write_backup_snapshot(&path)?;
    let mut target =
        BackupDatabase::open_restore_input(&path, &snapshot.key, BackupOpenMode::PreNormalization)?;
    assert_eq!(
        target.db.query_row("SELECT count(*) FROM object_retention_reference", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    let before = std::fs::read(&input)?;
    target.merge_backup_candidate(&input, &input_snapshot.key, || Ok(()))?;
    assert_veto(&target)?;
    assert_eq!(target.db.query_row("SELECT count(*) FROM message_copy_binding WHERE copy_id='object:wire' AND message_id='message'", [], |r| r.get::<_,u64>(0))?, 1);
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        1
    );
    assert_eq!(std::fs::read(&input)?, before);
    target.check_integrity()?;
    drop(target);
    drop(live);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn newer_archived_revocation_uses_target_admitted_mapping() -> TestResult {
    for legacy_zero in [false, true] {
        let (root, live) = crate::tests::test_db("restore-newer-archived-veto")?;
        legacy_owner(&live)?;
        let hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object.transport.owner.v1",
            &ramflux_protocol::canonical_json_bytes(&("wire", "legacy-manifest", "message"))?,
        );
        live.register_object_reference(
            ObjectReferenceAdmission::FreshMessage,
            &ObjectReferenceOwner {
                reference_hash: &hash,
                wire_id: "wire",
                manifest_hash: "legacy-manifest",
                selector: "wire",
                message_id: "message",
                reference: &json!({}),
                metadata: &json!({}),
            },
        )?;
        materialize(&live)?;
        let target_path = root.join("target.db");
        let target_snapshot = live.write_backup_snapshot(&target_path)?;
        live.connection.execute_batch("DELETE FROM object_message_reference; DELETE FROM object_retention_reference; DELETE FROM object_index;")?;
        live.set_object_tombstoned_with_revocation("wire", Some("peer"), Some("revoke"), 10)?;
        let input = root.join("revoked.db");
        let snapshot = live.write_backup_snapshot(&input)?;
        let source = BackupDatabase::open_restore_input(
            &input,
            &snapshot.key,
            BackupOpenMode::PreNormalization,
        )?;
        source.db.execute(
            "DELETE FROM runtime_actor_state WHERE state_kind='attachment/reference/wire'",
            [],
        )?;
        if legacy_zero {
            source.db.execute_batch("UPDATE object_index SET manifest_hash=zeroblob(32),chunk_manifest_hash=zeroblob(32);")?;
        }
        drop(source);
        let before = std::fs::read(&input)?;
        let mut target = BackupDatabase::open(&target_path, &target_snapshot.key)?;
        target.merge_backup_candidate(&input, &snapshot.key, || Ok(()))?;
        assert_veto(&target)?;
        assert_eq!(
            target.db.query_row(
                "SELECT CAST(manifest_hash AS TEXT) FROM object_index WHERE object_id='wire'",
                [],
                |r| r.get::<_, String>(0)
            )?,
            "legacy-manifest"
        );
        assert_eq!(std::fs::read(&input)?, before);
        target.check_integrity()?;
        drop(target);
        drop(live);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
