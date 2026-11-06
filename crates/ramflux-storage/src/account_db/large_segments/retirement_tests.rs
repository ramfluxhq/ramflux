// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::{
    tests::{fixture, reopen},
    *,
};
use crate::{BackupDatabase, ObjectReferenceAdmission, ObjectReferenceOwner, ObjectWrite};
use rusqlite::params;
use std::fs;
fn bind(db: &AccountDb, m: &VerifiedContentManifest, message: &str, reference: &str) {
    let wire = ramflux_protocol::encode_base64url(m.manifest().object_id);
    let hash = ramflux_protocol::encode_base64url(m.manifest().hash().unwrap());
    db.upsert_object(&ObjectWrite {
        object_id: &wire,
        manifest_hash: &hash,
        nonce: "nonce",
        ciphertext: b"",
        plaintext_hash: "plaintext",
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&[1; 32]),
        object: &serde_json::json!({"object_id":wire,"tombstoned":false}),
        updated_at: 1,
    })
    .unwrap();
    db.send_direct_message("thread", message, "peer", b"message").unwrap();
    db.register_object_reference(ObjectReferenceAdmission::FreshMessage,&ObjectReferenceOwner { reference_hash:reference,wire_id:&wire,manifest_hash:&hash,selector:&wire,message_id:message,reference:&serde_json::json!({"reference":{"object_id":wire,"manifest_hash":hash,"plaintext_hash":"plaintext"}}),metadata:&serde_json::json!({"message_id":message,"object_id":wire,"owner":"peer"}) }).unwrap();
}
#[test]
fn large_restore_and_late_worker_cannot_resurrect_revoked_segments() {
    let (root, db) = crate::tests::test_db("large-retirement").unwrap();
    let (native, cipher) = fixture(0);
    bind(&db, &native, "first", "ref-first");
    bind(&db, &native, "second", "ref-second");
    let wire = ramflux_protocol::encode_base64url(native.manifest().object_id);
    let first =
        SegmentReference { selector: &wire, reference_hash: "ref-first", message_id: "first" };
    let second =
        SegmentReference { selector: &wire, reference_hash: "ref-second", message_id: "second" };
    let mut store = db.segment_store().unwrap();
    store.admit_reference("first", 1, SegmentDirection::Download, &native, &first).unwrap();
    store.admit_reference("second", 1, SegmentDirection::Upload, &native, &second).unwrap();
    store.checkpoint("second", 1, 0, 0, &cipher[0]).unwrap();
    let retained = store.location("second", 1).join("0.segment");
    let old_path = root.join("old.db");
    let old = db.write_backup_snapshot(&old_path).unwrap();
    // The actual writer owns its lease while deletion commits. Cleanup must remain debt.
    let mut observed_busy = false;
    store.during_write = Some(Box::new(|| {
        db.delete_direct_message("thread", "first", "local", "delete").unwrap();
        assert!(db.connection.query_row("SELECT EXISTS(SELECT 1 FROM object_segment_resource WHERE transfer_id='first' AND retired=1)",[],|r|r.get::<_,bool>(0)).unwrap());
    }));
    assert!(store.checkpoint("first", 1, 0, 0, &cipher[0]).is_err());
    store.during_write = None;
    observed_busy |= !store.location("first", 1).try_exists().unwrap();
    assert!(observed_busy);
    assert_eq!(fs::read(&retained).unwrap(), cipher[0]);
    assert_eq!(store.read_chunk("second", 1, 0, 0).unwrap(), cipher[0]);
    assert!(
        store.admit_reference("first", 1, SegmentDirection::Download, &native, &first).is_err()
    );
    // Advancing a live generation durably reclaims the previous generation's files.
    store.admit_reference("second", 2, SegmentDirection::Upload, &native, &second).unwrap();
    assert!(!retained.try_exists().unwrap());
    store.checkpoint("second", 2, 0, 0, &cipher[0]).unwrap();
    let live = store.location("second", 2).join("0.segment");
    // Metadata/FK deletion still leaves durable resource debt and a generation restriction.
    db.write_transaction(|| {
        db.connection
            .execute("DELETE FROM object_transfer_state WHERE transfer_id='second'", [])?;
        Ok::<_, StorageError>(())
    })
    .unwrap();
    assert!(!live.try_exists().unwrap());
    assert!(
        store.admit_reference("second", 2, SegmentDirection::Upload, &native, &second).is_err()
    );
    store.admit_reference("second", 3, SegmentDirection::Upload, &native, &second).unwrap();
    store.checkpoint("second", 3, 0, 0, &cipher[0]).unwrap();
    db.delete_direct_message("thread", "second", "local", "delete").unwrap();
    assert!(!store.location("second", 3).try_exists().unwrap());
    assert!(store.read_chunk("second", 3, 0, 0).is_err());
    // Genuine pre-registration orphan discovery is bounded and creates debt before deletion.
    let orphan = store.root.join(ramflux_protocol::encode_base64url([89; 32])).join("4");
    fs::create_dir_all(&orphan).unwrap();
    fs::write(orphan.join("0.part"), b"orphan").unwrap();
    let mut scan = store.orphan_sweep().unwrap();
    while store.discover_orphans(&mut scan, 1).unwrap() {}
    store.cleanup_retired(32).unwrap();
    assert!(!orphan.try_exists().unwrap());
    db.write_transaction(|| {
        db.connection.execute(
            "INSERT INTO runtime_attachment_reference VALUES(?1,'missing','missing',1,0)",
            params![[91_u8; 32].as_slice()],
        )?;
        db.connection.execute("DELETE FROM runtime_attachment_reference", [])?;
        db.connection.execute(
            "INSERT INTO object_segment_reference_veto VALUES(?1)",
            params![[92_u8; 32].as_slice()],
        )?;
        Ok::<_, StorageError>(())
    })
    .unwrap();
    let erased_path = root.join("erased.db");
    let erased = db.write_backup_snapshot(&erased_path).unwrap();
    drop(store);
    drop(db);
    // Both merge directions union restrictions, even with no resource/progress rows.
    for incoming_erased in [true, false] {
        let (target, key, input, input_key) = if incoming_erased {
            (&old_path, &old.key, &erased_path, &erased.key)
        } else {
            (&erased_path, &erased.key, &old_path, &old.key)
        };
        let candidate_path = root.join(format!("candidate-{incoming_erased}.db"));
        let candidate_key = crate::AccountDbKey::generate().unwrap();
        BackupDatabase::open(target, key)
            .unwrap()
            .copy_to(&candidate_path, &candidate_key)
            .unwrap();
        let mut candidate = BackupDatabase::open(&candidate_path, &candidate_key).unwrap();
        candidate.merge_backup(input, input_key, || Ok(())).unwrap();
        assert!(
            candidate
                .db
                .query_row("SELECT count(*)>=2 FROM object_segment_floor", [], |r| r
                    .get::<_, bool>(0))
                .unwrap()
        );
        assert_eq!(
            candidate
                .db
                .query_row("SELECT count(*) FROM object_segment_resource", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let second_path = root.join(format!("second-{incoming_erased}.db"));
        let second_key = crate::AccountDbKey::generate().unwrap();
        candidate.copy_to(&second_path, &second_key).unwrap();
        drop(candidate);
        let mut second_gen = BackupDatabase::open(&second_path, &second_key).unwrap();
        second_gen.merge_backup(&old_path, &old.key, || Ok(())).unwrap();
        let restored_root = root.join(format!("restored-{incoming_erased}"));
        let index = crate::AccountIndex::open(&restored_root).unwrap();
        let record = index.create_account("acct", "root").unwrap();
        assert_eq!(
            second_gen
                .db
                .query_row("SELECT count(*) FROM object_segment_reference_veto", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        let restored_key = crate::AccountDbKey::generate().unwrap();
        second_gen.copy_to(&restored_root.join(record.db_relative_path), &restored_key).unwrap();
        drop(second_gen);
        let restored = AccountDb::open(&index, "acct", &restored_key).unwrap();
        assert!(
            restored
                .segment_store()
                .unwrap()
                .admit_reference("first", 1, SegmentDirection::Download, &native, &first)
                .is_err()
        );
    }
    let db = reopen(&root);
    assert!(
        db.segment_store()
            .unwrap()
            .admit_reference("second", 3, SegmentDirection::Upload, &native, &second)
            .is_err()
    );
    cleanup_query_plan(&db);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}
fn cleanup_query_plan(db: &AccountDb) {
    // Unrelated volume touches resource, floor and all reference-join tables.
    db.write_transaction(|| { db.connection.execute_batch("WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO object_segment_resource SELECT 'unrelated-'||i,1,'other-'||i,'wire','hash','commitment',NULL,NULL,NULL,0 FROM n; WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO object_segment_floor SELECT 'unrelated-'||i,1 FROM n;")?; Ok::<_,StorageError>(()) }).unwrap();
    let mut q=db.connection.prepare("EXPLAIN QUERY PLAN SELECT directory,generation FROM object_segment_resource WHERE retired=1 AND directory>=?1 ORDER BY directory,generation LIMIT 32").unwrap();
    let plan = q
        .query_map(params![""], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(plan.iter().any(|s| s.contains("object_segment_resource_retired")));
    assert!(!plan.iter().any(|s| s.contains("SCAN") || s.contains("TEMP B-TREE")));
}
