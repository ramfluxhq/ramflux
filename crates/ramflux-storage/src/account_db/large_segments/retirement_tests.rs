// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::{
    tests::{fixture, reopen},
    *,
};
use crate::{BackupDatabase, ObjectReferenceAdmission, ObjectReferenceOwner, ObjectWrite};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::params;
use std::fs;
pub(super) fn bind(db: &AccountDb, m: &VerifiedContentManifest, message: &str, reference: &str) {
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
    store.admit_reference("second", 2, SegmentDirection::Download, &native, &second).unwrap();
    store.checkpoint("second", 2, 0, 0, &cipher[0]).unwrap();
    let retained = store.location("second", 2).join("0.segment");
    let old_path = root.join("old.db");
    let old = db.write_backup_snapshot(&old_path).unwrap();
    let archive = BackupDatabase::open(&old_path, &old.key).unwrap();
    assert_eq!(
        archive
            .db
            .query_row("SELECT count(*) FROM object_segment_resource", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        archive
            .db
            .query_row(
                "SELECT sum(received_bitmap+cipher_verified) FROM object_segment_file",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    drop(archive);
    // The actual writer owns its lease while deletion commits. Cleanup must remain debt.
    store.during_write = Some(Box::new(|| {
        db.delete_direct_message("thread", "first", "local", "delete").unwrap();
        assert!(db.connection.query_row("SELECT EXISTS(SELECT 1 FROM object_segment_resource WHERE transfer_id='first' AND retired=1)",[],|r|r.get::<_,bool>(0)).unwrap());
    }));
    assert!(matches!(
        store.checkpoint("first", 1, 0, 0, &cipher[0]),
        Err(StorageError::ObjectErased)
    ));
    store.during_write = None;
    assert!(!store.location("first", 1).try_exists().unwrap());
    assert_eq!(fs::read(&retained).unwrap(), cipher[0]);
    assert_eq!(store.read_chunk("second", 2, 0, 0).unwrap(), cipher[0]);
    assert!(matches!(
        store.admit_reference("first", 1, SegmentDirection::Download, &native, &first),
        Err(StorageError::ObjectErased)
    ));
    // Advancing a live generation durably reclaims the previous generation's files.
    store.admit_reference("second", 3, SegmentDirection::Download, &native, &second).unwrap();
    assert!(!retained.try_exists().unwrap());
    store.checkpoint("second", 3, 0, 0, &cipher[0]).unwrap();
    let live = store.location("second", 3).join("0.segment");
    // Metadata/FK deletion still leaves durable resource debt and a generation restriction.
    db.write_transaction(|| {
        db.connection
            .execute("DELETE FROM object_transfer_state WHERE transfer_id='second'", [])?;
        Ok::<_, StorageError>(())
    })
    .unwrap();
    store.cleanup_retired(32).unwrap();
    assert!(!live.try_exists().unwrap());
    assert!(matches!(
        store.admit_reference("second", 3, SegmentDirection::Download, &native, &second),
        Err(StorageError::ObjectErased)
    ));
    store.admit_reference("second", 4, SegmentDirection::Download, &native, &second).unwrap();
    store.checkpoint("second", 4, 0, 0, &cipher[0]).unwrap();
    db.delete_direct_message("thread", "second", "local", "delete").unwrap();
    store.cleanup_retired(32).unwrap();
    assert!(!store.location("second", 4).try_exists().unwrap());
    assert!(matches!(
        store.read_chunk("second", 4, 0, 0),
        Err(StorageError::ObjectIdentityConflict)
    ));
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
        let record = index.create_account("acct", "principal").unwrap();
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
        assert_eq!(restored.segment_store().unwrap().resource_count().unwrap(), 0);
        assert!(matches!(
            restored.segment_store().unwrap().admit_reference(
                "first",
                1,
                SegmentDirection::Download,
                &native,
                &first
            ),
            Err(StorageError::ObjectErased)
        ));
    }
    let db = reopen(&root);
    assert!(matches!(
        db.segment_store().unwrap().admit_reference(
            "second",
            4,
            SegmentDirection::Download,
            &native,
            &second
        ),
        Err(StorageError::ObjectErased)
    ));
    cleanup_query_plan(&db);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}
fn cleanup_query_plan(db: &AccountDb) {
    // Every hot admission/cleanup join carries unrelated tenant-local volume.
    db.write_transaction(|| {
        for i in 0..1000u32 {
            let dir=ramflux_protocol::encode_base64url(blake3::hash(&i.to_le_bytes()).as_bytes());
            let key=format!("unrelated-{i}");
            db.connection.execute("INSERT INTO object_segment_reference_veto VALUES(?1)",params![blake3::hash(&i.to_le_bytes()).as_bytes().as_slice()])?;
            db.connection.execute("INSERT INTO object_segment_resource VALUES(?1,2,?2,'wire','hash',?2,NULL,NULL,NULL,0)",params![dir,key])?;
            db.connection.execute("INSERT INTO object_segment_floor VALUES(?1,1)",params![dir])?;
            db.connection.execute("INSERT INTO object_retention_payload VALUES(?1,?1,?1,?1,'message',NULL,0)",params![key])?;
            db.connection.execute("INSERT INTO object_retention_reference VALUES(?1,?1,?1,?1,'{}')",params![key])?;
            db.connection.execute("INSERT INTO object_message_reference VALUES(?1,?1,'{}')",params![key])?;
        }
        Ok::<_,StorageError>(())
    }).unwrap();
    for sql in [
        "EXPLAIN QUERY PLAN SELECT generation FROM object_segment_floor WHERE directory='probe'",
        "EXPLAIN QUERY PLAN SELECT 1 FROM object_segment_reference_veto WHERE reference_id=x'01'",
        "EXPLAIN QUERY PLAN SELECT 1 FROM object_retention_payload WHERE commitment='probe' AND owner_count>0",
        "EXPLAIN QUERY PLAN SELECT 1 FROM object_retention_payload WHERE commitment='probe' AND retention_class='pre_send' AND hold_expires_at>1",
        "EXPLAIN QUERY PLAN SELECT retired FROM object_segment_resource WHERE directory='probe' AND generation=1",
        "EXPLAIN QUERY PLAN SELECT 1 FROM object_message_reference m JOIN object_retention_reference r USING(reference_hash) JOIN object_retention_payload p USING(commitment) WHERE m.message_id='probe' AND m.reference_hash='probe' AND r.selector='probe' AND p.wire_id='probe' AND p.manifest_hash='probe'",
    ] {
        let mut statement = db.connection.prepare(sql).unwrap();
        let plan = statement
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(!plan.iter().any(|s| s.contains("SCAN") || s.contains("TEMP B-TREE")), "{plan:?}");
    }
    // The admission budget is recounted from local debt, including retired rows.
    let used = db.segment_store().unwrap().resource_count().unwrap();
    db.write_transaction(|| {
        for i in used..super::retirement::RESOURCE_LIMIT {
            let dir=ramflux_protocol::encode_base64url(blake3::hash(format!("capacity-{i}").as_bytes()).as_bytes());
            db.connection.execute("INSERT INTO object_segment_resource VALUES(?1,1,NULL,'wire','hash','commitment',NULL,NULL,NULL,0)",params![dir])?;
        }
        Ok::<_,StorageError>(())
    }).unwrap();
    assert_eq!(db.segment_store().unwrap().resource_count().unwrap(), 4096);
    assert!(matches!(
        super::retirement::check_capacity(&db.connection),
        Err(StorageError::SegmentResourceCapacity { limit: 4096 })
    ));
    let (native, _) = fixture(1);
    bind(db, &native, "capacity-live", "capacity-reference");
    let wire = ramflux_protocol::encode_base64url(native.manifest().object_id);
    let reference = SegmentReference {
        selector: &wire,
        reference_hash: "capacity-reference",
        message_id: "capacity-live",
    };
    assert!(matches!(
        db.segment_store().unwrap().admit_reference(
            "over-capacity",
            1,
            SegmentDirection::Download,
            &native,
            &reference
        ),
        Err(StorageError::SegmentResourceCapacity { limit: 4096 })
    ));
    let mut q=db.connection.prepare("EXPLAIN QUERY PLAN SELECT directory,generation FROM object_segment_resource WHERE retired=1 AND directory>=?1 ORDER BY directory,generation LIMIT 32").unwrap();
    let plan = q
        .query_map(params![""], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(plan.iter().any(|s| s.contains("object_segment_resource_retired")));
    assert!(!plan.iter().any(|s| s.contains("SCAN") || s.contains("TEMP B-TREE")));
}

#[test]
fn pinned_segment_reader_observes_current_retirement_floor() {
    let (root, db) = crate::tests::test_db("large-pinned-reader").unwrap();
    let (native, cipher) = fixture(0);
    bind(&db, &native, "message", "reference");
    let wire = ramflux_protocol::encode_base64url(native.manifest().object_id);
    let reference =
        SegmentReference { selector: &wire, reference_hash: "reference", message_id: "message" };
    let mut store = db.segment_store().unwrap();
    store.admit_reference("transfer", 1, SegmentDirection::Download, &native, &reference).unwrap();
    store.checkpoint("transfer", 1, 0, 0, &cipher[0]).unwrap();
    let reader = db.open_reader().unwrap();
    let snapshot = reader.connection.deferred_transaction().unwrap();
    let mut pinned = reader.segment_store().unwrap();
    assert_eq!(pinned.read_chunk("transfer", 1, 0, 0).unwrap(), cipher[0]);
    store.admit_reference("transfer", 2, SegmentDirection::Download, &native, &reference).unwrap();
    assert!(matches!(pinned.read_chunk("transfer", 1, 0, 0), Err(StorageError::ObjectErased)));
    assert!(matches!(
        pinned.checkpoint("transfer", 1, 0, 0, &cipher[0]),
        Err(StorageError::ObjectErased)
    ));
    assert!(!store.location("transfer", 1).try_exists().unwrap());
    drop(pinned);
    drop(snapshot);
    drop(reader);
    drop(store);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn provisional_segments_follow_hold_release_and_expiry() {
    let (root, db) = crate::tests::test_db("large-provisional").unwrap();
    let (original, cipher) = fixture(0);
    let key = SigningKey::from_bytes(&[77; 32]);
    let mut m = original.manifest().clone();
    m.owner.account_anchor = db.principal_commitment.clone();
    m.owner.signing_public_key = key.verifying_key().to_bytes();
    let signature = key.sign(&m.signing_bytes().unwrap()).to_bytes();
    let native = ramflux_protocol::large_attachment::ContentManifest::decode_signed(
        &m.signed_bytes(&signature).unwrap(),
    )
    .unwrap();
    let wire = ramflux_protocol::encode_base64url(m.object_id);
    let hash = ramflux_protocol::encode_base64url(m.hash().unwrap());
    let hold = db.pre_send_object_hold(&wire, &hash).unwrap();
    let mut store = db.segment_store().unwrap();
    store.admit_pre_send("upload", 1, &native, &hold).unwrap();
    store.checkpoint("upload", 1, 0, 0, &cipher[0]).unwrap();
    let path = store.location("upload", 1);
    hold.release().unwrap();
    store.cleanup_retired(32).unwrap();
    assert!(!path.try_exists().unwrap());
    assert!(matches!(
        store.read_chunk("upload", 1, 0, 0),
        Err(StorageError::ObjectIdentityConflict)
    ));
    let mut other = m.clone();
    other.object_id = [99; 32];
    let signature = key.sign(&other.signing_bytes().unwrap()).to_bytes();
    let other = ramflux_protocol::large_attachment::ContentManifest::decode_signed(
        &other.signed_bytes(&signature).unwrap(),
    )
    .unwrap();
    let wire2 = ramflux_protocol::encode_base64url(other.manifest().object_id);
    let hash2 = ramflux_protocol::encode_base64url(other.manifest().hash().unwrap());
    let hold2 = db.pre_send_object_hold(&wire2, &hash2).unwrap();
    store.admit_pre_send("expired", 1, &other, &hold2).unwrap();
    store.checkpoint("expired", 1, 0, 0, &cipher[0]).unwrap();
    assert!(store.location("expired", 1).join("0.segment").is_file());
    db.write_transaction(|| {
        db.connection.execute(
            "UPDATE object_retention_payload SET hold_expires_at=?1 WHERE wire_id=?2",
            params![db.now_unix() - 1, wire2],
        )?;
        Ok::<_, StorageError>(())
    })
    .unwrap();
    assert!(matches!(
        store.checkpoint("expired", 1, 0, 0, &cipher[0]),
        Err(StorageError::ObjectErased)
    ));
    db.maintain_expired_object_holds().unwrap();
    store.cleanup_retired(32).unwrap();
    assert!(!store.location("expired", 1).try_exists().unwrap());
    drop(hold2);
    let mut converted = m.clone();
    converted.object_id = [100; 32];
    let signature = key.sign(&converted.signing_bytes().unwrap()).to_bytes();
    let converted = ramflux_protocol::large_attachment::ContentManifest::decode_signed(
        &converted.signed_bytes(&signature).unwrap(),
    )
    .unwrap();
    let wire3 = ramflux_protocol::encode_base64url(converted.manifest().object_id);
    let hash3 = ramflux_protocol::encode_base64url(converted.manifest().hash().unwrap());
    let hold3 = db.pre_send_object_hold(&wire3, &hash3).unwrap();
    store.admit_pre_send("converted", 1, &converted, &hold3).unwrap();
    store.checkpoint("converted", 1, 0, 0, &cipher[0]).unwrap();
    bind(&db, &converted, "converted-message", "converted-reference");
    hold3.release().unwrap();
    assert_eq!(store.read_chunk("converted", 1, 0, 0).unwrap(), cipher[0]);
    db.delete_direct_message("thread", "converted-message", "local", "delete").unwrap();
    store.cleanup_retired(32).unwrap();
    assert!(!store.location("converted", 1).try_exists().unwrap());
    drop(store);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}
