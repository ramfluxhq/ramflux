// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::files::CrashPoint;
use super::*;
use crate::{AccountDbKey, AccountIndex};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use std::fs;
fn fixture(case: usize) -> (VerifiedContentManifest, Vec<Vec<u8>>) {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/tests/fixtures/large_attachment_v1.json"
    ))
    .unwrap();
    let value = &vectors["cases"][case];
    let decode = |field: &str| {
        value[field]
            .as_str()
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let mc = decode("content_manifest_unsigned_hex");
    let mut signed = Vec::new();
    signed.extend_from_slice(&u32::try_from(mc.len()).unwrap().to_be_bytes());
    signed.extend(mc);
    signed.extend_from_slice(&64_u32.to_be_bytes());
    signed.extend(decode("content_signature_hex"));
    let verified =
        ramflux_protocol::large_attachment::ContentManifest::decode_signed(&signed).unwrap();
    let manifest = verified.manifest();
    let key = decode("file_key_hex");
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let mut offset = 0;
    let mut ciphertexts = Vec::new();
    for index in 0..manifest.segment_digests.len() {
        let len = usize::try_from(manifest.layout.segment_plaintext_length(index as u64).unwrap())
            .unwrap();
        let plaintext: Vec<u8> =
            (offset..offset + len).map(|j| u8::try_from(j % 251).unwrap()).collect();
        offset += len;
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&(index as u64).to_be_bytes());
        let bytes = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &manifest
                        .layout
                        .associated_data(&manifest.object_id, index as u64)
                        .unwrap(),
                },
            )
            .unwrap();
        assert_eq!(
            ramflux_crypto::large_attachment::segment_digest(&bytes).unwrap(),
            manifest.segment_digests[index]
        );
        ciphertexts.push(bytes);
    }
    (verified, ciphertexts)
}
fn raw_progress(db: &AccountDb, id: &str) -> (u8, bool, i64, u64) {
    db.connection.query_row("SELECT f.received_bitmap,f.cipher_verified,t.done_bytes,t.segment_sequence FROM object_segment_file f JOIN object_transfer_state t USING(transfer_id) WHERE transfer_id=?1 ORDER BY f.segment_index LIMIT 1",params![id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
}
fn reopen(root: &std::path::Path) -> AccountDb {
    let index = AccountIndex::open(root).unwrap();
    AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret")).unwrap()
}
#[test]
fn large_segment_checkpoint_survives_crash_without_phantom_bytes() {
    let (manifest, ciphertexts) = fixture(1);
    let ciphertext = &ciphertexts[0];
    for point in
        [CrashPoint::Written, CrashPoint::Synced, CrashPoint::Renamed, CrashPoint::Committed]
    {
        let (root, db) = crate::tests::test_db("large-segment-crash").unwrap();
        let mut store = db.segment_store().unwrap();
        store.admit("transfer", 1, SegmentDirection::Download, &manifest).unwrap();
        let directory = store.directory("transfer", 1).unwrap();
        store.crash = Some(point);
        assert!(store.checkpoint("transfer", 1, 0, 0, ciphertext).is_err());
        let acknowledged = point == CrashPoint::Committed;
        assert_eq!(
            raw_progress(&db, "transfer"),
            (
                u8::from(acknowledged),
                acknowledged,
                if acknowledged { i64::try_from(ciphertext.len()).unwrap() } else { 0 },
                u64::from(acknowledged)
            )
        );
        let path =
            directory.join(if matches!(point, CrashPoint::Renamed | CrashPoint::Committed) {
                "0.segment"
            } else {
                "0.part"
            });
        // Independent filesystem oracle observes the complete expected bytes,
        // including data written before the bitmap transaction was reached.
        assert_eq!(fs::read(path).unwrap(), *ciphertext);
        drop(store);
        drop(db);
        let db = reopen(&root);
        let mut store = db.segment_store().unwrap();
        let page = store.page("transfer", 1, 0, 1).unwrap();
        let recovered = matches!(point, CrashPoint::Renamed | CrashPoint::Committed);
        assert_eq!(page[0].cipher_verified, recovered);
        assert_eq!(page[0].received_bitmap, u8::from(recovered));
        store.checkpoint("transfer", 1, 0, 0, ciphertext).unwrap();
        let sequence = store.sequence("transfer", 1).unwrap();
        store.checkpoint("transfer", 1, 0, 0, ciphertext).unwrap();
        assert_eq!(store.sequence("transfer", 1).unwrap(), sequence);
        assert_eq!(store.read_chunk("transfer", 1, 0, 0).unwrap(), *ciphertext);
        let mut conflict = ciphertext.clone();
        conflict[0] ^= 1;
        assert!(store.checkpoint("transfer", 1, 0, 0, &conflict).is_err());
        assert!(store.read_chunk("transfer", 1, 0, 1).is_err());
        assert_eq!(fs::read(directory.join("0.segment")).unwrap(), *ciphertext);
        assert_eq!(raw_progress(&db, "transfer").2, i64::try_from(ciphertext.len()).unwrap());
        drop(store);
        drop(db);
        fs::remove_dir_all(root).unwrap();
    }
    let (manifest, ciphertexts) = fixture(4); // Full segment + authenticated tail.
    let (root, db) = crate::tests::test_db("large-segment-pages").unwrap();
    let mut store = db.segment_store().unwrap();
    store.admit("transfer", 1, SegmentDirection::Upload, &manifest).unwrap();
    assert!(store.page("transfer", 1, 0, 0).is_err());
    assert!(store.page("transfer", 1, 0, 129).is_err());
    assert_eq!(store.page("transfer", 1, 0, 1).unwrap()[0].index, 0);
    assert_eq!(store.page("transfer", 1, 1, 1).unwrap()[0].index, 1);
    assert_eq!(store.page("transfer", 1, 2, 1).unwrap(), Vec::<SegmentPageEntry>::new());
    assert!(store.admit("duplicate", 1, SegmentDirection::Upload, &manifest).is_err());
    let mut plan=db.connection.prepare("EXPLAIN QUERY PLAN SELECT segment_index FROM object_segment_file WHERE transfer_id=?1 AND generation=?2 AND segment_index>=?3 ORDER BY segment_index LIMIT ?4").unwrap();
    let details = plan
        .query_map(params!["transfer", 1, 0, 1], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(details.iter().any(|line| line.contains("sqlite_autoindex_object_segment_file_1")
        || line.contains("PRIMARY KEY")));
    assert!(details.iter().all(|line| !line.contains("SCAN object_segment_file")));
    drop(plan);
    let chunk = manifest.manifest().layout.network_chunk_bytes as usize;
    store.checkpoint("transfer", 1, 0, 0, &ciphertexts[0][..chunk]).unwrap();
    assert_eq!(raw_progress(&db, "transfer").0, 1);
    let directory = store.directory("transfer", 1).unwrap();
    fs::write(directory.join("0.part"), [1, 2]).unwrap();
    drop(store);
    let mut store = db.segment_store().unwrap();
    assert_eq!(store.page("transfer", 1, 0, 1).unwrap()[0].received_bitmap, 0);
    assert_eq!(raw_progress(&db, "transfer").2, 0);
    for (index, bytes) in ciphertexts.iter().enumerate() {
        for (part, data) in bytes.chunks(chunk).enumerate() {
            store
                .checkpoint(
                    "transfer",
                    1,
                    u32::try_from(index).unwrap(),
                    u32::try_from(part).unwrap(),
                    data,
                )
                .unwrap();
        }
    }
    assert_eq!(
        store.page("transfer", 1, 0, 2).unwrap().iter().filter(|r| r.cipher_verified).count(),
        2
    );
    // Corruption with unchanged length must not survive restart/reconciliation.
    let mut corrupt = ciphertexts[0].clone();
    corrupt[0] ^= 1;
    fs::write(directory.join("0.segment"), corrupt).unwrap();
    drop(store);
    drop(db);
    let db = reopen(&root);
    let mut store = db.segment_store().unwrap();
    assert!(!store.page("transfer", 1, 0, 1).unwrap()[0].cipher_verified);
    assert_eq!(raw_progress(&db, "transfer").0, 0);
    assert!(store.page("transfer", 1, 1, 1).unwrap()[0].cipher_verified);
    store.admit("transfer", 2, SegmentDirection::Upload, &manifest).unwrap();
    assert!(store.checkpoint("transfer", 1, 0, 0, &ciphertexts[0][..chunk]).is_err());
    assert!(store.page("transfer", 1, 0, 1).is_err());
    assert!(store.admit("transfer", 1, SegmentDirection::Upload, &manifest).is_err());
    assert_eq!(
        store.page("transfer", 2, 0, 2).unwrap().iter().map(|r| r.received_bitmap).sum::<u8>(),
        0
    );
    // Payload bytes never enter the old whole-object BLOB route.
    let blobs: i64 =
        db.connection.query_row("SELECT COUNT(*) FROM object_index", [], |r| r.get(0)).unwrap();
    assert_eq!(blobs, 0);
    drop(store);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn large_partial_restart_rejects_same_length_corruption_and_invalid_lengths() {
    let (manifest, ciphertexts) = fixture(4);
    let (root, db) = crate::tests::test_db("large-part-restart").unwrap();
    let mut store = db.segment_store().unwrap();
    store.admit("transfer", 1, SegmentDirection::Download, &manifest).unwrap();
    let chunk = manifest.manifest().layout.network_chunk_bytes as usize;
    store.checkpoint("transfer", 1, 0, 0, &ciphertexts[0][..chunk]).unwrap();
    let path = store.location("transfer", 1).join("0.part");
    let mut corrupt = fs::read(&path).unwrap();
    corrupt[17] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), chunk as u64);
    drop(store);
    drop(db);
    let db = reopen(&root);
    let store = db.segment_store().unwrap();
    assert_eq!(raw_progress(&db, "transfer").0, 0);
    assert_eq!(raw_progress(&db, "transfer").2, 0);
    drop(store);
    // Ignore SQL CHECK only to model at-rest corruption, not a supported writer.
    db.connection.execute_batch("PRAGMA ignore_check_constraints=ON;").unwrap();
    for len in [-1_i64, 0, 15, 4_194_305, i64::MAX] {
        db.connection
            .execute(
                "UPDATE object_segment_file SET expected_length=?1 WHERE segment_index=0",
                params![len],
            )
            .unwrap();
        assert!(matches!(
            db.segment_store(),
            Err(StorageError::Integrity("segment expected length"))
        ));
    }
    drop(db);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn large_transfer_lease_protects_inflight_part_and_reads_only_requested_chunk() {
    let (manifest, ciphertexts) = fixture(4);
    let (root, db) = crate::tests::test_db("large-transfer-owner").unwrap();
    let observed = std::cell::Cell::new(false);
    let mut store = db.segment_store().unwrap();
    store.admit("transfer", 1, SegmentDirection::Download, &manifest).unwrap();
    let path = store.directory("transfer", 1).unwrap().join("0.part");
    store.during_write = Some(Box::new(|| {
        assert!(matches!(db.segment_store(), Err(StorageError::AccountWriterBusy(_))));
        observed.set(true);
    }));
    let chunk = manifest.manifest().layout.network_chunk_bytes as usize;
    store.checkpoint("transfer", 1, 0, 0, &ciphertexts[0][..chunk]).unwrap();
    assert!(observed.get());
    assert!(path.exists());
    store.during_write = None;
    for (index, bytes) in ciphertexts[0].chunks(chunk).enumerate().skip(1) {
        store.checkpoint("transfer", 1, 0, u32::try_from(index).unwrap(), bytes).unwrap();
    }
    let final_path = store.location("transfer", 1).join("0.segment");
    let mut bytes = fs::read(&final_path).unwrap();
    bytes[chunk + 11] ^= 1;
    fs::write(&final_path, &bytes).unwrap();
    // A chunk-0 read neither rehashes nor repairs chunk 1. Its own digest still verifies.
    assert_eq!(store.read_chunk("transfer", 1, 0, 0).unwrap(), ciphertexts[0][..chunk]);
    assert!(matches!(
        store.read_chunk("transfer", 1, 0, 1),
        Err(StorageError::Integrity("segment chunk hash"))
    ));
    assert_eq!(fs::read(final_path).unwrap(), bytes);
    drop(store);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}

fn historical_segment_schema(db: &AccountDb) {
    let mut stmt=db.connection.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='object_transfer_state'").unwrap();
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for name in names {
        db.connection
            .execute_batch(&format!("DROP TRIGGER \"{}\"", name.replace('"', "\"\"")))
            .unwrap();
    }
    db.connection.execute_batch("DROP TABLE object_segment_file; DROP INDEX idx_segment_transfer_identity; ALTER TABLE object_transfer_state DROP COLUMN segment_generation; ALTER TABLE object_transfer_state DROP COLUMN segment_sequence; ALTER TABLE object_transfer_state DROP COLUMN segment_manifest;").unwrap();
}

#[test]
fn large_backup_merge_upgrades_old_shapes_without_importing_physical_progress() {
    let (manifest, ciphertexts) = fixture(1);
    for source_new in [false, true] {
        for target_new in [false, true] {
            let (source_root, source) = crate::tests::test_db("large-backup-source").unwrap();
            let (target_root, target) = crate::tests::test_db("large-backup-target").unwrap();
            for (db, new, id) in
                [(&source, source_new, "source-transfer"), (&target, target_new, "target-transfer")]
            {
                let present:bool=db.connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='object_segment_file')",[],|r|r.get(0)).unwrap();
                assert!(present, "normal open must install the additive schema");
                if new {
                    let mut store = db.segment_store().unwrap();
                    store.admit(id, 1, SegmentDirection::Download, &manifest).unwrap();
                    store.checkpoint(id, 1, 0, 0, &ciphertexts[0]).unwrap();
                } else {
                    historical_segment_schema(db);
                }
            }
            source.connection.execute_batch("INSERT INTO object_transfer_state(transfer_id,object_id,peer_device_id,manifest_hash,missing_chunk_bitmap,completed_chunk_bitmap,state,updated_at) VALUES('generic-source','generic-object','peer',x'01',x'5b5d',x'5b5d','idle',1);").unwrap();
            let incoming = source_root.join("incoming.db");
            let source_snapshot = source.write_backup_snapshot(&incoming).unwrap();
            let merged_path = target_root.join("merged.db");
            let target_snapshot = target.write_backup_snapshot(&merged_path).unwrap();
            let mut merged =
                crate::BackupDatabase::open(&merged_path, &target_snapshot.key).unwrap();
            merged.merge_backup(&incoming, &source_snapshot.key, || Ok(())).unwrap();
            let imported: u64 = merged
                .db
                .query_row(
                    "SELECT count(*) FROM object_segment_file WHERE transfer_id='source-transfer'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(imported, 0);
            let local: u64 = merged
                .db
                .query_row(
                    "SELECT count(*) FROM object_segment_file WHERE transfer_id='target-transfer'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(local, u64::from(target_new));
            let active:u64=merged.db.query_row("SELECT count(*) FROM object_transfer_state WHERE transfer_id='source-transfer'",[],|r|r.get(0)).unwrap();
            assert_eq!(active, 0);
            let generic:(Option<u64>,Option<Vec<u8>>,u64)=merged.db.query_row("SELECT segment_generation,segment_manifest,segment_sequence FROM object_transfer_state WHERE transfer_id='generic-source'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
            assert_eq!(generic, (None, None, 0));
            drop(merged);
            drop(source);
            drop(target);
            fs::remove_dir_all(source_root).unwrap();
            fs::remove_dir_all(target_root).unwrap();
        }
    }
}
