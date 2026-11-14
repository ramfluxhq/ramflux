// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real target copy provenance, writer races and scratch lifetime; no DV/install claim.
use super::super::receiver_projection::tests::{db, input, seed};
use super::*;
use ramflux_protocol::custody::pairing::full_transfer::CHUNK_BYTES;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn pairing_full_receiver_copy_is_own_pinned_b_and_rejects_changed_writer() -> TestResult {
    let (initial, _, _) = super::super::stage_tests::fixture()?;
    let (aroot, a) = db("receiver-copy-a", &initial.grant.source_ref.account_anchor)?;
    let (broot, b) = db("receiver-copy-b", &initial.grant.destination_ref.account_anchor)?;
    b.connection.execute_batch("CREATE TRIGGER runtime_full_imported_mac_bundle_insert AFTER INSERT ON full_imported_mac_bundle BEGIN SELECT NEW.rowid; END;")?;
    b.enable_runtime()?;
    assert_eq!(b.connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'runtime_full_imported_mac_bundle_%'", [], |row| row.get::<_, u64>(0))?, 0, "old generic verifier triggers survived runtime initialization");
    seed(&a, 11, 8)?;
    seed(&b, 21, 9)?;
    let (record, manifest, bytes) = input(&a)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = b.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, index as u64, chunk)?;
    }
    let original_bundle: String = b.connection.query_row(
        "SELECT bundle_id FROM account_mac_bundle WHERE is_current=1",
        [],
        |row| row.get(0),
    )?;
    let pinned = stage.pin_receiver_base(&hash).map_err(|e| format!("pin B: {e}"))?;
    let scratch = pinned.scratch.path.clone();
    let mut copy = pinned.copy().map_err(|e| format!("copy B: {e}"))?;
    let another = stage.pin_receiver_base(&hash)?;
    assert!(scratch.exists(), "new preparation reclaimed an active receiver owner");
    drop(another);
    copy.project(&stage).map_err(|e| format!("project B: {e}"))?;
    assert_qualified_union(&copy, &original_bundle).map_err(|e| format!("qualified root: {e}"))?;
    assert_eq!(
        BackupDatabase::open_full_receiver_copy(&copy.scratch.path.join("private.db"), &copy.key)?
            .db
            .query_row("SELECT count(*) FROM object_erasure_fence", [], |row| row
                .get::<_, u64>(0))?,
        2
    );
    assert_eq!(
        b.connection.query_row("SELECT count(*) FROM object_erasure_fence", [], |row| row
            .get::<_, u64>(0))?,
        1
    );
    assert_eq!(
        stage.connection.query_row(
            "SELECT count(*) FROM manifest WHERE verified=1",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        0
    );
    assert_prepared_bytes_rechecked(&copy, &stage)?;
    seed(&b, 31, 10)?;
    assert!(copy.project(&stage).is_err(), "changed B was accepted");
    assert!(copy.projected_input().is_none() && copy.union_encoding().is_none());
    drop(copy);
    assert!(!scratch.exists(), "private scratch survived its key owner");
    let pending = stage.pin_receiver_base(&hash)?;
    let cancelledscratch = pending.scratch.path.clone();
    stage.io_cancel_handle().cancel();
    assert!(pending.copy().is_err(), "cancelled copy survived stage removal");
    assert!(!cancelledscratch.exists(), "cancelled scratch survived key erasure");
    drop(stage);
    drop(a);
    drop(b);
    std::fs::remove_dir_all(aroot)?;
    std::fs::remove_dir_all(broot)?;
    Ok(())
}

fn assert_qualified_union(copy: &FullReceiverBaseCopy, original_bundle: &str) -> TestResult {
    use ramflux_protocol::custody::pairing::full_transfer::RootHasher;
    use zeroize::Zeroizing;
    let encoded = copy.union_encoding().ok_or("missing normalized root")?;
    let db = crate::database::Connection::open(copy.scratch.path.join("contributions.db"))?;
    crate::encryption::apply_key(&db, &copy.key)?;
    let nonce = encoded.generation_nonce;
    let logical = db.call(move |db| {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut statement = db.prepare("SELECT owner,record,family FROM full_union_record WHERE generation_nonce=?1 ORDER BY owner COLLATE BINARY,family COLLATE BINARY,key COLLATE BINARY")?;
        let mut rows = statement.query(rusqlite::params![nonce.as_slice()])?;
        let mut generations = 0;
        while let Some(row) = rows.next()? {
            let owner = row.get_ref(0)?.as_str()?;
            let record = row.get_ref(1)?.as_blob()?;
            if row.get_ref(2)?.as_str()? == "sql/account_erasure_generation" {
                assert_eq!(&record[record.len()-8..], &9_i64.to_be_bytes(), "root retained a pre-merge source maximum");
                generations += 1;
            }
            let length = u32::try_from(owner.len()).map_err(|_| rusqlite::Error::InvalidQuery)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(owner.as_bytes());
            bytes.extend_from_slice(record);
        }
        assert_eq!(generations, 2, "independent source and B contributions were collapsed");
        Ok(bytes)
    })?;
    assert_eq!(logical.len() as u64, encoded.total_bytes);
    let mut root = RootHasher::new(encoded.total_bytes)?;
    for (index, chunk) in logical.chunks(CHUNK_BYTES as usize).enumerate() {
        root.push(index as u64, chunk)?;
    }
    assert_eq!(root.finish()?, encoded.chunks_root);
    let private =
        BackupDatabase::open_full_receiver_copy(&copy.scratch.path.join("private.db"), &copy.key)?;
    let current: String = private.db.query_row(
        "SELECT bundle_id FROM account_mac_bundle WHERE is_current=1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        current, original_bundle,
        "private opener rotated or discarded B's current MAC owner"
    );
    Ok(())
}

fn assert_prepared_bytes_rechecked(
    copy: &FullReceiverBaseCopy,
    stage: &FullTransferStage<'_>,
) -> TestResult {
    copy.verify_materialization(stage)?;
    let private =
        BackupDatabase::open_full_receiver_copy(&copy.scratch.path.join("private.db"), &copy.key)?;
    let before = copy.union_encoding().ok_or("root")?.chunks_root;
    let old = ramflux_protocol::encode_base64url([21; 32]);
    let replacement = ramflux_protocol::encode_base64url([99; 32]);
    private.db.execute(
        "UPDATE object_payload_dependency SET parent_commitment=?1 WHERE parent_commitment=?2",
        rusqlite::params![replacement, old],
    )?;
    assert!(
        copy.verify_materialization(stage).is_err(),
        "same-count replacement of prepared B data was accepted"
    );
    assert_eq!(
        copy.union_encoding().ok_or("root")?.chunks_root,
        before,
        "test changed metadata rather than prepared bytes"
    );
    private.db.execute(
        "UPDATE object_payload_dependency SET parent_commitment=?1 WHERE parent_commitment=?2",
        rusqlite::params![old, replacement],
    )?;
    copy.verify_materialization(stage)?;
    Ok(())
}
