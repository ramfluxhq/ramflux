// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real source cut -> signed retained slots -> PRIVATE B projection. No SAS/native/DV claim.
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase};
use ramflux_crypto::custody::pairing::FullResumeRecord;
use ramflux_protocol::{custody::pairing::full_transfer::*, encode_base64url};
use std::sync::{Arc, atomic::AtomicBool};
use zeroize::Zeroizing;
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn h(n: u8) -> String {
    encode_base64url([n; 32])
}
pub(in crate::account_db::full_transfer) fn db(
    label: &str,
    anchor: &str,
) -> ResultOf<(ramflux_test_support::TestPath, AccountDb)> {
    let root = crate::tests::temp_root(label);
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", anchor)?;
    Ok((root, AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", label.as_bytes()))?))
}
pub(in crate::account_db::full_transfer) fn input(
    source: &AccountDb,
) -> ResultOf<(FullResumeRecord, SourceManifest, Zeroizing<Vec<u8>>)> {
    let (mut record, mut manifest, _) = super::super::stage_tests::fixture()?;
    let mut prep = source.prepare_full_transfer_source()?;
    prep.capture_base_cut(&manifest.manifest.snapshot_id)?;
    let (bytes, encoded) =
        prep.encode_fixed_base_source(&manifest.manifest.snapshot_id, Vec::new())?;
    manifest.manifest.families = encoded.schema.families.clone();
    manifest.manifest.census_hash = encode_base64url(encoded.schema.census_hash);
    manifest.manifest.total_bytes = U64(encoded.total_bytes);
    manifest.manifest.chunk_count = U64(encoded.chunk_count);
    manifest.manifest.chunks_root = encode_base64url(encoded.chunks_root);
    manifest.manifest.storage_generation = U64(encoded.storage_generation);
    manifest.manifest.source_erasure_generation = U64(encoded.source_erasure_generation);
    manifest.source_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &manifest.manifest.signing_bytes()?,
        [7; 32],
    );
    record.base_manifest_hash = encode_base64url(manifest_hash(&manifest)?);
    Ok((record, manifest, Zeroizing::new(bytes)))
}
pub(in crate::account_db::full_transfer) fn seed(
    db: &AccountDb,
    n: u8,
    generation: u64,
) -> ResultOf {
    db.connection
        .execute("INSERT INTO object_erasure_fence VALUES(?1)", rusqlite::params![h(n)])?;
    db.connection.execute(
        "INSERT INTO object_payload_dependency VALUES(?1,?2)",
        rusqlite::params![h(n), h(n + 1)],
    )?;
    db.connection.execute(
        "UPDATE account_erasure_generation SET generation=?1",
        rusqlite::params![generation],
    )?;
    Ok(())
}
#[test]
fn pairing_full_receiver_fixed_projection_consumes_signed_slots_and_preserves_live_target()
-> ResultOf {
    let (initial, _, _) = super::super::stage_tests::fixture()?;
    let (aroot, a) = db("receiver-project-source", &initial.grant.source_ref.account_anchor)?;
    let (broot, b) = db("receiver-project-target", &initial.grant.destination_ref.account_anchor)?;
    seed(&a, 11, 8)?;
    seed(&b, 21, 9)?;
    let (record, manifest, bytes) = input(&a)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = b.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (i, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, i as u64, chunk)?;
    }
    let (cut, observation) = b.pin_full_transfer_target()?;
    let path = broot.join("private-projection.db");
    let snapshot = cut.write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    let mut private = BackupDatabase::open(&path, &snapshot.key)?;
    let counts = stage.project_forward_fixed_base(&hash, &mut private, &observation)?;
    assert_eq!(counts.encoded_bytes, bytes.len() as u64);
    assert_eq!(
        private
            .db
            .query_row("SELECT count(*) FROM object_erasure_fence", [], |r| r.get::<_, u64>(0))?,
        2
    );
    assert_eq!(
        private.db.query_row("SELECT count(*) FROM object_payload_dependency", [], |r| r
            .get::<_, u64>(0))?,
        2
    );
    assert_eq!(
        private.db.query_row("SELECT generation FROM account_erasure_generation", [], |r| r
            .get::<_, u64>(0))?,
        9
    );
    assert_eq!(
        b.connection
            .query_row("SELECT count(*) FROM object_erasure_fence", [], |r| r.get::<_, u64>(0))?,
        1,
        "private projection changed live B"
    );
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM manifest WHERE verified=1", [], |r| r
                .get::<_, u64>(0))?,
        0,
        "projection incorrectly marked semantic acceptance"
    );
    // Repeat checks exact bytes and idempotent fixed merge, not a cached input marker.
    stage.project_forward_fixed_base(&hash, &mut private, &observation)?;
    b.connection
        .execute("INSERT INTO object_erasure_fence VALUES(?1)", rusqlite::params![h(31)])?;
    assert!(
        stage.project_forward_fixed_base(&hash, &mut private, &observation).is_err(),
        "changed B accepted old baseline"
    );
    drop(private);
    drop(stage);
    drop(a);
    drop(b);
    std::fs::remove_dir_all(aroot)?;
    std::fs::remove_dir_all(broot)?;
    Ok(())
}
#[test]
fn pairing_full_receiver_fixed_projection_conflict_rolls_back_earlier_restrictions() -> ResultOf {
    let (initial, _, _) = super::super::stage_tests::fixture()?;
    let (aroot, a) = db("receiver-project-conflict-a", &initial.grant.source_ref.account_anchor)?;
    let (broot, b) =
        db("receiver-project-conflict-b", &initial.grant.destination_ref.account_anchor)?;
    seed(&a, 11, 8)?;
    seed(&b, 21, 9)?;
    for (db, value) in [(&a, 11), (&b, 21)] {
        db.connection.execute(
            "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
            rusqlite::params![h(30), h(value)],
        )?;
    }
    let (record, manifest, bytes) = input(&a)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = b.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (i, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, i as u64, chunk)?;
    }
    let (cut, observation) = b.pin_full_transfer_target()?;
    let path = broot.join("private-conflict.db");
    let snapshot = cut.write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    let mut private = BackupDatabase::open(&path, &snapshot.key)?;
    assert!(matches!(
        stage.project_forward_fixed_base(&hash, &mut private, &observation),
        Err(crate::StorageError::PairingField("TransferConflict"))
    ));
    assert!(private.db.is_autocommit(), "failed projection retained transaction");
    assert_eq!(
        private
            .db
            .query_row("SELECT count(*) FROM object_erasure_fence", [], |r| r.get::<_, u64>(0))?,
        1,
        "failed projection retained prior restrictive source rows"
    );
    assert_eq!(
        private.db.query_row(
            "SELECT commitment FROM object_erasure_lookup WHERE lookup=?1",
            [h(30)],
            |r| r.get::<_, String>(0)
        )?,
        h(21)
    );
    drop(private);
    drop(stage);
    drop(a);
    drop(b);
    std::fs::remove_dir_all(aroot)?;
    std::fs::remove_dir_all(broot)?;
    Ok(())
}
