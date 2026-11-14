// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source work lifetime and exact local cut replay; no SAS/native admission shortcut claim.
use super::*;
use crate::account_db::full_transfer::{
    receiver_projection::tests::{db, input, seed},
    source_owner::SourceMetadataKey as _,
};
use ramflux_protocol::custody::pairing::full_transfer::ChainHasher;
use rusqlite::params;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn h(n: u8) -> String {
    encode_base64url([n; 32])
}
fn source<'a>(
    a: &'a crate::AccountDb,
    root: &std::path::Path,
) -> TestResult<FullTransferStage<'a>> {
    let (mut record, base, _) = input(a)?;
    record.role = PairingRole::Initiator;
    let hash = record.base_manifest_hash.clone();
    let mut stage = a.create_full_stage_for_test(record, 604_900)?;
    let path = root.join("source-base.db");
    let snapshot = a
        .pin_full_transfer_cut()?
        .write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    stage.adopt_source_cut(0, &base.manifest.snapshot_id, &path, snapshot)?;
    stage.retain_source_manifest(&base, super::super::full_transfer_catalog())?;
    let mut chain = ChainHasher::new(1)?;
    chain.push(
        0,
        &super::super::stage::raw32(&hash)?,
        &super::super::stage::raw32(&base.manifest.chunks_root)?,
    )?;
    // The test controls original B's fixture key. This is a signed input receipt,
    // not a claim that this source-only unit fixture ran the receiver endpoint.
    let mut packet = DataPacket::DataVerified {
        manifest_hash: hash,
        chunks_root: base.manifest.chunks_root,
        total_bytes: base.manifest.total_bytes,
        census_hash: base.manifest.census_hash,
        destination_ref: base.manifest.destination_ref,
        manifest_chain_hash: encode_base64url(chain.finish()?),
        signature: encode_base64url([0; 64]),
    };
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &packet.data_verified_signing_bytes()?,
        [8; 32],
    );
    if let DataPacket::DataVerified { signature: slot, .. } = &mut packet {
        *slot = signature;
    }
    stage.record_source_data_verified(&packet, 1000)?;
    Ok(stage)
}
fn change(a: &crate::AccountDb, generation: u64, n: u8) -> TestResult {
    a.connection
        .execute("UPDATE account_erasure_generation SET generation=?1", params![generation])?;
    a.connection
        .execute("INSERT INTO object_payload_dependency VALUES(?1,?2)", params![h(n), h(n + 1)])?;
    Ok(())
}
#[test]
fn pairing_full_source_successor_releases_writer_and_replays_exact_cut_after_unsigned_loss()
-> TestResult {
    let (record, _, _) = super::super::stage_tests::fixture()?;
    let (root, a) = db("source-successor-own-cut", &record.grant.source_ref.account_anchor)?;
    seed(&a, 11, 8)?;
    let stage = source(&a, &root)?;
    let reference = stage.reference().clone();
    let directory = stage.directory.clone();
    let key = stage.key.source_job_key(SourceGuard::new(&a, None))?;
    change(&a, 9, 71)?;
    let work = stage.into_source_successor_work(1000)?;
    change(&a, 10, 81)?; // Ordinary A writes continue while its immutable copy job exists.
    let first = work.encode()?;
    assert_eq!(
        first.manifest().source_erasure_generation,
        U64(9),
        "successor substituted a live writer read for its pinned view"
    );
    let wire = key.open_source_metadata(&directory.join("source-wire.db"))?;
    let bytes = zeroize::Zeroizing::new(wire.query_row(
        "SELECT bytes FROM wire_chunk WHERE cut=1 AND idx=0",
        [],
        |r| r.get::<_, Vec<u8>>(0),
    )?);
    assert!(bytes.windows(h(71).len()).any(|part| part == h(71).as_bytes()));
    assert!(!bytes.windows(h(81).len()).any(|part| part == h(81).as_bytes()));
    drop(wire);
    change(&a, 11, 91)?;
    // Reopen only the internal encrypted-spool decoder. The production entrypoint
    // additionally requires a matching live row and fresh original-peer epoch.
    let stage = a.open_full_stage_reference(reference, PairingRole::Initiator, 1000)?;
    let replay = stage.into_source_successor_work(1000)?.encode()?;
    assert_eq!(replay.manifest(), first.manifest(), "unsigned local loss recut later A data");
    assert!(
        first
            .signed_manifest(ramflux_crypto::sign_canonical_bytes_with_seed(
                &first.manifest().signing_bytes()?,
                [8; 32]
            ))
            .is_err()
    );
    drop(key);
    drop(a);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn pairing_full_source_successor_cannot_retain_or_revive_original_unlocked_writer() -> TestResult {
    let (record, _, _) = super::super::stage_tests::fixture()?;
    let (root, a) = db("source-successor-lost-writer", &record.grant.source_ref.account_anchor)?;
    let stage = source(&a, &root)?;
    let work = stage.into_source_successor_work(1000)?;
    let pending = work.pending.0.clone();
    drop(a);
    assert!(
        matches!(work.encode(), Err(StorageError::AuthorizationRejected)),
        "detached source key revived the original writer"
    );
    assert!(!pending.exists(), "cancelled source work retained a partial snapshot");
    std::fs::remove_dir_all(root)?;
    Ok(())
}
