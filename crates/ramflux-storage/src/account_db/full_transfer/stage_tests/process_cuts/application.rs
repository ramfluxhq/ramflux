// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process death around the actual private recipient generation and atomic semantic DV ledger.
use super::{
    ARMED, PairingRole, TestResult, fixture, kill_writer, open, reference, save_reference,
};
use crate::account_db::full_transfer::receiver_projection::tests::{db, input, seed};
use crate::{AccountIndex, FullTransferStage};
use ramflux_protocol::custody::pairing::full_transfer::CHUNK_BYTES;
use std::{path::Path, time::Duration};

pub(super) fn write(root: &Path, cut: u8) -> TestResult {
    let db = open(root)?;
    let mut stage =
        db.open_full_stage_reference(reference(root)?, PairingRole::Responder, 604_801)?;
    let hash = stage.resume_record()?.base_manifest_hash;
    let mut copy = stage.pin_receiver_base(&hash)?.copy()?;
    copy.project(&stage)?;
    ARMED.with(|armed| armed.set(Some(cut)));
    commit(&mut copy, &mut stage)?;
    Err("test: armed recipient did not reach its application boundary".into())
}
fn commit(copy: &mut crate::FullReceiverBaseCopy, stage: &mut FullTransferStage<'_>) -> TestResult {
    let proof = copy.commit_application(stage, 604_801)?;
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &proof.packet().data_verified_signing_bytes()?,
        [8; 32],
    );
    let packet = proof.signed_packet(signature)?;
    copy.record_data_verified(stage, &proof, &packet, 604_801)?;
    Ok(())
}
#[tokio::test]
async fn pairing_full_application_process_death_never_fabricates_data_verified() -> TestResult {
    tokio::time::timeout(Duration::from_secs(60), async {
        for cut in 5..=13 {
            run(cut).await?;
        }
        Ok(())
    })
    .await?
}
async fn run(cut: u8) -> TestResult {
    let owner = tempfile::tempdir()?;
    let (initial, _, _) = fixture()?;
    let (_source_owner, source) =
        db("dv-process-source", &initial.grant.source_ref.account_anchor)?;
    seed(&source, 11, 8)?;
    let index = AccountIndex::open(owner.path())?;
    index.create_account("acct", &initial.grant.destination_ref.account_anchor)?;
    let target = open(owner.path())?;
    seed(&target, 21, 9)?;
    let (record, manifest, bytes) = input(&source)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = target.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, index as u64, chunk)?;
    }
    save_reference(owner.path(), stage.reference())?;
    drop(stage);
    drop(target);
    kill_writer(owner.path(), cut).await?;
    let target = open(owner.path())?;
    let mut stage = target.open_full_stage_reference(
        reference(owner.path())?,
        PairingRole::Responder,
        604_801,
    )?;
    let verified = stage.connection.query_row(
        "SELECT verified FROM manifest WHERE manifest_hash=?1",
        rusqlite::params![hash],
        |row| row.get::<_, bool>(0),
    )?;
    let has_table = stage.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='receiver_receipt')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    let receipts = if has_table {
        stage
            .connection
            .query_row("SELECT count(*) FROM receiver_receipt", [], |row| row.get::<_, u64>(0))?
    } else {
        0
    };
    assert_eq!(verified, cut >= 12, "test: cut {cut} lost or invented semantic DV");
    assert_eq!(receipts, u64::from(verified), "test: cut {cut} split receipt and semantic DV");
    assert!(target.pairing_head()?.is_none(), "test: data persistence invented native publication");
    let mut copy = stage.pin_receiver_base(&hash)?.copy()?;
    copy.project(&stage)?;
    commit(&mut copy, &mut stage)?;
    assert_eq!(target.privacy_erasure_generation()?, 9, "test: crash recovery changed original B");
    assert_eq!(source.privacy_erasure_generation()?, 8, "test: crash recovery changed original A");
    Ok(())
}
