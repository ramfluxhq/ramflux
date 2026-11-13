// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual original-B typed bytes validate off-loan; no validation-only proof merges a veto.
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex, FullStageReference};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    context_v3::TranscriptV3,
    full_transfer::{CHUNK_BYTES, U64, manifest_hash},
};
use sha2::Digest as _;
type ResultOf<T> = Result<T, Box<dyn std::error::Error>>;
type Staged = (tempfile::TempDir, AccountDb, FullStageReference, String);
fn open(root: &std::path::Path, anchor: &str) -> ResultOf<AccountDb> {
    let index = AccountIndex::open(root)?;
    index.create_account("acct", anchor)?;
    Ok(AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"reverse-work-secret"))?)
}
fn staged(false_counts: bool) -> ResultOf<Staged> {
    let (initial, _, _) = super::super::stage_tests::fixture()?;
    let root = tempfile::tempdir()?;
    let b_root = tempfile::tempdir()?;
    let db = open(root.path(), &initial.grant.source_ref.account_anchor)?;
    let b = open(b_root.path(), &initial.grant.destination_ref.account_anchor)?;
    b.connection.execute(
        "INSERT INTO object_erasure_fence VALUES(?1)",
        rusqlite::params![ramflux_protocol::encode_base64url([7; 32])],
    )?;
    b.connection
        .execute("UPDATE account_erasure_generation SET generation=9 WHERE singleton=1", [])?;
    let (mut record, forward, _) = super::super::receiver_projection::tests::input(&db)?;
    let (_, mut reverse, bytes) = super::super::receiver_projection::tests::input(&b)?;
    assert!(
        !reverse
            .manifest
            .families
            .iter()
            .any(|family| !family.restrictive && family.portable_records.0 > 0),
        "test: reverse fixture contains nonrestrictive bytes"
    );
    reverse.manifest.families.retain(|family| family.restrictive);
    reverse.manifest.source_ref = record.grant.destination_ref.clone();
    reverse.manifest.destination_ref = record.grant.source_ref.clone();
    if false_counts {
        let family = reverse
            .manifest
            .families
            .iter_mut()
            .find(|family| family.portable_records.0 > 0)
            .ok_or("test: restrictive family")?;
        family.source_rows = U64(family.source_rows.0 + 1);
        family.portable_records = U64(family.portable_records.0 + 1);
    }
    reverse.source_signature =
        ramflux_crypto::sign_canonical_bytes_with_seed(&reverse.manifest.signing_bytes()?, [8; 32]);
    let mut transcript = TranscriptV3::from_wire_bytes(&record.transcript)?;
    transcript.initiator.common.recipient_mode = "existing".into();
    transcript.initiator.common.destination_ref = Some(record.grant.destination_ref.clone());
    transcript.responder.common = transcript.initiator.common.clone();
    record.transcript = Zeroizing::new(transcript.to_wire_bytes()?);
    record.th = sha2::Sha256::digest(
        ramflux_protocol::custody::pairing::context_v3::transcript_preimage(&transcript)?,
    )
    .into();
    record.role = PairingRole::Initiator;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    stage.retain_manifest_for_role(&forward, &forward.manifest.families, PairingRole::Initiator)?;
    stage.retain_reverse_manifest(&reverse, &forward.manifest.families)?;
    let hash = ramflux_protocol::encode_base64url(manifest_hash(&reverse)?);
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_reverse_chunk(&hash, index as u64, chunk)?;
    }
    let reference = stage.reference().clone();
    drop(stage);
    Ok((root, db, reference, hash))
}
#[test]
fn pairing_full_reverse_validation_releases_writer_and_cannot_retain_or_revive_unlock()
-> ResultOf<()> {
    let (root, db, reference, hash) = staged(false)?;
    let work = db
        .open_full_stage_reference(reference.clone(), PairingRole::Initiator, 1000)?
        .into_reverse_validation_work(&hash)?;
    db.connection
        .execute("UPDATE account_erasure_generation SET generation=5 WHERE singleton=1", [])?;
    let proof = work.validate()?;
    let stage = db.open_full_stage_reference(reference, PairingRole::Initiator, 1000)?;
    stage.accept_validated_reverse_input(&proof)?;
    assert_eq!(
        db.connection.query_row(
            "SELECT generation FROM account_erasure_generation",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        5,
        "test: validation-only work applied B's higher restrictive maximum"
    );
    assert_eq!(
        db.connection.query_row("SELECT count(*) FROM object_erasure_fence", [], |row| row
            .get::<_, u64>(0))?,
        0,
        "test: input validation alone imported a B veto"
    );
    assert_eq!(
        stage.connection.query_row(
            "SELECT verified FROM manifest WHERE direction=1",
            [],
            |row| row.get::<_, u8>(0)
        )?,
        0,
        "test: input proof asserted semantic verification"
    );
    let work = stage.into_reverse_validation_work(&hash)?;
    drop(db);
    let index = AccountIndex::open(root.path())?;
    let _reopened =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"reverse-work-secret"))?;
    assert!(
        work.validate().is_err(),
        "test: new unlock revived an old reverse reader/key capability"
    );
    Ok(())
}
#[test]
fn pairing_full_reverse_validation_refuses_signed_false_counts_before_any_application()
-> ResultOf<()> {
    let (_root, db, reference, hash) = staged(true)?;
    let work = db
        .open_full_stage_reference(reference.clone(), PairingRole::Initiator, 1000)?
        .into_reverse_validation_work(&hash)?;
    assert!(
        work.validate().is_err(),
        "test: correct root and B signature bypassed false restrictive counts"
    );
    let stage = db.open_full_stage_reference(reference, PairingRole::Initiator, 1000)?;
    assert_eq!(
        stage.connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='reverse_input_validated'",
            [],
            |row| row.get::<_, u8>(0)
        )?,
        0,
        "test: malformed input created a positive validation ledger"
    );
    assert_eq!(
        db.connection.query_row(
            "SELECT generation FROM account_erasure_generation",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        0,
        "test: malformed input changed actual A"
    );
    Ok(())
}
