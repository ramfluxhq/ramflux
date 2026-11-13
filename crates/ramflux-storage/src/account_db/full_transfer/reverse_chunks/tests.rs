// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual encrypted reverse slots: no semantic/DV marker follows mere durable receipt.
use super::*;
use ramflux_crypto::custody::pairing::{FullResumeRecord, PairingRole};
use ramflux_protocol::custody::pairing::{context_v3::TranscriptV3, full_transfer::manifest_hash};
use sha2::Digest as _;
type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fixture = (FullResumeRecord, SourceManifest, SourceManifest, Zeroizing<Vec<u8>>);
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let (mut record, mut forward, plaintext) = super::super::stage_tests::fixture()?;
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
    for family in &mut forward.manifest.families {
        family.restrictive = true;
    }
    forward.source_signature =
        ramflux_crypto::sign_canonical_bytes_with_seed(&forward.manifest.signing_bytes()?, [7; 32]);
    record.base_manifest_hash = ramflux_protocol::encode_base64url(manifest_hash(&forward)?);
    let mut reverse = forward.clone();
    reverse.manifest.source_ref = record.grant.destination_ref.clone();
    reverse.manifest.destination_ref = record.grant.source_ref.clone();
    reverse.manifest.snapshot_id = ramflux_protocol::encode_base64url([99; 32]);
    reverse.source_signature =
        ramflux_crypto::sign_canonical_bytes_with_seed(&reverse.manifest.signing_bytes()?, [8; 32]);
    Ok((record, forward, reverse, plaintext))
}
#[test]
fn pairing_full_linked_reverse_durable_slots_recheck_root_and_repair_torn_prefix() -> TestResult {
    let root = tempfile::tempdir()?;
    let index = crate::AccountIndex::open(root.path())?;
    index.create_account("acct", "principal")?;
    let key = crate::AccountDbKey::derive("acct", b"linked-reverse-test-secret");
    let db = crate::AccountDb::open(&index, "acct", &key)?;
    let (record, forward, reverse, plaintext) = fixture()?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let catalog = forward.manifest.families.clone();
    stage.retain_manifest_for_role(&forward, &catalog, PairingRole::Initiator)?;
    stage.retain_reverse_manifest(&reverse, &catalog)?;
    let hash = ramflux_protocol::encode_base64url(manifest_hash(&reverse)?);
    assert!(
        stage.reverse_reader(&hash).is_err(),
        "test: incomplete reverse stream became readable"
    );
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).enumerate() {
        assert!(
            stage.retain_reverse_chunk(&hash, index as u64, chunk)?,
            "test: first reverse slot not durable"
        );
        assert!(
            !stage.retain_reverse_chunk(&hash, index as u64, chunk)?,
            "test: exact reverse retry rewrote a receipt"
        );
    }
    assert_eq!(
        stage.revalidate_reverse_prefix(&hash)?,
        Some(2),
        "test: durable reverse prefix lost a slot"
    );
    let mut output = Zeroizing::new(Vec::new());
    stage.reverse_reader(&hash)?.take(u64::from(CHUNK_BYTES) * 3 + 1).read_to_end(&mut output)?;
    assert_eq!(*output, *plaintext, "test: reverse stream bytes changed across encrypted slots");
    assert_eq!(
        stage.connection.query_row(
            "SELECT verified FROM manifest WHERE direction=1",
            [],
            |row| row.get::<_, u8>(0)
        )?,
        0,
        "test: reverse root receipt asserted semantic application"
    );
    let path = stage.reverse_segment_path(0);
    let mut file = open_regular(&path, true)?;
    file.seek(SeekFrom::Start(0))?;
    let mut first = [0; 1];
    file.read_exact(&mut first)?;
    *first.first_mut().ok_or("test: torn slot nonce byte")? ^= 1;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&first)?;
    file.sync_all()?;
    drop(file);
    assert_eq!(
        stage.revalidate_reverse_prefix(&hash)?,
        None,
        "test: torn reverse slot retained a durable prefix"
    );
    assert!(stage.reverse_reader(&hash).is_err(), "test: reverse read trusted a stale root marker");
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_reverse_chunk(&hash, index as u64, chunk)?;
    }
    stage.verify_reverse_root(&hash)?;
    assert_eq!(
        stage.revalidate_reverse_prefix(&hash)?,
        Some(2),
        "test: valid retransmission did not restore durable prefix"
    );
    Ok(())
}
