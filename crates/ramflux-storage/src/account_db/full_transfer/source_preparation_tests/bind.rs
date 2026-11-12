// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Storage binding scope only. The cfg(test) record has no network-acceptable lease/SAS proof.
use super::*;
use crate::account_db::full_transfer::{FullBaseSourceEncoding, stage_tests::fixture};
use ramflux_crypto::custody::{VerifiedRecord, pairing::FullResumeRecord};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{
        DeviceSet, Envelope, object_hash,
        pairing::{
            PairingWire,
            context_v3::TranscriptV3,
            full_transfer::{SourceManifest, U64, manifest_hash},
        },
    },
};
use sha2::Digest as _;
use zeroize::Zeroizing;
type ResultOf<T> = Result<T, Box<dyn std::error::Error>>;
fn base() -> ResultOf<VerifiedRecord> {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    let base: Envelope<DeviceSet> =
        ramflux_protocol::parse_i_json(&canonical_json_bytes(&vectors["record"])?)?;
    Ok(ramflux_crypto::custody::verify_record(&base, base.body.issued_at, None, None)?)
}
fn operands(
    base: &VerifiedRecord,
    snapshot: &str,
    encoded: &FullBaseSourceEncoding,
) -> ResultOf<(FullResumeRecord, SourceManifest)> {
    let (mut record, mut manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let native = &base.envelope().body;
    let source = native.master_certificate.body.primary_device_ref.clone();
    let destination = ramflux_protocol::custody::DeviceRef {
        account_anchor: native.account_anchor.clone(),
        device_id: "prepared-destination".into(),
        device_epoch: 1,
    };
    let mut transcript = TranscriptV3::from_wire_bytes(&record.transcript)?;
    let mut common = transcript.initiator.common.clone();
    common.account_anchor = native.account_anchor.clone();
    common.master_public_key = native.master_certificate.body.master_public_key.clone();
    common.record_hash = object_hash(base.envelope())?;
    common.device_set_epoch = native.device_set_epoch;
    common.recipient_mode = "new".into();
    common.destination_ref = None;
    transcript.initiator.common = common.clone();
    transcript.responder.common = common.clone();
    transcript.initiator.device_ref = source.clone();
    transcript.responder.device_ref = destination.clone();
    record.th = sha2::Sha256::digest(
        ramflux_protocol::custody::pairing::context_v3::transcript_preimage(&transcript)?,
    )
    .into();
    record.transcript = Zeroizing::new(transcript.to_wire_bytes()?);
    record.base_record_hash = common.record_hash.clone();
    record.grant.source_ref = source.clone();
    record.grant.destination_ref = destination.clone();
    record.grant.expires_at = native.issued_at + 604_800;
    let body = &mut manifest.manifest;
    body.account_anchor = native.account_anchor.clone();
    body.source_ref = source;
    body.destination_ref = destination;
    body.base_record_hash = common.record_hash;
    body.snapshot_id = snapshot.into();
    body.families = encoded.schema.families.clone();
    body.census_hash = ramflux_protocol::encode_base64url(encoded.schema.census_hash);
    body.total_bytes = U64(encoded.total_bytes);
    body.chunk_count = U64(encoded.chunk_count);
    body.chunks_root = ramflux_protocol::encode_base64url(encoded.chunks_root);
    body.storage_generation = U64(encoded.storage_generation);
    body.source_erasure_generation = U64(encoded.source_erasure_generation);
    manifest.source_signature =
        ramflux_crypto::sign_canonical_bytes_with_seed(&body.signing_bytes()?, [7; 32]);
    record.base_manifest_hash = ramflux_protocol::encode_base64url(manifest_hash(&manifest)?);
    Ok((record, manifest))
}
#[test]
fn pairing_full_source_binding_preserves_data_and_seeds_exact_resume_and_floor() -> TestResult {
    let (_root, db) = crate::tests::test_db("full-source-bind")?;
    let mut owner = db.prepare_full_transfer_source()?;
    let snapshot = ramflux_protocol::encode_base64url([41; 32]);
    owner.capture_base_cut(&snapshot)?;
    let (_, encoded) = owner.encode_fixed_base_source(&snapshot, std::io::sink())?;
    let encoded = encoded.clone();
    let ready = owner.close_ready()?;
    let native = base()?;
    let now = native.envelope().body.issued_at;
    let (record, manifest) = operands(&native, &snapshot, &encoded)?;
    let digest = record.stage_digest()?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = db.open_full_source_preparation(&ready)?.bind_record_for_test(
        record,
        now + 604_800,
        &native,
        &manifest,
        now,
    )?;
    assert_eq!(stage.resume_record()?.stage_digest()?, digest);
    stage.require_full_native_floor(&native)?;
    assert_eq!(stage.forward_manifest(&hash)?, manifest);
    assert!(stage.source_last_data_verified()?.is_none());
    assert!(db.open_full_source_preparation(&ready).is_err());
    let (_, actual) = stage.encode_fixed_base_source(&snapshot, std::io::sink())?;
    assert_eq!(actual.chunks_root, encoded.chunks_root);
    assert_eq!(actual.total_bytes, encoded.total_bytes);
    assert_eq!(
        db.pairing_live_rows()?.len(),
        0,
        "caller must explicitly persist the authenticated stage reference"
    );
    Ok(())
}
#[test]
fn pairing_full_source_binding_refuses_a_signed_root_not_matching_actual_preparation() -> TestResult
{
    let (_root, db) = crate::tests::test_db("full-source-bind-wrong-root")?;
    let mut owner = db.prepare_full_transfer_source()?;
    let snapshot = ramflux_protocol::encode_base64url([42; 32]);
    owner.capture_base_cut(&snapshot)?;
    let (_, encoded) = owner.encode_fixed_base_source(&snapshot, std::io::sink())?;
    let encoded = encoded.clone();
    let ready = owner.close_ready()?;
    let native = base()?;
    let now = native.envelope().body.issued_at;
    let (mut record, mut manifest) = operands(&native, &snapshot, &encoded)?;
    manifest.manifest.chunks_root = ramflux_protocol::encode_base64url([99; 32]);
    manifest.source_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &manifest.manifest.signing_bytes()?,
        [7; 32],
    );
    record.base_manifest_hash = ramflux_protocol::encode_base64url(manifest_hash(&manifest)?);
    assert!(matches!(
        db.open_full_source_preparation(&ready)?.bind_record_for_test(
            record,
            now + 604_800,
            &native,
            &manifest,
            now
        ),
        Err(crate::StorageError::PairingField("ManifestMismatch"))
    ));
    assert!(
        db.open_full_source_preparation(&ready).is_ok(),
        "wrong root changed the wrapper or moved the source files"
    );
    Ok(())
}

#[test]
fn pairing_full_source_wire_chunks_survive_binding_and_failed_reencode() -> TestResult {
    use std::io::Write;
    struct FailAfterChunk {
        written: usize,
    }
    impl Write for FailAfterChunk {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let remaining = (ramflux_protocol::custody::pairing::full_transfer::CHUNK_BYTES
                as usize)
                .saturating_sub(self.written);
            if remaining == 0 {
                return Err(std::io::Error::other("intentional source sink refusal"));
            }
            let accepted = remaining.min(bytes.len());
            self.written += accepted;
            Ok(accepted)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_root, db) = crate::tests::test_db("full-source-wire-bind")?;
    db.connection.call(|db| {
        let tx = db.transaction()?;
        for index in 0..2048 {
            let value = ramflux_crypto::object_erasure_commitment(
                "root",
                &format!("wire-{index}"),
                "manifest",
            );
            tx.execute("INSERT INTO object_identity_replacement VALUES(?1)", [value])?;
        }
        tx.commit()
    })?;
    let mut owner = db.prepare_full_transfer_source()?;
    let snapshot = ramflux_protocol::encode_base64url([61; 32]);
    owner.capture_base_cut(&snapshot)?;
    let (_, encoded) = owner.encode_fixed_base_source(&snapshot, std::io::sink())?;
    let encoded = encoded.clone();
    assert!(encoded.chunk_count > 1);
    let ready = owner.close_ready()?;
    let native = base()?;
    let now = native.envelope().body.issued_at;
    let (record, manifest) = operands(&native, &snapshot, &encoded)?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = db.open_full_source_preparation(&ready)?.bind_record_for_test(
        record,
        now + 604_800,
        &native,
        &manifest,
        now,
    )?;
    let mut expected = Vec::new();
    let mut root =
        ramflux_protocol::custody::pairing::full_transfer::RootHasher::new(encoded.total_bytes)?;
    for index in 0..encoded.chunk_count {
        let chunk = stage.read_source_wire_chunk(&hash, index)?;
        root.push(index, &chunk)?;
        expected.push(chunk);
    }
    assert_eq!(root.finish()?, encoded.chunks_root);
    assert!(stage.read_source_wire_chunk(&hash, encoded.chunk_count).is_err());
    assert!(stage.encode_fixed_base_source(&snapshot, FailAfterChunk { written: 0 }).is_err());
    for (index, bytes) in expected.iter().enumerate() {
        assert_eq!(
            &*stage.read_source_wire_chunk(&hash, u64::try_from(index)?)?,
            bytes.as_slice(),
            "failed reencode replaced the committed source prefix"
        );
    }
    let io = stage.io_cancel_handle();
    io.cancel();
    assert!(matches!(
        stage.read_source_wire_chunk(&hash, 0),
        Err(crate::StorageError::PairingField("Cancelled"))
    ));
    Ok(())
}
