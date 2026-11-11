// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ramflux_crypto::custody::pairing::{FullResumeRecord, PairingRole};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::pairing::{
        PairingWire,
        context_v3::TranscriptV3,
        full_transfer::{
            lease::{BranchKeys, DataGrant},
            *,
        },
    },
    encode_base64url,
};
use sha2::Digest as _;
use std::io::{Seek as _, SeekFrom, Write as _};
use zeroize::Zeroizing;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn h(value: u8) -> String {
    encode_base64url([value; 32])
}
fn fixture() -> TestResult<(FullResumeRecord, SourceManifest, Zeroizing<Vec<u8>>)> {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/fixtures/pairing_v3/vectors.json"
    ))?;
    let mut transcript =
        TranscriptV3::from_wire_bytes(&canonical_json_bytes(&vectors["transcript"])?)?;
    transcript.initiator.branch_key = ramflux_crypto::public_key_base64url_from_seed([7; 32]);
    transcript.responder.branch_key = ramflux_crypto::public_key_base64url_from_seed([8; 32]);
    let common = &transcript.initiator.common;
    let plaintext = Zeroizing::new(vec![93; CHUNK_BYTES as usize * 2 + 17]);
    let mut root = RootHasher::new(plaintext.len() as u64)?;
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).enumerate() {
        root.push(index as u64, chunk)?;
    }
    let mut manifest = SourceManifest {
        manifest: Manifest {
            schema: "ramflux.pairing.full_transfer.manifest.v1".into(),
            version: 1,
            transfer_id: common.transfer_id.clone().ok_or("transfer id")?,
            account_anchor: common.account_anchor.clone(),
            source_ref: transcript.initiator.device_ref.clone(),
            destination_ref: transcript.responder.device_ref.clone(),
            base_record_hash: common.record_hash.clone(),
            snapshot_id: h(55),
            snapshot_cut: U64(0),
            previous_cut: None,
            parent_manifest_hash: None,
            kind: ManifestKind::Base,
            source_erasure_generation: U64(1),
            storage_generation: U64(1),
            census_hash: h(56),
            families: vec![Family {
                id: "message_projection".into(),
                codec_version: U64(1),
                restrictive: false,
                disposition: Disposition::Transfer,
                source_rows: U64(1),
                portable_records: U64(1),
                encoded_bytes: U64(plaintext.len() as u64),
                rule_hash: h(57),
            }],
            total_bytes: U64(plaintext.len() as u64),
            chunk_bytes: U64(u64::from(CHUNK_BYTES)),
            chunk_count: U64(3),
            chunks_root: encode_base64url(root.finish()?),
            attachment_policy: "remote_ciphertext".into(),
        },
        source_signature: String::new(),
    };
    manifest.source_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &manifest.manifest.signing_bytes()?,
        [7; 32],
    );
    let record = FullResumeRecord {
        role: PairingRole::Responder,
        transcript: Zeroizing::new(transcript.to_wire_bytes()?),
        th: sha2::Sha256::digest(
            ramflux_protocol::custody::pairing::context_v3::transcript_preimage(&transcript)?,
        )
        .into(),
        grant: DataGrant {
            schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
            version: 1,
            transfer_id: manifest.manifest.transfer_id.clone(),
            node_id: "node-stage".into(),
            source_ref: manifest.manifest.source_ref.clone(),
            destination_ref: manifest.manifest.destination_ref.clone(),
            branch_keys: BranchKeys {
                source: transcript.initiator.branch_key.clone(),
                destination: transcript.responder.branch_key.clone(),
            },
            opaque_commitment: h(58),
            expires_at: 604_900,
        },
        lease: Zeroizing::new(
            b"local storage fixture only; no native lease acceptance claimed".to_vec(),
        ),
        transfer_id: manifest.manifest.transfer_id.clone(),
        base_manifest_hash: encode_base64url(manifest_hash(&manifest)?),
        base_record_hash: common.record_hash.clone(),
    };
    Ok((record, manifest, plaintext))
}
#[test]
fn pairing_full_stage_forward_slots_are_immutable_and_corruption_cuts_prefix() -> TestResult {
    let (_root, db) = crate::tests::test_db("stage-forward-slots")?;
    let (record, manifest, plaintext) = fixture()?;
    let hash = record.base_manifest_hash.clone();
    let stage = db.create_full_stage_for_test(record, 604_900)?;
    let mut wrong = manifest.clone();
    wrong.source_signature = h(60);
    assert!(stage.retain_forward_manifest(&wrong, &manifest.manifest.families).is_err());
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    assert!(stage.verify_forward_root(&hash).is_err());
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).enumerate() {
        assert!(stage.retain_forward_chunk(&hash, index as u64, chunk)?);
    }
    assert_eq!(stage.revalidate_forward_prefix(&hash)?, Some(2));
    stage.verify_forward_root(&hash)?;
    let (root_verified, data_verified) = stage.connection.query_row(
        "SELECT root_verified,verified FROM manifest WHERE direction=0 AND manifest_hash=?1",
        rusqlite::params![hash],
        |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
    )?;
    assert!(root_verified);
    assert!(!data_verified, "a matching encrypted root cannot bypass logical record validation");
    let path = stage.directory.join("seg-f-0-0.bin");
    let original = Zeroizing::new(std::fs::read(&path)?);
    assert!(!stage.retain_forward_chunk(&hash, 0, &plaintext[..CHUNK_BYTES as usize])?);
    assert_eq!(
        std::fs::read(&path)?.as_slice(),
        original.as_slice(),
        "receipted duplicate rewrote an immutable nonce/slot"
    );
    let mut changed = Zeroizing::new(plaintext[..CHUNK_BYTES as usize].to_vec());
    changed[0] ^= 1;
    assert!(stage.retain_forward_chunk(&hash, 0, &changed).is_err());
    assert!(stage.retain_forward_chunk(&hash, 3, b"extra").is_err());
    // Corrupt a genuinely receipted encrypted slot; durable-prefix recovery must discard
    // this row and every suffix row, preserving the first authenticated slot exactly.
    let mut file = std::fs::OpenOptions::new().write(true).open(&path)?;
    file.seek(SeekFrom::Start(262_172 + 12))?;
    file.write_all(&[0, 1, 2, 3])?;
    file.sync_all()?;
    assert!(stage.verify_forward_root(&hash).is_err());
    assert_eq!(stage.revalidate_forward_prefix(&hash)?, Some(0));
    let rows =
        stage.connection.query_row("SELECT count(*) FROM chunk", [], |row| row.get::<_, u64>(0))?;
    assert_eq!(rows, 1);
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).enumerate().skip(1) {
        assert!(stage.retain_forward_chunk(&hash, index as u64, chunk)?);
    }
    let repaired = Zeroizing::new(std::fs::read(&path)?);
    assert_eq!(&repaired[..262_172], &original[..262_172]);
    assert_ne!(
        &repaired[262_172..262_184],
        &original[262_172..262_184],
        "unreceipted/torn slot reused its nonce"
    );
    stage.verify_forward_root(&hash)?;
    assert_eq!(stage.revalidate_forward_prefix(&hash)?, Some(2));
    Ok(())
}
