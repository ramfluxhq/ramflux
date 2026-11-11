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
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use zeroize::Zeroizing;
const SCALAR_RULE: super::FamilyRule = super::FamilyRule {
    id: "sql/stage_fixture",
    selector: super::FamilySelector::Table("stage_fixture"),
    codec_version: U64(1),
    key_grammar_version: U64(1),
    disposition: Disposition::Transfer,
    restrictive: false,
    merge: super::MergeRule::Immutable,
    key: &["id"],
    excluded: &[],
    restrictive_projection: &[],
    cells: &[super::CellRule { name: "id", nullable: false, cell_type: CellType::I64 }],
    codec: &[super::FieldRule {
        name: "id",
        nullable: false,
        disposition: Disposition::Transfer,
        merge: super::MergeRule::Immutable,
        codec: super::CodecRule::Scalar { cell_type: CellType::I64 },
    }],
};

#[test]
fn pairing_full_source_manifest_preflight_cannot_hide_unknown_owners_with_peer_zero_counts()
-> TestResult {
    let (root, db) = crate::tests::test_db("source-compiled-preflight")?;
    let (mut record, mut manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let private = root.join("source-preflight-private.db");
    let snapshot = db.pin_full_transfer_cut()?.write_private_snapshot(
        &private,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    stage.adopt_source_cut(0, &manifest.manifest.snapshot_id, &private, snapshot)?;
    let rules = super::full_transfer_catalog();
    let own = stage.source_cut_schema(0, &manifest.manifest.snapshot_id, rules)?;
    assert!(
        own.families
            .iter()
            .any(|family| family.disposition == Disposition::Transfer && family.source_rows.0 > 0)
    );
    manifest.manifest.census_hash = encode_base64url(own.census_hash);
    manifest.manifest.families = own.families;
    for family in &mut manifest.manifest.families {
        family.source_rows = U64(0);
        family.portable_records = U64(0);
        family.encoded_bytes = U64(0);
    }
    manifest.manifest.total_bytes = U64(0);
    manifest.manifest.chunk_count = U64(0);
    manifest.manifest.chunks_root = encode_base64url(RootHasher::new(0)?.finish()?);
    manifest.source_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &manifest.manifest.signing_bytes()?,
        [7; 32],
    );
    assert!(
        matches!(
            stage.retain_source_manifest(&manifest, rules),
            Err(crate::StorageError::PairingField("UnsupportedRecord"))
        ),
        "caller metadata hid actual nonempty cut rows before typed-owner preflight"
    );
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM manifest", [], |row| row.get::<_, u64>(0))?,
        0
    );
    assert!(stage.source_cut_estimated_bytes(0, &manifest.manifest.snapshot_id)? > 0);
    Ok(())
}

#[test]
fn pairing_full_source_receipt_requires_exact_local_chain_and_original_destination_signature()
-> TestResult {
    let (_root, db) = crate::tests::test_db("stage-source-receipt")?;
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let hash = record.base_manifest_hash.clone();
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    // Storage receipt unit: bypasses the public source encoder/snapshot preflight, which
    // remains separately required. No SAS/native/semantic application proof is inferred.
    stage.retain_manifest_for_role(
        &manifest,
        &manifest.manifest.families,
        PairingRole::Initiator,
    )?;
    assert!(stage.source_last_data_verified()?.is_none());
    let mut chain = ChainHasher::new(1)?;
    chain.push(
        0,
        &manifest_hash(&manifest)?,
        &super::stage::raw32(&manifest.manifest.chunks_root)?,
    )?;
    let receipt = DataPacket::DataVerified {
        manifest_hash: hash.clone(),
        chunks_root: manifest.manifest.chunks_root.clone(),
        total_bytes: manifest.manifest.total_bytes,
        census_hash: manifest.manifest.census_hash.clone(),
        destination_ref: manifest.manifest.destination_ref.clone(),
        manifest_chain_hash: encode_base64url(chain.finish()?),
        signature: encode_base64url([0; 64]),
    };
    let sign = |mut packet: DataPacket, seed| -> TestResult<DataPacket> {
        let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &packet.data_verified_signing_bytes()?,
            [seed; 32],
        );
        let DataPacket::DataVerified { signature: slot, .. } = &mut packet else {
            return Err("receipt".into());
        };
        *slot = signature;
        Ok(packet)
    };
    assert!(stage.record_source_data_verified(&sign(receipt.clone(), 9)?, 100).is_err());
    for mutation in 0..5 {
        let mut wrong = receipt.clone();
        let DataPacket::DataVerified {
            manifest_hash,
            chunks_root,
            total_bytes,
            census_hash,
            manifest_chain_hash,
            ..
        } = &mut wrong
        else {
            return Err("receipt".into());
        };
        match mutation {
            0 => *manifest_hash = h(99),
            1 => *chunks_root = h(99),
            2 => total_bytes.0 += 1,
            3 => *census_hash = h(99),
            _ => *manifest_chain_hash = h(99),
        }
        assert!(
            stage.record_source_data_verified(&sign(wrong, 8)?, 100).is_err(),
            "foreign receipt{mutation}"
        );
        assert!(stage.source_last_data_verified()?.is_none());
    }
    let receipt = sign(receipt, 8)?;
    assert!(matches!(
        stage.record_source_data_verified(&receipt, 604_900),
        Err(crate::StorageError::PairingField("LeaseExpired"))
    ));
    stage.record_source_data_verified(&receipt, 100)?;
    let expected = receipt.encode_secret()?;
    assert_eq!(
        stage.source_last_data_verified()?.ok_or("saved receipt")?.encode_secret()?.as_slice(),
        expected.as_slice()
    );
    stage.record_source_data_verified(&receipt, 100)?;
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM source_receipt", [], |row| row.get::<_, u64>(0))?,
        1
    );
    let verified = stage.connection.query_row(
        "SELECT verified FROM manifest WHERE manifest_hash=?1",
        rusqlite::params![hash],
        |row| row.get::<_, bool>(0),
    )?;
    assert!(verified);
    Ok(())
}

#[test]
fn pairing_full_stage_replacement_keeps_verified_chain_and_discards_only_unverified_slots()
-> TestResult {
    let (_root, db) = crate::tests::test_db("stage-replace-child")?;
    let (record, base, plaintext) = fixture()?;
    let base_hash = record.base_manifest_hash.clone();
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let catalog = &base.manifest.families;
    stage.retain_forward_manifest(&base, catalog)?;
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&base_hash, index as u64, chunk)?;
    }
    stage.verify_forward_root(&base_hash)?;
    let mut child = base.clone();
    child.manifest.kind = ManifestKind::Delta;
    child.manifest.snapshot_cut = U64(1);
    child.manifest.previous_cut = Some(U64(0));
    child.manifest.parent_manifest_hash = Some(base_hash.clone());
    child.source_signature =
        ramflux_crypto::sign_canonical_bytes_with_seed(&child.manifest.signing_bytes()?, [7; 32]);
    assert!(
        stage.retain_forward_manifest(&child, catalog).is_err(),
        "root alone admitted a successor"
    );
    // Fixture for the storage admission subroutine only: the complete semantic application
    // and signed DataVerified owner is not implemented by this test or this SQL update.
    stage.connection.execute(
        "UPDATE manifest SET verified=1 WHERE manifest_hash=?1",
        rusqlite::params![base_hash],
    )?;
    stage.retain_forward_manifest(&child, catalog)?;
    let first_hash = encode_base64url(manifest_hash(&child)?);
    stage.retain_forward_chunk(&first_hash, 0, &plaintext[..CHUNK_BYTES as usize])?;
    let old_file = stage.directory.join("seg-f-1-0.bin");
    let old_bytes = Zeroizing::new(std::fs::read(&old_file)?);
    stage.retain_forward_manifest(&child, catalog)?;
    assert_eq!(
        std::fs::read(&old_file)?.as_slice(),
        old_bytes.as_slice(),
        "retry discarded retained prefix"
    );
    let mut replacement = child.clone();
    replacement.manifest.snapshot_id = h(99);
    replacement.manifest.parent_manifest_hash = Some(h(98));
    replacement.source_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &replacement.manifest.signing_bytes()?,
        [7; 32],
    );
    assert!(stage.retain_forward_manifest(&replacement, catalog).is_err());
    assert_eq!(
        std::fs::read(&old_file)?.as_slice(),
        old_bytes.as_slice(),
        "foreign parent destroyed valid prefix"
    );
    replacement.manifest.parent_manifest_hash = Some(base_hash.clone());
    replacement.source_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &replacement.manifest.signing_bytes()?,
        [7; 32],
    );
    stage.retain_forward_manifest(&replacement, catalog)?;
    assert!(!old_file.exists(), "replacement retained obsolete encrypted slots");
    assert!(
        stage.directory.join("seg-f-0-0.bin").exists(),
        "replacement removed verified predecessor data"
    );
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM manifest", [], |row| row.get::<_, u64>(0))?,
        2
    );
    assert_eq!(
        stage.connection.query_row(
            "SELECT count(*) FROM chunk WHERE manifest_hash=?1",
            rusqlite::params![first_hash],
            |row| row.get::<_, u64>(0)
        )?,
        0
    );
    assert_eq!(stage.revalidate_forward_prefix(&base_hash)?, Some(2));
    let replacement_hash = encode_base64url(manifest_hash(&replacement)?);
    assert_eq!(stage.revalidate_forward_prefix(&replacement_hash)?, None);
    stage.retain_forward_chunk(&replacement_hash, 0, &plaintext[..CHUNK_BYTES as usize])?;
    assert_ne!(&std::fs::read(&old_file)?[..12], &old_bytes[..12]);
    Ok(())
}

#[test]
fn pairing_full_stage_scalar_input_checks_order_counts_and_bytes_without_data_verified()
-> TestResult {
    for (case, ids, op, count_delta, byte_delta, accepted) in [
        ("valid", vec![7_i64, 8], RecordOp::Put, 0, 0, true),
        ("empty", vec![], RecordOp::Put, 0, 0, true),
        ("duplicate", vec![7, 7], RecordOp::Put, 0, 0, false),
        ("reverse", vec![8, 7], RecordOp::Put, 0, 0, false),
        ("count", vec![7, 8], RecordOp::Put, 1, 0, false),
        ("truncated-cell", vec![7, 8], RecordOp::Put, 0, 1, false),
        ("base-absent", vec![7], RecordOp::Absent, 0, 0, false),
    ] {
        let (mut record, mut manifest, _) = fixture()?;
        let mut stream = Zeroizing::new(Vec::new());
        for id in &ids {
            let bytes = id.to_be_bytes();
            let header = RecordHeader {
                family: SCALAR_RULE.id.into(),
                codec_version: U64(1),
                key: encode_stable_key([(CellType::I64, bytes.as_slice())])?.to_string(),
                op,
                cell_types: if op == RecordOp::Put { vec![CellType::I64] } else { vec![] },
                cell_lengths: if op == RecordOp::Put { vec![U64(8)] } else { vec![] },
            };
            write_record_header(&mut *stream, &header)?;
            if op == RecordOp::Put {
                stream.extend_from_slice(&bytes);
            }
        }
        if byte_delta > 0 {
            let truncated = stream.len() - 1;
            stream.truncate(truncated);
        }
        let body = &mut manifest.manifest;
        let mut family = SCALAR_RULE.manifest_family()?;
        family.source_rows = U64(ids.len() as u64);
        family.portable_records = U64(ids.len() as u64 + count_delta);
        family.encoded_bytes = U64(stream.len() as u64);
        body.families = vec![family];
        body.census_hash = encode_base64url(super::full_census_hash(&[SCALAR_RULE])?);
        body.total_bytes = U64(stream.len() as u64);
        body.chunk_count = U64(u64::from(!stream.is_empty()));
        let mut root = RootHasher::new(stream.len() as u64)?;
        for (index, chunk) in stream.chunks(CHUNK_BYTES as usize).enumerate() {
            root.push(index as u64, chunk)?;
        }
        body.chunks_root = encode_base64url(root.finish()?);
        manifest.source_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &manifest.manifest.signing_bytes()?,
            [7; 32],
        );
        record.base_manifest_hash = encode_base64url(manifest_hash(&manifest)?);
        let hash = record.base_manifest_hash.clone();
        let (_root, db) = crate::tests::test_db(&format!("stage-input-{case}"))?;
        let mut stage = db.create_full_stage_for_test(record, 604_900)?;
        stage.retain_forward_manifest(&manifest, &[SCALAR_RULE.manifest_family()?])?;
        for (index, chunk) in stream.chunks(CHUNK_BYTES as usize).enumerate() {
            stage.retain_forward_chunk(&hash, index as u64, chunk)?;
        }
        assert_eq!(
            stage.validate_forward_scalar_records(&hash, &[SCALAR_RULE]).is_ok(),
            accepted,
            "{case}"
        );
        let verified = stage.connection.query_row(
            "SELECT verified FROM manifest WHERE manifest_hash=?1",
            rusqlite::params![hash],
            |row| row.get::<_, bool>(0),
        )?;
        assert!(!verified, "input validation cannot stand in for durable application: {case}");
    }
    Ok(())
}
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
    let plaintext =
        Zeroizing::new((0_u8..251).cycle().take(CHUNK_BYTES as usize * 2 + 17).collect::<Vec<_>>());
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
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let mut wrong = manifest.clone();
    let mut oversized = manifest.clone();
    oversized.manifest.kind = ManifestKind::Tail;
    oversized.manifest.previous_cut = Some(U64(0));
    oversized.manifest.snapshot_cut = U64(1);
    oversized.manifest.parent_manifest_hash = Some(hash.clone());
    oversized.manifest.total_bytes = U64(MAX_TAIL_BYTES + 1);
    oversized.manifest.families[0].encoded_bytes = U64(MAX_TAIL_BYTES + 1);
    oversized.manifest.chunk_count = U64(chunk_layout(MAX_TAIL_BYTES + 1)?.0);
    assert!(matches!(
        stage.retain_forward_manifest(&oversized, &manifest.manifest.families),
        Err(crate::StorageError::PairingField("NoSpace"))
    ));
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM manifest", [], |row| row.get::<_, u64>(0))?,
        0
    );
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

#[test]
fn pairing_full_stage_reader_seeks_across_encrypted_slots_and_retires_on_corruption() -> TestResult
{
    let (_root, db) = crate::tests::test_db("stage-forward-reader")?;
    let (record, manifest, plaintext) = fixture()?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    assert!(stage.forward_reader(&hash).is_err());
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, index as u64, chunk)?;
    }
    let mut reader = stage.forward_reader(&hash)?;
    let mut restored = Zeroizing::new(Vec::new());
    let mut scratch = Zeroizing::new([0; 8191]);
    loop {
        let amount = reader.read(scratch.as_mut())?;
        if amount == 0 {
            break;
        }
        restored.extend_from_slice(&scratch[..amount]);
    }
    assert_eq!(restored.as_slice(), plaintext.as_slice());
    assert!(reader.seek(SeekFrom::End(1)).is_err());
    assert!(reader.seek(SeekFrom::Start(u64::MAX)).is_err());
    reader.seek(SeekFrom::Start(u64::from(CHUNK_BYTES) - 7))?;
    let mut boundary = [0; 29];
    reader.read_exact(&mut boundary)?;
    assert_eq!(&boundary, &plaintext[CHUNK_BYTES as usize - 7..CHUNK_BYTES as usize + 22]);
    reader.seek(SeekFrom::End(-17))?;
    let mut last = [0; 17];
    reader.read_exact(&mut last)?;
    assert_eq!(&last, &plaintext[plaintext.len() - 17..]);
    // Revisit a different slot after the reader was opened. AEAD failure must not be
    // masked by the earlier root check, and failure permanently retires this reader.
    let path = stage.directory.join("seg-f-0-0.bin");
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(262_172 + 12))?;
    file.write_all(&[0, 1, 2, 3])?;
    file.sync_all()?;
    reader.seek(SeekFrom::Start(u64::from(CHUNK_BYTES)))?;
    let mut untouched = [123; 16];
    assert!(reader.read(&mut untouched).is_err());
    assert_eq!(untouched, [123; 16]);
    assert!(reader.seek(SeekFrom::Start(0)).is_err());
    assert!(reader.read(&mut untouched).is_err());
    let verified = stage.connection.query_row(
        "SELECT verified FROM manifest WHERE manifest_hash=?1",
        rusqlite::params![hash],
        |row| row.get::<_, bool>(0),
    )?;
    assert!(!verified, "reading a root-checked stream must not grant DataVerified");
    Ok(())
}
