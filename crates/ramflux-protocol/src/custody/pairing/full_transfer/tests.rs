// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::{encode_base64url, parse_i_json_secret};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn manifest() -> SourceManifest {
    let hash = encode_base64url([1; 32]);
    SourceManifest {
        manifest: Manifest {
            schema: "ramflux.pairing.full_transfer.manifest.v1".into(),
            version: 1,
            transfer_id: hash.clone(),
            account_anchor: hash.clone(),
            source_ref: DeviceRef {
                account_anchor: hash.clone(),
                device_id: "source".into(),
                device_epoch: 1,
            },
            destination_ref: DeviceRef {
                account_anchor: hash.clone(),
                device_id: "destination".into(),
                device_epoch: 1,
            },
            base_record_hash: hash.clone(),
            snapshot_id: hash.clone(),
            snapshot_cut: U64(0),
            previous_cut: None,
            parent_manifest_hash: None,
            kind: ManifestKind::Base,
            source_erasure_generation: U64(1),
            storage_generation: U64(1),
            census_hash: hash.clone(),
            families: vec![Family {
                id: "message_projection".into(),
                codec_version: U64(1),
                restrictive: false,
                disposition: Disposition::Transfer,
                source_rows: U64(0),
                portable_records: U64(0),
                encoded_bytes: U64(0),
                rule_hash: hash.clone(),
            }],
            total_bytes: U64(0),
            chunk_bytes: U64(u64::from(CHUNK_BYTES)),
            chunk_count: U64(0),
            chunks_root: hash,
            attachment_policy: "remote_ciphertext".into(),
        },
        source_signature: encode_base64url([2; 64]),
    }
}

fn part(hash: &str, wire: &[u8], offset: usize, length: usize) -> DataPacket {
    DataPacket::Manifest {
        manifest_hash: hash.into(),
        offset: U64(offset as u64),
        total: U64(wire.len() as u64),
        bytes: SecretBase64::from_bytes(&wire[offset..offset + length]),
    }
}
#[test]
fn full_transfer_manifest_assembly_is_bounded_canonical_and_retries_exact_prefix_only() -> TestResult
{
    let mut source = manifest();
    let family = source.manifest.families[0].clone();
    source.manifest.families = (0..2800)
        .map(|index| {
            let mut next = family.clone();
            next.id = format!("{index:04}_{}", "x".repeat(120));
            next
        })
        .collect();
    let wire = zeroize::Zeroizing::new(source.to_wire_bytes()?);
    assert!(wire.len() > CHUNK_BYTES as usize * 3 && wire.len() <= MANIFEST_BYTES);
    let hash = encode_base64url(manifest_hash(&source)?);
    let mut assembly = ManifestAssembler::default();
    for (index, bytes) in wire.chunks(CHUNK_BYTES as usize).enumerate() {
        let packet = part(&hash, &wire, index * CHUNK_BYTES as usize, bytes.len());
        let result = assembly.push(&packet)?;
        if index < 3 {
            assert!(result.is_none());
            assert!(assembly.push(&packet)?.is_none(), "exact retained prefix was appended twice");
        } else {
            assert_eq!(result.ok_or("complete manifest")?, source);
        }
    }
    assert!(
        assembly.push(&part(&hash, &wire, 0, CHUNK_BYTES as usize)).is_err(),
        "completed assembler delivered an object twice"
    );
    // Short, unaligned consecutive parts are valid in the adopted carrier as well.
    let mut assembly = ManifestAssembler::default();
    let mut offset = 0;
    while offset < wire.len() {
        let length = if offset == 0 { 17 } else { (wire.len() - offset).min(CHUNK_BYTES as usize) };
        let result = assembly.push(&part(&hash, &wire, offset, length))?;
        offset += length;
        assert_eq!(result.is_some(), offset == wire.len());
    }
    for mutation in 0..5 {
        let mut assembly = ManifestAssembler::default();
        let first = part(&hash, &wire, 0, CHUNK_BYTES as usize);
        if mutation != 0 {
            assembly.push(&first)?;
        }
        let mut packet = part(&hash, &wire, CHUNK_BYTES as usize, CHUNK_BYTES as usize);
        if let DataPacket::Manifest { manifest_hash, offset, total, bytes } = &mut packet {
            match mutation {
                0 => {} // Nonzero first offset.
                1 => *manifest_hash = encode_base64url([99; 32]),
                2 => total.0 -= 1,
                3 => offset.0 += u64::from(CHUNK_BYTES),
                _ => {
                    offset.0 = 0;
                    if let DataPacket::Manifest { bytes: value, .. } = &first {
                        let mut raw = value.decode(CHUNK_BYTES as usize)?;
                        raw[0] ^= 1;
                        *bytes = SecretBase64::from_bytes(&raw);
                    }
                }
            }
        }
        assert!(assembly.push(&packet).is_err(), "mutation{mutation}");
        assert!(assembly.push(&first).is_err(), "refused assembler was rearmed");
    }
    let small = manifest();
    let mut noncanonical = small.to_wire_bytes()?;
    noncanonical.insert(1, b' ');
    let hash = encode_base64url(manifest_hash(&small)?);
    assert!(
        ManifestAssembler::default()
            .push(&part(&hash, &noncanonical, 0, noncanonical.len()))
            .is_err()
    );
    let canonical = small.to_wire_bytes()?;
    let wrong_hash = encode_base64url([98; 32]);
    assert!(
        ManifestAssembler::default()
            .push(&part(&wrong_hash, &canonical, 0, canonical.len()))
            .is_err()
    );
    let mut oversized = part(&hash, &canonical, 0, 1);
    if let DataPacket::Manifest { total, .. } = &mut oversized {
        total.0 = MANIFEST_BYTES as u64 + 1;
    }
    assert!(ManifestAssembler::default().push(&oversized).is_err());
    Ok(())
}

#[test]
fn full_transfer_decimal_counts_are_exact_and_closed() -> TestResult {
    for value in [0, 1, (1_u64 << 53) + 1, u64::MAX] {
        let encoded = serde_json::to_vec(&U64(value))?;
        assert_eq!(parse_i_json_secret::<U64>(&encoded)?.0, value);
    }
    for input in [
        r#""00""#,
        r#""01""#,
        r#""+1""#,
        r#""-1""#,
        r#""1.0""#,
        r#""1e2""#,
        r#""18446744073709551616""#,
        "1",
        "null",
    ] {
        assert!(parse_i_json_secret::<U64>(input.as_bytes()).is_err());
    }
    Ok(())
}

#[test]
fn full_transfer_manifest_rejects_shape_context_and_chain_changes() -> TestResult {
    let source = manifest();
    let wire = source.to_wire_bytes()?;
    assert!(SourceManifest::from_wire_bytes(&wire).is_ok());
    let duplicated = String::from_utf8(wire.clone())?.replacen(
        "\"source_signature\":",
        "\"source_signature\":\"ignored\",\"source_signature\":",
        1,
    );
    assert!(SourceManifest::from_wire_bytes(duplicated.as_bytes()).is_err());
    let omitted = String::from_utf8(wire)?.replace("\"previous_cut\":null,", "");
    assert!(SourceManifest::from_wire_bytes(omitted.as_bytes()).is_err());
    let mut changed = source.clone();
    changed.manifest.destination_ref.account_anchor = encode_base64url([9; 32]);
    assert!(changed.validate().is_err());
    let mut changed = source.clone();
    changed.manifest.kind = ManifestKind::Delta;
    changed.manifest.snapshot_cut = U64(1);
    assert!(changed.validate().is_err());
    changed.manifest.previous_cut = Some(U64(0));
    changed.manifest.parent_manifest_hash = Some(encode_base64url(manifest_hash(&source)?));
    changed.validate()?;
    changed.verify_predecessor(&source)?;
    for (kind, cut, accepted) in [
        (ManifestKind::Delta, 8, true),
        (ManifestKind::Delta, 9, false),
        (ManifestKind::Tail, 1, true),
        (ManifestKind::Tail, 9, true),
        (ManifestKind::Tail, 10, false),
    ] {
        let mut bounded = changed.clone();
        bounded.manifest.kind = kind;
        bounded.manifest.previous_cut = Some(U64(cut - 1));
        bounded.manifest.snapshot_cut = U64(cut);
        assert_eq!(bounded.validate().is_ok(), accepted, "{kind:?} cut{cut}");
    }
    let mut stale_privacy = changed.clone();
    stale_privacy.manifest.source_erasure_generation = U64(0);
    assert!(stale_privacy.verify_predecessor(&source).is_err());
    let mut newer_privacy = changed.clone();
    newer_privacy.manifest.source_erasure_generation = U64(2);
    newer_privacy.verify_predecessor(&source)?;
    let mut rebound = changed.clone();
    rebound.manifest.base_record_hash = encode_base64url([10; 32]);
    assert!(rebound.verify_predecessor(&source).is_err());
    let mut different_catalog = changed.clone();
    different_catalog.manifest.families[0].restrictive = true;
    assert!(different_catalog.verify_predecessor(&source).is_err());
    let mut wrong_parent = changed.clone();
    wrong_parent.manifest.parent_manifest_hash = Some(encode_base64url([11; 32]));
    assert!(wrong_parent.verify_predecessor(&source).is_err());
    assert_ne!(manifest_hash(&source)?, manifest_hash(&changed)?);
    changed.manifest.snapshot_cut = U64(2);
    assert!(changed.validate().is_err());
    let mut changed = source;
    changed.manifest.families.push(changed.manifest.families[0].clone());
    assert!(changed.validate().is_err());
    Ok(())
}

// Independent byte assembly: deliberately does not call the production framing/digest helpers.
fn independent_hash(
    tag: &[u8],
    pieces: &[&[u8]],
) -> std::result::Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut bytes = u32::try_from(tag.len())?.to_be_bytes().to_vec();
    bytes.extend_from_slice(tag);
    for piece in pieces {
        bytes.extend_from_slice(piece);
    }
    Ok(*blake3::hash(&bytes).as_bytes())
}

#[test]
fn full_transfer_stream_roots_match_independent_framing_and_refuse_missing_chunks() -> TestResult {
    let empty = RootHasher::new(0)?.finish()?;
    assert_eq!(
        empty,
        independent_hash(
            b"ramflux.pairing.full.root.v1",
            &[&0_u64.to_be_bytes(), &0_u64.to_be_bytes()]
        )?
    );
    let first = vec![3; CHUNK_BYTES as usize];
    let last = b"final chunk";
    let first_digest = independent_hash(
        b"ramflux.pairing.full.chunk.v1",
        &[&0_u64.to_be_bytes(), &CHUNK_BYTES.to_be_bytes(), &first],
    )?;
    let last_digest = independent_hash(
        b"ramflux.pairing.full.chunk.v1",
        &[&1_u64.to_be_bytes(), &u32::try_from(last.len())?.to_be_bytes(), last],
    )?;
    let total = u64::from(CHUNK_BYTES) + u64::try_from(last.len())?;
    let expected = independent_hash(
        b"ramflux.pairing.full.root.v1",
        &[&total.to_be_bytes(), &2_u64.to_be_bytes(), &first_digest, &last_digest],
    )?;
    let mut root = RootHasher::new(total)?;
    assert!(root.push(1, last).is_err());
    assert!(root.push(0, &first[..first.len() - 1]).is_err());
    assert_eq!(root.push(0, &first)?, first_digest);
    assert!(root.push(0, &first).is_err());
    assert_eq!(root.push(1, last)?, last_digest);
    assert!(root.push(2, last).is_err());
    assert_eq!(root.finish()?, expected);
    let mut incomplete = RootHasher::new(total)?;
    incomplete.push(0, &first)?;
    assert!(incomplete.finish().is_err());
    let mut altered = RootHasher::new(total)?;
    altered.push(0, &first)?;
    altered.push(1, b"wrong chunk")?;
    assert_ne!(altered.finish()?, expected);
    Ok(())
}

#[test]
fn full_transfer_large_offsets_and_record_headers_have_no_old_total_cap() -> TestResult {
    assert_eq!(chunk_layout(1_u64 << 40)?, (1_u64 << 22, CHUNK_BYTES));
    assert!(chunk_layout(i64::MAX.cast_unsigned()).is_ok());
    assert!(chunk_layout(1_u64 << 63).is_err());
    assert!(chunk_layout(u64::MAX).is_err());
    let mut header = RecordHeader {
        family: "raw_inner_copy".into(),
        codec_version: U64(1),
        key: "source-qualified-stable-key".into(),
        op: RecordOp::Put,
        cell_types: vec![CellType::Bytes],
        cell_lengths: vec![U64(1_u64 << 40)],
    };
    let bytes = header.to_wire_bytes()?;
    assert!(bytes.len() < 512);
    assert!(RecordHeader::from_wire_bytes(&bytes).is_ok());
    header.op = RecordOp::Absent;
    assert!(header.validate().is_err());
    header.cell_types.clear();
    header.cell_lengths.clear();
    header.validate()?;
    Ok(())
}

#[test]
fn full_transfer_chain_commits_every_ordered_manifest_and_root() -> TestResult {
    let mut chain = ChainHasher::new(2)?;
    chain.push(0, &[1; 32], &[2; 32])?;
    assert!(chain.push(0, &[3; 32], &[4; 32]).is_err());
    chain.push(1, &[3; 32], &[4; 32])?;
    let expected = independent_hash(
        b"ramflux.pairing.full.chain.v1",
        &[&2_u64.to_be_bytes(), &[1; 32], &[2; 32], &[3; 32], &[4; 32]],
    )?;
    assert_eq!(chain.finish()?, expected);
    assert!(ChainHasher::new(1)?.finish().is_err());
    assert!(ChainHasher::new(0).is_err());
    Ok(())
}

#[test]
fn full_transfer_exact_cells_stream_with_bounded_scratch_and_validate_types() -> TestResult {
    use std::io::{Read as _, Write};
    #[derive(Default)]
    struct Count {
        total: usize,
        largest: usize,
    }
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.total += bytes.len();
            self.largest = self.largest.max(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut header = RecordHeader {
        family: "raw_inner_copy".into(),
        codec_version: U64(1),
        key: "source-qualified-key".into(),
        op: RecordOp::Put,
        cell_types: vec![CellType::Bytes],
        cell_lengths: vec![U64(5_242_883)],
    };
    let mut encoded = Vec::new();
    write_record_header(&mut encoded, &header)?;
    let decoded = read_record_header(&mut encoded.as_slice())?.ok_or("missing header")?;
    let mut generated = std::io::repeat(42).take(header.cell_lengths[0].0);
    let mut sink = Count::default();
    copy_record_cells(&mut generated, &mut sink, &decoded)?;
    assert_eq!(sink.total, 5_242_883);
    assert!(sink.largest <= 16_384);
    assert!(read_record_header(&mut [0, 1, 0, 1].as_slice()).is_err());
    assert!(read_record_header(&mut [0, 0].as_slice()).is_err());
    header.cell_types[0] = CellType::F64;
    header.cell_lengths[0] = U64(8);
    assert!(
        copy_record_cells(&mut f64::NAN.to_be_bytes().as_slice(), &mut std::io::sink(), &header)
            .is_err()
    );
    assert!(
        copy_record_cells(&mut 1.5_f64.to_be_bytes().as_slice(), &mut std::io::sink(), &header)
            .is_ok()
    );
    header.cell_types[0] = CellType::Utf8;
    let mut text = vec![b'a'; 16_383];
    text.extend_from_slice("🙂".as_bytes());
    header.cell_lengths[0] = U64(u64::try_from(text.len())?);
    copy_record_cells(&mut text.as_slice(), &mut std::io::sink(), &header)?;
    text.pop();
    header.cell_lengths[0] = U64(u64::try_from(text.len())?);
    assert!(copy_record_cells(&mut text.as_slice(), &mut std::io::sink(), &header).is_err());
    text.push(0xff);
    header.cell_lengths[0] = U64(u64::try_from(text.len())?);
    assert!(copy_record_cells(&mut text.as_slice(), &mut std::io::sink(), &header).is_err());
    Ok(())
}

#[test]
fn full_transfer_packet_canonical_secret_encoding_and_actual_bounds() -> TestResult {
    let bytes = vec![7; CHUNK_BYTES as usize];
    let digest = encode_base64url(chunk_digest(0, &bytes)?);
    let packet = DataPacket::Chunk {
        manifest_hash: encode_base64url([1; 32]),
        index: U64(0),
        length: U64(u64::from(CHUNK_BYTES)),
        digest,
        bytes: SecretBase64::from_bytes(&bytes),
    };
    let wire = packet.encode_secret()?;
    assert_eq!(wire.as_slice(), crate::canonical_json_bytes(&packet)?);
    assert!(DataPacket::from_wire_bytes(&wire).is_ok());
    assert!(wire.len() <= DataPacket::LIMIT);
    // Exactly the two base64 layers prescribed by the inner bytes field and outer ciphertext.
    let ciphertext_len = wire.len() + 16;
    assert!(ciphertext_len.div_ceil(3) * 4 + 4096 < PACKET_BYTES);
    let mut damaged = wire.to_vec();
    let at = damaged.iter().position(|v| *v == b'B').ok_or("base64 fixture")?;
    damaged[at] = b'C';
    assert!(DataPacket::from_wire_bytes(&damaged).is_err());
    let oversized_control = format!(
        "{{\"credit\":2,\"durable_through\":null,\"kind\":\"receipt\",\"manifest_hash\":\"{}\"}}",
        "A".repeat(9000)
    );
    assert_eq!(
        DataPacket::from_wire_bytes(oversized_control.as_bytes()).err(),
        Some(WireError::Size)
    );
    let control = DataPacket::Receipt {
        manifest_hash: encode_base64url([1; 32]),
        durable_through: None,
        credit: 2,
    };
    assert_eq!(control.encode_secret()?.as_slice(), crate::canonical_json_bytes(&control)?);
    let invalid = DataPacket::Receipt {
        manifest_hash: encode_base64url([1; 32]),
        durable_through: None,
        credit: 3,
    };
    assert!(invalid.encode_secret().is_err());
    assert!(
        DataPacket::Stop { code: FullError::Busy, retry_after_ms: Some(1000) }
            .encode_secret()
            .is_ok()
    );
    assert!(
        DataPacket::Stop { code: FullError::Busy, retry_after_ms: Some(999) }
            .encode_secret()
            .is_err()
    );
    assert!(
        DataPacket::Stop { code: FullError::LeaseExpired, retry_after_ms: Some(1000) }
            .encode_secret()
            .is_err()
    );
    Ok(())
}

#[test]
fn pairing_full_tail_endpoint_size_cap_refused_before_staging() -> TestResult {
    for total in [MAX_TAIL_BYTES, MAX_TAIL_BYTES + 1] {
        let mut tail = manifest();
        tail.manifest.kind = ManifestKind::Tail;
        tail.manifest.previous_cut = Some(U64(1));
        tail.manifest.snapshot_cut = U64(2);
        tail.manifest.parent_manifest_hash = Some(encode_base64url([7; 32]));
        tail.manifest.total_bytes = U64(total);
        tail.manifest.families[0].encoded_bytes = U64(total);
        tail.manifest.chunk_count = U64(chunk_layout(total)?.0);
        if total == MAX_TAIL_BYTES {
            tail.validate()?;
        } else {
            assert_eq!(tail.validate(), Err(WireError::Field("NoSpace")));
        }
    }
    Ok(())
}

#[test]
fn pairing_full_stop_requires_explicit_nullable_retry() -> TestResult {
    let bytes = br#"{"code":"ResumeRequired","kind":"stop","retry_after_ms":null}"#;
    assert_eq!(DataPacket::from_wire_bytes(bytes)?.encode_secret()?.as_slice(), bytes);
    assert!(DataPacket::from_wire_bytes(br#"{"code":"ResumeRequired","kind":"stop"}"#).is_err());
    assert!(
        DataPacket::from_wire_bytes(
            br#"{"code":"ResumeRequired","kind":"stop","retry_after_ms":1000}"#
        )
        .is_err()
    );
    assert!(
        DataPacket::from_wire_bytes(br#"{"code":"Busy","kind":"stop","retry_after_ms":null}"#)
            .is_err()
    );
    DataPacket::from_wire_bytes(br#"{"code":"Busy","kind":"stop","retry_after_ms":1000}"#)?;
    Ok(())
}

fn successor(previous: &SourceManifest, kind: ManifestKind, total: u64) -> Result<SourceManifest> {
    let mut next = previous.clone();
    next.manifest.kind = kind;
    next.manifest.previous_cut = Some(previous.manifest.snapshot_cut);
    next.manifest.snapshot_cut = U64(previous.manifest.snapshot_cut.0 + 1);
    next.manifest.parent_manifest_hash = Some(encode_base64url(manifest_hash(previous)?));
    next.manifest.total_bytes = U64(total);
    next.manifest.chunk_count = U64(chunk_layout(total)?.0);
    next.manifest.families[0].encoded_bytes = U64(total);
    Ok(next)
}
#[test]
fn full_transfer_final_prepublication_delta_is_signed_stop_rule_and_base_never_authorizes_tail()
-> TestResult {
    let base = manifest();
    assert!(!base.manifest.is_last_prepublication_delta());
    assert!(
        successor(&base, ManifestKind::Tail, 0)?.verify_predecessor(&base).is_err(),
        "base-only tail accepted"
    );
    let first = successor(&base, ManifestKind::Delta, 0)?;
    first.verify_predecessor(&base)?;
    assert!(first.manifest.is_last_prepublication_delta(), "empty delta_1 was not final");
    assert!(
        successor(&first, ManifestKind::Delta, 0)?.verify_predecessor(&first).is_err(),
        "delta after signed stop accepted"
    );
    successor(&first, ManifestKind::Tail, 0)?.verify_predecessor(&first)?;
    for total in [PREPUBLICATION_DELTA_STOP_BYTES, PREPUBLICATION_DELTA_STOP_BYTES + 1] {
        let large = successor(&base, ManifestKind::Delta, total)?;
        large.verify_predecessor(&base)?;
        assert_eq!(
            large.manifest.is_last_prepublication_delta(),
            total == PREPUBLICATION_DELTA_STOP_BYTES
        );
        let delta = successor(&large, ManifestKind::Delta, 0)?;
        let tail = successor(&large, ManifestKind::Tail, 0)?;
        assert_eq!(
            delta.verify_predecessor(&large).is_ok(),
            total > PREPUBLICATION_DELTA_STOP_BYTES
        );
        assert_eq!(
            tail.verify_predecessor(&large).is_ok(),
            total <= PREPUBLICATION_DELTA_STOP_BYTES
        );
    }
    let mut eighth = successor(&base, ManifestKind::Delta, PREPUBLICATION_DELTA_STOP_BYTES + 1)?;
    eighth.manifest.previous_cut = Some(U64(7));
    eighth.manifest.snapshot_cut = U64(8);
    eighth.validate()?;
    assert!(eighth.manifest.is_last_prepublication_delta());
    successor(&eighth, ManifestKind::Tail, 0)?.verify_predecessor(&eighth)?;
    assert!(
        successor(&eighth, ManifestKind::Delta, 0)?.verify_predecessor(&eighth).is_err(),
        "ninth delta accepted"
    );
    Ok(())
}
