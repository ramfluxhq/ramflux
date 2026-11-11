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
