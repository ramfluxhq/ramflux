// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual immutable cuts and encrypted indexed spools; not endpoint/DV/retirement proof.
use super::{
    FullTransferStage, full_transfer_catalog, source_scalar_tests::Sink, stage_tests::fixture,
};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::{custody::pairing::full_transfer::*, encode_base64url};
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn capture(
    stage: &FullTransferStage<'_>,
    db: &crate::AccountDb,
    root: &Path,
    cut: u64,
) -> ResultOf<String> {
    let id = encode_base64url(ramflux_crypto::random_32()?);
    let private = root.join(format!("delta-private-{cut}.db"));
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&private, Arc::new(AtomicBool::new(false)))?;
    stage.adopt_source_cut(cut, &id, &private, snapshot)?;
    Ok(id)
}

#[test]
fn pairing_full_fixed_delta_uses_saved_cuts_and_emits_exact_put_absent_and_empty_diff() -> ResultOf
{
    let (root, db) = crate::tests::test_db("full-fixed-delta")?;
    let old = encode_base64url([11; 32]);
    let retained = encode_base64url([22; 32]);
    let new = encode_base64url([33; 32]);
    for value in [&old, &retained] {
        db.connection.execute(
            "INSERT INTO object_identity_replacement VALUES(?1)",
            rusqlite::params![value],
        )?;
    }
    let (mut record, _, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let base = capture(&stage, &db, &root, 0)?;
    db.connection.execute(
        "DELETE FROM object_identity_replacement WHERE commitment=?1",
        rusqlite::params![old],
    )?;
    db.connection
        .execute("INSERT INTO object_identity_replacement VALUES(?1)", rusqlite::params![new])?;
    db.connection.execute("UPDATE account_erasure_generation SET generation=generation+1", [])?;
    let expected_generation: i64 =
        db.connection
            .query_row("SELECT generation FROM account_erasure_generation", [], |r| r.get(0))?;
    let next = capture(&stage, &db, &root, 1)?;
    let unchanged = capture(&stage, &db, &root, 2)?;
    // Ordinary later writes must never be substituted for either retained cut.
    db.connection.execute(
        "INSERT INTO object_identity_replacement VALUES(?1)",
        rusqlite::params![encode_base64url([44; 32])],
    )?;
    let (encoded, metadata) = stage.encode_fixed_delta_source(1, &base, &next, Sink::default())?;
    let (retry, retry_meta) = stage.encode_fixed_delta_source(1, &base, &next, Sink::default())?;
    assert_eq!(encoded.0.as_slice(), retry.0.as_slice());
    assert_eq!(metadata.chunks_root, retry_meta.chunks_root);
    assert_eq!(metadata.total_bytes, encoded.0.len() as u64);
    let mut root_hash = RootHasher::new(metadata.total_bytes)?;
    for (index, bytes) in encoded.0.chunks(CHUNK_BYTES as usize).enumerate() {
        root_hash.push(index as u64, bytes)?;
    }
    assert_eq!(metadata.chunks_root, root_hash.finish()?);
    let first_wire = (metadata.chunks_root, encoded.0.clone());
    let mut input = encoded.0.as_slice();
    let mut operations = Vec::new();
    while let Some(header) = read_record_header(&mut input)? {
        let rule = full_transfer_catalog().iter().find(|r| r.id == header.family).ok_or("rule")?;
        let cells = input;
        super::copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
        if header.family == "sql/account_erasure_generation" {
            let actual =
                i64::from_be_bytes(cells.get(8..16).ok_or("generation bytes")?.try_into()?);
            assert_eq!(actual, expected_generation, "changed row must carry the CURRENT cut value");
        }
        operations.push((header.family, header.key, header.op));
    }
    assert_eq!(operations.len(), 3, "exact generation change + one missing + one new row");
    let family = "sql/object_identity_replacement";
    let old_key = encode_stable_key([(CellType::Utf8, old.as_bytes())])?.to_string();
    let new_key = encode_stable_key([(CellType::Utf8, new.as_bytes())])?.to_string();
    assert!(operations.contains(&(family.into(), old_key, RecordOp::Absent)));
    assert!(operations.contains(&(family.into(), new_key, RecordOp::Put)));
    assert_eq!(
        operations.iter().filter(|(id, _, _)| id == "sql/account_erasure_generation").count(),
        1
    );
    assert!(operations.windows(2).all(|pair| (&pair[0].0, &pair[0].1) < (&pair[1].0, &pair[1].1)));
    assert_eq!(metadata.schema.families.iter().map(|f| f.portable_records.0).sum::<u64>(), 3);
    assert_eq!(
        metadata.schema.families.iter().map(|f| f.encoded_bytes.0).sum::<u64>(),
        metadata.total_bytes
    );
    let (empty, metadata) =
        stage.encode_fixed_delta_source(2, &next, &unchanged, Sink::default())?;
    assert_preserved_wire(&stage, 1, &first_wire.1, first_wire.0)?;
    assert!(empty.0.is_empty());
    assert_eq!(metadata.total_bytes, 0);
    assert_eq!(metadata.chunk_count, 0);
    assert_eq!(metadata.chunks_root, RootHasher::new(0)?.finish()?);
    assert!(
        metadata
            .schema
            .families
            .iter()
            .all(|f| f.source_rows.0 == 0 && f.portable_records.0 == 0 && f.encoded_bytes.0 == 0)
    );
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM source_cut", [], |r| r.get::<_, u64>(0))?,
        3,
        "diff must not retire any immutable snapshot"
    );
    Ok(())
}

#[test]
fn pairing_full_fixed_delta_refuses_decreased_erasure_generation_before_output() -> ResultOf {
    let (root, db) = crate::tests::test_db("full-fixed-delta-erasure")?;
    db.connection.execute("UPDATE account_erasure_generation SET generation=7", [])?;
    let (mut record, _, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let base = capture(&stage, &db, &root, 0)?;
    db.connection.execute("UPDATE account_erasure_generation SET generation=6", [])?;
    let next = capture(&stage, &db, &root, 1)?;
    assert!(matches!(
        stage.encode_fixed_delta_source(1, &base, &next, Sink::default()),
        Err(crate::StorageError::PairingField("ManifestMismatch"))
    ));
    for cut in [0, 9, u64::MAX] {
        assert!(stage.encode_fixed_delta_source(cut, &base, &next, Sink::default()).is_err());
    }
    assert!(
        stage.encode_fixed_delta_source(1, &next, &base, Sink::default()).is_err(),
        "wrong cut identity"
    );
    Ok(())
}

fn assert_preserved_wire(
    stage: &FullTransferStage<'_>,
    cut: u64,
    expected: &[u8],
    expected_root: [u8; 32],
) -> ResultOf {
    let connection = stage.key.open_metadata(&stage.directory.join("source-wire.db"))?;
    let (total, root): (u64, Vec<u8>) = connection.query_row(
        "SELECT total_bytes,root FROM wire_complete WHERE cut=?1",
        rusqlite::params![i64::try_from(cut)?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(root, expected_root, "successor preflight replaced the signed delta root");
    assert_eq!(total, u64::try_from(expected.len())?);
    let actual: Vec<u8> = connection.query_row(
        "SELECT bytes FROM wire_chunk WHERE cut=?1 AND idx=0",
        rusqlite::params![i64::try_from(cut)?],
        |row| row.get(0),
    )?;
    assert_eq!(actual, expected, "successor preflight replaced the prior delta bytes");
    Ok(())
}
