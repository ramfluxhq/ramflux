// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Qualified-stream construction only. Test records have no network-acceptable data lease.
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex};
use ramflux_protocol::{
    canonical_json_bytes, custody::pairing::full_transfer::*, encode_base64url,
};
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture(
    label: &str,
) -> ResultOf<(
    ramflux_test_support::TestPath,
    AccountDb,
    ramflux_crypto::custody::pairing::FullResumeRecord,
)> {
    let (record, _, _) = super::super::stage_tests::fixture()?;
    let root = crate::tests::temp_root(label);
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", &record.grant.source_ref.account_anchor)?;
    let key = AccountDbKey::derive("acct", label.as_bytes());
    Ok((root, AccountDb::open(&index, "acct", &key)?, record))
}
fn expected_record(commitment: &str) -> ResultOf<Zeroizing<Vec<u8>>> {
    let header = RecordHeader {
        family: "sql/object_erasure_fence".into(),
        codec_version: U64(2),
        key: encode_stable_key([(CellType::Utf8, commitment.as_bytes())])?.to_string(),
        op: RecordOp::Put,
        cell_types: vec![CellType::Utf8],
        cell_lengths: vec![U64(commitment.len() as u64)],
    };
    let mut bytes = Zeroizing::new(Vec::new());
    write_record_header(&mut *bytes, &header)?;
    bytes.extend_from_slice(commitment.as_bytes());
    Ok(bytes)
}

#[test]
fn pairing_full_union_encoding_qualifies_orders_dedupes_and_roots_actual_fixed_rows() -> ResultOf {
    let (_root, db, record) = fixture("full-union-encoding")?;
    let owners = [record.grant.source_ref.clone(), record.grant.destination_ref.clone()];
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    // Local normalized values, not source-provided SQL or an actual G1 install proof.
    let input = rusqlite::Connection::open_in_memory()?;
    input.execute_batch("CREATE TABLE object_erasure_fence(commitment TEXT UNIQUE NOT NULL);")?;
    for index in 0..2048_u64 {
        input.execute(
            "INSERT INTO object_erasure_fence VALUES(?1)",
            [encode_base64url(blake3::hash(&index.to_be_bytes()).as_bytes())],
        )?;
    }
    let mut builder = stage.begin_fixed_union_encoding()?;
    let mut query =
        input.prepare("SELECT commitment FROM object_erasure_fence ORDER BY commitment DESC")?;
    let mut rows = query.query([])?;
    let mut expected = Vec::new();
    let mut index = 0;
    while let Some(row) = rows.next()? {
        let value = row.get_ref(0)?.as_str()?;
        let owner = &owners[index % 2];
        builder.put_sql_row(owner, "sql/object_erasure_fence", row)?;
        if index == 0 {
            builder.put_sql_row(owner, "sql/object_erasure_fence", row)?;
            builder.put_sql_row(&owners[1], "sql/object_erasure_fence", row)?;
            expected.push((
                canonical_json_bytes(&owners[1])?,
                encode_stable_key([(CellType::Utf8, value.as_bytes())])?.to_string(),
                expected_record(value)?,
            ));
        }
        expected.push((
            canonical_json_bytes(owner)?,
            encode_stable_key([(CellType::Utf8, value.as_bytes())])?.to_string(),
            expected_record(value)?,
        ));
        index += 1;
    }
    // Ref bytes precede family/key in order; this fixture has one family only.
    expected.sort_by(|(a_owner, a_key, _), (b_owner, b_key, _)| {
        (a_owner, a_key).cmp(&(b_owner, b_key))
    });
    let mut logical = Zeroizing::new(Vec::new());
    for (owner, _, record) in expected {
        logical.extend_from_slice(&u32::try_from(owner.len())?.to_be_bytes());
        logical.extend_from_slice(&owner);
        logical.extend_from_slice(&record);
    }
    let encoded = builder.finish()?;
    assert_eq!(encoded.records, 2049, "same-owner retry deduped; independent co-owner retained");
    assert_eq!(encoded.total_bytes, logical.len() as u64);
    assert!(logical.len() > CHUNK_BYTES as usize, "fixture must exercise chunk boundaries");
    let mut root = RootHasher::new(logical.len() as u64)?;
    for (index, chunk) in logical.chunks(CHUNK_BYTES as usize).enumerate() {
        root.push(index as u64, chunk)?;
    }
    assert_eq!(encoded.chunks_root, root.finish()?, "qualified canonical stream differs");
    assert_eq!(
        stage.connection.query_row(
            "SELECT records FROM full_union_encoding WHERE generation_nonce=?1",
            params![encoded.generation_nonce.as_slice()],
            |r| r.get::<_, u64>(0)
        )?,
        2049
    );
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM manifest WHERE verified=1", [], |r| r
                .get::<_, u64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn pairing_full_union_encoding_poison_rolls_back_changed_row_and_unfinished_builder() -> ResultOf {
    let (_root, db, record) = fixture("full-union-encoding-poison")?;
    let owner = record.grant.destination_ref.clone();
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let input = rusqlite::Connection::open_in_memory()?;
    input.execute_batch("CREATE TABLE account_erasure_generation(singleton INTEGER,generation INTEGER);INSERT INTO account_erasure_generation VALUES(1,7);")?;
    {
        let mut builder = stage.begin_fixed_union_encoding()?;
        for generation in [7, 8] {
            input.execute("UPDATE account_erasure_generation SET generation=?1", [generation])?;
            let mut query =
                input.prepare("SELECT singleton,generation FROM account_erasure_generation")?;
            let mut rows = query.query([])?;
            let row = rows.next()?.ok_or("row")?;
            let result = builder.put_sql_row(&owner, "sql/account_erasure_generation", row);
            if generation == 7 {
                result?;
            } else {
                assert!(matches!(result, Err(StorageError::PairingField("TransferConflict"))));
            }
        }
        assert!(builder.finish().is_err(), "poisoned partial stream committed");
    }
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM full_union_record", [], |r| r.get::<_, u64>(0))?,
        0
    );
    let mut builder = stage.begin_fixed_union_encoding()?;
    let mut query = input.prepare("SELECT singleton,generation FROM account_erasure_generation")?;
    let mut rows = query.query([])?;
    builder.put_sql_row(&owner, "sql/account_erasure_generation", rows.next()?.ok_or("row")?)?;
    drop(builder);
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM full_union_record", [], |r| r.get::<_, u64>(0))?,
        0
    );
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM full_union_encoding", [], |r| r.get::<_, u64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn pairing_full_union_encoding_refuses_foreign_qualifier_and_source_role() -> ResultOf {
    let (_root, db, record) = fixture("full-union-encoding-role")?;
    let mut foreign = record.grant.destination_ref.clone();
    foreign.device_id = "unapproved-owner".into();
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let input = rusqlite::Connection::open_in_memory()?;
    let mut query = input.prepare("SELECT 1 AS singleton,0 AS generation")?;
    let mut rows = query.query([])?;
    let mut builder = stage.begin_fixed_union_encoding()?;
    assert!(
        builder
            .put_sql_row(&foreign, "sql/account_erasure_generation", rows.next()?.ok_or("row")?)
            .is_err()
    );
    assert!(builder.finish().is_err());
    drop(stage);
    let (mut record, _, _) = super::super::stage_tests::fixture()?;
    record.role = PairingRole::Initiator;
    record.transfer_id = encode_base64url([90; 32]);
    record.grant.transfer_id = record.transfer_id.clone();
    // This mutated local record would not pass native/lease/SAS trust; role refusal only.
    let mut source = db.create_full_stage_for_test(record, 604_900)?;
    assert!(source.begin_fixed_union_encoding().is_err());
    Ok(())
}

#[test]
fn pairing_full_union_encoding_cancel_rolls_back_and_refuses_reuse() -> ResultOf {
    let (_root, db, record) = fixture("full-union-encoding-cancel")?;
    let owner = record.grant.destination_ref.clone();
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let cancel = stage.io_cancel_handle();
    let input = rusqlite::Connection::open_in_memory()?;
    let mut query = input.prepare("SELECT 1 AS singleton,0 AS generation")?;
    let mut rows = query.query([])?;
    let mut builder = stage.begin_fixed_union_encoding()?;
    builder.put_sql_row(&owner, "sql/account_erasure_generation", rows.next()?.ok_or("row")?)?;
    cancel.cancel();
    assert!(cancel.is_cancelled());
    assert!(matches!(builder.finish(), Err(StorageError::PairingField("Cancelled"))));
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM full_union_record", [], |r| r.get::<_, u64>(0))?,
        0
    );
    assert!(matches!(
        stage.begin_fixed_union_encoding(),
        Err(StorageError::PairingField("Cancelled"))
    ));
    Ok(())
}
