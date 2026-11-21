// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real private SQLite spools retain native bytes without lending their budget to metadata.
use super::super::{native_payload::test_support, record_spool};
use super::*;
use prost::Message as _;
#[cfg(feature = "sqlcipher")]
use std::io::{Read as _, Write as _};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn record_profile_metadata_does_not_borrow_the_native_allowance() -> TestResult {
    let native = test_support::rule()?;
    let metadata = super::super::full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == "sql/object_payload_dependency")
        .ok_or("metadata declaration")?;
    assert!(
        require_length(metadata, METADATA_LIMIT as u64 + 1).is_err(),
        "metadata acquired the native byte allowance"
    );
    require_length(&native, METADATA_LIMIT as u64 + 1)?;
    let db = rusqlite::Connection::open_in_memory()?;
    db.execute_batch(&super::super::source_scalar::schema())?;
    assert!(db.execute("INSERT INTO source_scalar_row VALUES('cut','sql/object_payload_dependency','key',zeroblob(?1))",[METADATA_LIMIT + 1]).is_err(),
        "metadata SQL constraint accepted an oversized record");
    db.execute("INSERT INTO source_scalar_row VALUES('cut','sql/runtime_message_content','key',zeroblob(?1))",[METADATA_LIMIT + 1])?;
    assert!(db.execute("INSERT INTO source_scalar_row VALUES('cut','sql/runtime_message_content','too-big',zeroblob(?1))",[limit(&native)? + 1]).is_err(),
        "native SQL constraint exceeded its compiled format bound");
    Ok(())
}

#[cfg(feature = "sqlcipher")]
#[test]
fn record_profile_native_sql_and_input_spools_retain_exact_keyed_bytes() -> TestResult {
    const MAX_NATIVE_RECORD_BYTES: u64 =
        (METADATA_LIMIT + super::super::FULL_DIRECT_HISTORY_LIMIT) as u64;
    let root = tempfile::tempdir()?;
    let mut db = rusqlite::Connection::open(root.path().join("native-spool.db"))?;
    let key = crate::AccountDbKey::derive("native-spool", b"native-spool-fixture");
    let hex = Zeroizing::new(key.sqlcipher_hex());
    let pragma = Zeroizing::new(format!("PRAGMA key=\"x'{}'\";", hex.as_str()));
    db.execute_batch(&pragma)?;
    let cipher: String = db.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    assert!(!cipher.is_empty(), "private spool fixture is not encrypted");
    db.execute_batch(&super::super::union_encoding::schema())?;
    super::super::union_encoding::require_existing_format(&db)?;
    let inner = test_support::inner(ramflux_protocol::message::validation::MAX_TEXT_BYTES)?;
    let body = test_support::frame(&inner)?;
    test_support::install_source(&db, &inner)?;
    let rule = test_support::rule()?;
    let tx = db.transaction()?;
    let candidate = tx.query_row(
        "SELECT message_id,conversation_id,body FROM runtime_message_content",
        [],
        |row| {
            Ok(record_spool::Candidate::sql(
                &tx,
                &tx,
                &rule,
                row,
                &ramflux_protocol::encode_base64url([31; 32]),
            ))
        },
    )??;
    let stable = Zeroizing::new(candidate.header.0.key.clone());
    candidate.retain_original(&[3; 32], "first")?;
    candidate.retain_union(&[3; 32], "first", false)?;
    let (rowid, length): (i64, u64) = tx.query_row(
        "SELECT rowid,length(record) FROM full_union_record WHERE owner='first'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert!(length > METADATA_LIMIT as u64, "spool fixture did not cross metadata limit");
    let mut encoded = Zeroizing::new(Vec::new());
    record_spool::checked_blob(&tx, "full_union_record", rowid, length, &rule, &stable)?
        .take(MAX_NATIVE_RECORD_BYTES + 1)
        .read_to_end(&mut encoded)?;
    assert_eq!(encoded.len() as u64, length, "keyed spool lost native bytes");
    assert!(encoded.ends_with(&body), "source SQL adapter rewrote exact native frame bytes");
    let mut probe = record_spool::Probe::new();
    probe.write_all(&encoded)?;
    let header = probe.header(length, &rule)?;
    let prefix = {
        let mut bytes = Vec::new();
        write_record_header(&mut bytes, &header.0)?;
        bytes.len()
    };
    let mut input = encoded.get(prefix..).ok_or("payload offset")?;
    record_spool::Candidate::input(&tx, &rule, header.0.clone(), &mut input)?
        .retain_union(&[3; 32], "second", false)?;
    assert!(input.is_empty(), "input spool left native bytes unchecked");
    let equal: bool = tx.query_row("SELECT record=(SELECT record FROM full_union_input WHERE owner='first') FROM full_union_record WHERE owner='second'",[],|row|row.get(0))?;
    assert!(equal, "SQL/input spools changed original contribution bytes");
    tx.execute(
        "UPDATE full_union_record SET record=zeroblob(length(record)) WHERE owner='second'",
        [],
    )?;
    let (tampered, length): (i64, u64) = tx.query_row(
        "SELECT rowid,length(record) FROM full_union_record WHERE owner='second'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert!(
        record_spool::checked_blob(&tx, "full_union_record", tampered, length, &rule, &stable)
            .is_err(),
        "corrupt native framing became a checked contribution"
    );
    tx.commit()?;
    Ok(())
}

#[test]
fn record_profile_old_metadata_only_ledger_refuses_without_conversion() -> TestResult {
    let db = rusqlite::Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE full_union_record(generation_nonce BLOB,owner TEXT,family TEXT,key TEXT,record BLOB CHECK(length(record)<=262144)); INSERT INTO full_union_record VALUES(x'01','first','old','key',x'11');")?;
    db.execute_batch(&super::super::union_encoding::schema())?;
    assert!(
        matches!(
            super::super::union_encoding::require_existing_format(&db),
            Err(StorageError::PairingField("SchemaMismatch"))
        ),
        "old ledger was accepted or converted"
    );
    let bytes: Vec<u8> =
        db.query_row("SELECT record FROM full_union_record", [], |row| row.get(0))?;
    assert_eq!(bytes, vec![17], "old ledger content was changed to unblock transfer");
    Ok(())
}

#[test]
fn record_profile_old_pending_slot_refuses_without_conversion() -> TestResult {
    let mut db = rusqlite::Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE full_stream_pending(slot INTEGER PRIMARY KEY,record BLOB CHECK(length(record)<=262144)); INSERT INTO full_stream_pending VALUES(1,x'11');")?;
    let rule = test_support::rule()?;
    let inner = test_support::inner(16)?;
    let identity = inner.identity.as_ref().ok_or("fixture identity")?;
    test_support::install_source(&db, &inner)?;
    let tx = db.transaction()?;
    let result = tx.query_row(
        "SELECT ?1 AS message_id,?2 AS conversation_id,?3 AS body",
        rusqlite::params![
            ramflux_protocol::encode_base64url(&identity.id),
            &identity.conversation_id,
            inner.encode_to_vec()
        ],
        |row| {
            Ok(record_spool::Candidate::sql(
                &tx,
                &tx,
                &rule,
                row,
                &ramflux_protocol::encode_base64url([31; 32]),
            ))
        },
    )?;
    assert!(
        matches!(result, Err(StorageError::PairingField("SchemaMismatch"))),
        "old pending slot was accepted or converted"
    );
    let bytes: Vec<u8> =
        tx.query_row("SELECT record FROM full_stream_pending", [], |row| row.get(0))?;
    assert_eq!(bytes, vec![17], "old pending bytes were changed to unblock transfer");
    Ok(())
}

#[test]
fn record_profile_native_adapter_reads_source_not_metadata_spool() -> TestResult {
    let source = rusqlite::Connection::open_in_memory()?;
    let inner = test_support::inner(32)?;
    test_support::install_source(&source, &inner)?;
    let mut spool = rusqlite::Connection::open_in_memory()?;
    spool.execute_batch(&super::super::union_encoding::schema())?;
    let rule = test_support::rule()?;
    let tx = spool.transaction()?;
    let candidate = source.query_row(
        "SELECT message_id,conversation_id,body FROM runtime_message_content",
        [],
        |row| {
            Ok(record_spool::Candidate::sql(
                &source,
                &tx,
                &rule,
                row,
                &ramflux_protocol::encode_base64url([31; 32]),
            ))
        },
    )??;
    candidate.retain_original(&[7; 32], "source-owner")?;
    let bytes: Vec<u8> = tx.query_row(
        "SELECT record FROM full_union_input WHERE owner='source-owner'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        bytes.ends_with(&test_support::frame(&inner)?),
        "native source context was taken from the unrelated spool"
    );
    let wrong = source.query_row(
        "SELECT message_id,conversation_id,body FROM runtime_message_content",
        [],
        |row| {
            Ok(record_spool::Candidate::sql(
                &source,
                &tx,
                &rule,
                row,
                &ramflux_protocol::encode_base64url([32; 32]),
            ))
        },
    )?;
    assert!(
        matches!(wrong, Err(StorageError::PairingField("UnsupportedRecord"))),
        "source's embedded account replaced the authenticated transfer account"
    );
    let body: Vec<u8> =
        source.query_row("SELECT body FROM runtime_message_content", [], |row| row.get(0))?;
    assert_eq!(body, inner.encode_to_vec(), "source assembly rewrote live native body");
    Ok(())
}
