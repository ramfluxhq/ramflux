// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{copy_full_scalar_record, full_transfer_catalog, stage_tests::fixture};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::{
    PairingWire as _,
    full_transfer::{CellType, RecordHeader, encode_stable_key, read_record_header},
};
use std::sync::{Arc, atomic::AtomicBool};
use zeroize::Zeroizing;
#[derive(Default)]
pub(super) struct Sink(pub(super) Zeroizing<Vec<u8>>);
impl std::io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
type TestResult = Result<(), Box<dyn std::error::Error>>;
const FAMILY: &str = "sql/object_identity_replacement";

#[test]
fn pairing_full_fixed_source_spool_uses_immutable_cut_and_encoded_key_order() -> TestResult {
    let (root, db) = crate::account_db::full_transfer::test_support::owned_source_test_db(
        "full-source-scalar-order",
    )?;
    let mut expected = Vec::new();
    // Find differing SQL/text and base64-framed-key orders; never assume they agree.
    for value in u8::MIN..=u8::MAX {
        let commitment = ramflux_protocol::encode_base64url([value; 32]);
        let key = encode_stable_key([(CellType::Utf8, commitment.as_bytes())])?;
        expected.push(key.to_string());
        db.connection.execute(
            "INSERT INTO object_identity_replacement(commitment) VALUES(?1)",
            rusqlite::params![commitment],
        )?;
    }
    let mut sql_order = expected.clone();
    sql_order.sort_by_key(|key| ramflux_protocol::decode_base64url(key).ok());
    expected.sort();
    assert_ne!(sql_order, expected, "fixture must distinguish SQL order from encoded key order");
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let snapshot_id = &manifest.manifest.snapshot_id;
    let private = root.path().join("scalar-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&private, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    stage.adopt_source_cut(0, snapshot_id, &private, snapshot)?;
    db.connection.execute_batch("DELETE FROM object_identity_replacement")?;
    let counts = stage.stage_source_fixed_base_family(snapshot_id, FAMILY)?;
    assert_eq!(counts.records, 256);
    assert_eq!(stage.stage_source_fixed_base_family(snapshot_id, FAMILY)?, counts);
    let (output, written) =
        stage.write_source_fixed_base_family(snapshot_id, FAMILY, Sink::default())?;
    assert_eq!(written, counts);
    assert_eq!(output.0.len() as u64, counts.encoded_bytes);
    let rule = full_transfer_catalog().iter().find(|rule| rule.id == FAMILY).ok_or("rule")?;
    let mut input = output.0.as_slice();
    let mut actual = Vec::new();
    while let Some(header) = read_record_header(&mut input)? {
        actual.push(header.key.clone());
        copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
    }
    assert_eq!(actual, expected);
    assert!(stage.stage_source_fixed_base_family(snapshot_id, "sql/runtime_actor_state").is_err());
    Ok(())
}

#[test]
fn pairing_full_fixed_source_spool_rolls_back_invalid_family_without_ready_counts() -> TestResult {
    let (root, db) = crate::account_db::full_transfer::test_support::owned_source_test_db(
        "full-source-scalar-rollback",
    )?;
    let valid = ramflux_protocol::encode_base64url([0; 32]);
    let mut invalid = valid.clone().into_bytes();
    invalid[42] = b'B'; // Same physical TEXT width, invalid canonical base64 tail bits.
    db.connection
        .execute("INSERT INTO object_identity_replacement VALUES(?1)", rusqlite::params![valid])?;
    db.connection.execute(
        "INSERT INTO object_identity_replacement VALUES(?1)",
        rusqlite::params![std::str::from_utf8(&invalid)?],
    )?;
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let private = root.path().join("invalid-scalar-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&private, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let snapshot_id = &manifest.manifest.snapshot_id;
    stage.adopt_source_cut(0, snapshot_id, &private, snapshot)?;
    assert!(stage.stage_source_fixed_base_family(snapshot_id, FAMILY).is_err());
    for table in ["source_scalar_family", "source_scalar_row"] {
        assert_eq!(
            stage
                .connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, u64>(0))?,
            0
        );
    }
    assert!(stage.write_source_fixed_base_family(snapshot_id, FAMILY, Sink::default()).is_err());
    Ok(())
}

struct ChangeGeneration {
    index: Arc<crate::AccountIndex>,
    writes: Arc<std::sync::atomic::AtomicUsize>,
}
impl std::io::Write for ChangeGeneration {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        use std::sync::atomic::Ordering;
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.index.connection().execute("UPDATE local_account SET db_relative_path='accounts/acct/replaced.db' WHERE local_account_id='acct'",[])
            .map_err(std::io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn pairing_full_fixed_source_spool_rechecks_generation_before_each_output_row() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (root, db) = crate::account_db::full_transfer::test_support::owned_source_test_db(
        "full-source-generation-guard",
    )?;
    for value in [1, 2] {
        db.connection.execute(
            "INSERT INTO object_identity_replacement VALUES(?1)",
            rusqlite::params![ramflux_protocol::encode_base64url([value; 32])],
        )?;
    }
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let private = root.path().join("generation-guard-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&private, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let snapshot_id = &manifest.manifest.snapshot_id;
    stage.adopt_source_cut(0, snapshot_id, &private, snapshot)?;
    stage.stage_source_fixed_base_family(snapshot_id, FAMILY)?;
    let emitted = Arc::new(AtomicUsize::new(0));
    let destination = ChangeGeneration { index: db.account_index.clone(), writes: emitted.clone() };
    assert!(matches!(
        stage.write_source_fixed_base_family(snapshot_id, FAMILY, destination),
        Err(crate::StorageError::PairingField("SnapshotInvalidated"))
    ));
    assert_eq!(
        emitted.load(Ordering::SeqCst),
        1,
        "stale source emitted a second row after generation replacement"
    );
    Ok(())
}

#[test]
fn pairing_full_fixed_source_spool_encodes_lookup_and_dependency_families() -> TestResult {
    let (root, db) = crate::account_db::full_transfer::test_support::owned_source_test_db(
        "full-source-erasure-links",
    )?;
    let lookup = ramflux_crypto::object_erasure_lookup("root", "wire");
    let commitment = ramflux_crypto::object_erasure_commitment("root", "wire", "manifest");
    db.connection.execute(
        "INSERT INTO object_erasure_lookup(lookup,commitment) VALUES(?1,?2)",
        rusqlite::params![lookup, commitment],
    )?;
    db.connection.execute(
        "INSERT INTO object_payload_dependency(parent_commitment,child_commitment) VALUES(?1,?2)",
        rusqlite::params![commitment, lookup],
    )?;
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let private = root.path().join("erasure-links-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&private, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let snapshot_id = &manifest.manifest.snapshot_id;
    stage.adopt_source_cut(0, snapshot_id, &private, snapshot)?;
    for family in ["sql/object_erasure_lookup", "sql/object_payload_dependency"] {
        let counts = stage.stage_source_fixed_base_family(snapshot_id, family)?;
        assert_eq!(counts.records, 1);
        let (output, written) =
            stage.write_source_fixed_base_family(snapshot_id, family, Sink::default())?;
        assert_eq!(counts, written);
        let mut input = output.0.as_slice();
        let header = read_record_header(&mut input)?.ok_or("header")?;
        assert_eq!(header.family, family);
        let rule = full_transfer_catalog().iter().find(|rule| rule.id == family).ok_or("rule")?;
        copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
        assert_eq!(input, b"");
    }
    Ok(())
}

#[test]
fn pairing_full_fixed_source_spool_streams_record_beyond_header_cache() -> TestResult {
    const TEXT_BYTES: usize = 32_000;
    let family = super::message_denial::FAMILY;
    let (root, db) = super::test_support::owned_source_test_db("full-source-large-denial")?;
    let text = "d".repeat(TEXT_BYTES);
    db.connection.execute(
        "INSERT INTO message_tombstone_projection(tombstone_id,conversation_id,message_id,delete_scope,created_at) VALUES(?1,?1,?1,?1,42)",
        rusqlite::params![text],
    )?;
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let snapshot_id = &manifest.manifest.snapshot_id;
    let path = root.path().join("large-denial-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    stage.adopt_source_cut(0, snapshot_id, &path, snapshot)?;
    let counts = stage.stage_source_fixed_base_family(snapshot_id, family)?;
    assert_eq!(counts.records, 1, "large denial was omitted from the source spool");
    assert!(
        counts.encoded_bytes > (RecordHeader::LIMIT + 4) as u64,
        "fixture must overflow the bounded header cache"
    );
    let (output, written) =
        stage.write_source_fixed_base_family(snapshot_id, family, Sink::default())?;
    assert_eq!(written, counts, "streamed denial counts differ from the committed spool");
    assert_eq!(
        output.0.len() as u64,
        counts.encoded_bytes,
        "overflowing the cache truncated the committed record"
    );
    let mut input = output.0.as_slice();
    let header = read_record_header(&mut input)?.ok_or("large denial header")?;
    let rule =
        full_transfer_catalog().iter().find(|rule| rule.id == family).ok_or("large denial rule")?;
    let mut copied = Vec::new();
    copy_full_scalar_record(rule, &header, &mut input, &mut copied)?;
    let mut expected = text.repeat(4).into_bytes();
    expected.extend_from_slice(&42_i64.to_be_bytes());
    assert_eq!(copied, expected, "streaming changed exact denial cells after cache overflow");
    assert!(input.is_empty(), "large denial left unchecked trailing bytes");
    Ok(())
}
