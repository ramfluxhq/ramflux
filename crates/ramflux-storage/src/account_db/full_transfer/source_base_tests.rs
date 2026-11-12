// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{full_transfer_catalog, source_scalar_tests::Sink, stage_tests::fixture};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::{
    CHUNK_BYTES, RootHasher, read_record_header,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct ShortSink(Sink);
impl std::io::Write for ShortSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.0, &bytes[..bytes.len().min(7)])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn pairing_full_base_source_fixed_owner_fixture_counts_order_and_root() -> TestResult {
    let (root, db) = crate::tests::test_db("full-base-source-encoding")?;
    // Real initialized AccountDb; MAC and local metadata remain present. This checks
    // implemented-owner composition, not unknown actor/union/SAS acceptance.
    let lookup = ramflux_crypto::object_erasure_lookup("root", "wire");
    let commitment = ramflux_crypto::object_erasure_commitment("root", "wire", "manifest");
    db.connection.execute(
        "INSERT INTO object_identity_replacement VALUES(?1)",
        rusqlite::params![commitment],
    )?;
    db.connection
        .execute("INSERT INTO object_erasure_fence VALUES(?1)", rusqlite::params![commitment])?;
    db.connection.execute(
        "INSERT INTO object_segment_reference_veto VALUES(?1)",
        rusqlite::params![[7_u8; 32].as_slice()],
    )?;
    db.connection.execute(
        "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
        rusqlite::params![lookup, commitment],
    )?;
    db.connection.execute(
        "INSERT INTO object_payload_dependency VALUES(?1,?2)",
        rusqlite::params![commitment, lookup],
    )?;
    db.connection.call(|db| {
        let tx = db.transaction()?;
        for index in 0..2048 {
            let commitment = ramflux_crypto::object_erasure_commitment(
                "root",
                &format!("wire-{index}"),
                "manifest",
            );
            tx.execute("INSERT INTO object_identity_replacement VALUES(?1)", [commitment])?;
        }
        tx.commit()
    })?;
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let private = root.join("complete-base-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&private, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let snapshot_id = &manifest.manifest.snapshot_id;
    stage.adopt_source_cut(0, snapshot_id, &private, snapshot)?;
    let census = stage.source_cut_schema(0, snapshot_id, full_transfer_catalog())?;
    let unowned = census
        .families
        .iter()
        .zip(full_transfer_catalog())
        .filter(|(family, rule)| family.source_rows.0 > 0 && rule.require_typed_codec().is_err())
        .map(|(family, _)| family.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(unowned, Vec::<&str>::new(), "fixture contains unimplemented owners");
    let (output, encoded) =
        stage.encode_fixed_base_source(snapshot_id, ShortSink(Sink::default()))?;
    assert_eq!(encoded.total_bytes, output.0.0.len() as u64);
    assert!(encoded.chunk_count > 1, "fixture must cross a full chunk with short writes");
    let mut root = RootHasher::new(encoded.total_bytes)?;
    for (index, chunk) in output.0.0.chunks(CHUNK_BYTES as usize).enumerate() {
        root.push(index as u64, chunk)?;
    }
    assert_eq!(encoded.chunks_root, root.finish()?);
    let mut counts = std::collections::BTreeMap::new();
    let mut input = output.0.0.as_slice();
    let mut previous = None;
    while let Some(header) = read_record_header(&mut input)? {
        let start = input.len();
        let position = (header.family.clone(), header.key.clone());
        assert!(previous.as_ref().is_none_or(|old| old < &position));
        let rule =
            full_transfer_catalog().iter().find(|rule| rule.id == header.family).ok_or("rule")?;
        super::copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
        assert!(input.len() < start);
        *counts.entry(header.family).or_insert(0_u64) += 1;
        previous = Some(position);
    }
    assert_eq!(counts.len(), 7);
    for family in &encoded.schema.families {
        assert_eq!(family.portable_records.0, counts.get(&family.id).copied().unwrap_or(0));
    }
    assert_eq!(
        encoded.schema.families.iter().map(|family| family.encoded_bytes.0).sum::<u64>(),
        encoded.total_bytes
    );
    Ok(())
}
struct Observed(Arc<AtomicUsize>);
impl std::io::Write for Observed {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.fetch_add(bytes.len(), Ordering::SeqCst);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn pairing_full_base_source_unknown_owner_refuses_before_spool_or_output() -> TestResult {
    let (root, db) = crate::tests::test_db("full-base-source-unknown-owner")?;
    db.connection.execute_batch("DELETE FROM runtime_actor_state;")?;
    db.connection.execute(
        "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES('identity/safety-verification-migration/v1/unknown',?1)",
        rusqlite::params![b"{}".as_slice()],
    )?;
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let private = root.join("unknown-base-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&private, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let snapshot_id = &manifest.manifest.snapshot_id;
    stage.adopt_source_cut(0, snapshot_id, &private, snapshot)?;
    let emitted = Arc::new(AtomicUsize::new(0));
    assert!(matches!(
        stage.encode_fixed_base_source(snapshot_id, Observed(emitted.clone())),
        Err(crate::StorageError::PairingField("UnsupportedRecord"))
    ));
    assert_eq!(emitted.load(Ordering::SeqCst), 0);
    assert_eq!(
        stage
            .connection
            .query_row("SELECT count(*) FROM source_scalar_row", [], |row| row.get::<_, u64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn pairing_full_base_source_startup_local_marker_is_rebuilt_not_exported() -> TestResult {
    let (root, db) = crate::tests::test_db("full-base-source-startup-marker")?;
    let (mut record, manifest, _) = fixture()?;
    record.role = PairingRole::Initiator;
    let private = root.join("startup-owner-cut.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&private, Arc::new(AtomicBool::new(false)))?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    let snapshot_id = &manifest.manifest.snapshot_id;
    stage.adopt_source_cut(0, snapshot_id, &private, snapshot)?;
    let (output, encoded) = stage.encode_fixed_base_source(snapshot_id, Sink::default())?;
    let local = encoded
        .schema
        .families
        .iter()
        .find(|family| family.id == "actor/group-message/upgrade-start")
        .ok_or("local family")?;
    assert_eq!(local.source_rows.0, 1);
    assert_eq!(local.portable_records.0, 0);
    assert_eq!(local.encoded_bytes.0, 0);
    let mut input = output.0.as_slice();
    while let Some(header) = read_record_header(&mut input)? {
        assert!(matches!(
            header.family.as_str(),
            "sql/account_mac_bundle/portable" | "sql/account_erasure_generation"
        ));
        let rule =
            full_transfer_catalog().iter().find(|rule| rule.id == header.family).ok_or("rule")?;
        super::copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
    }
    Ok(())
}
