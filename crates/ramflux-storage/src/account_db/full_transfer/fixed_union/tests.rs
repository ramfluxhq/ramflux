// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Eight fixed projections only; no complete receiver/DV/native/installation claim.
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase, StorageError};
use ramflux_protocol::{
    custody::{DeviceRef, pairing::full_transfer::*},
    encode_base64url,
};
use std::{
    io::Write,
    sync::{Arc, atomic::AtomicBool},
};
use zeroize::Zeroizing;
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn h(value: u8) -> String {
    encode_base64url([value; 32])
}
fn reference(id: &str) -> DeviceRef {
    DeviceRef { account_anchor: h(2), device_id: id.into(), device_epoch: 1 }
}
fn database(label: &str) -> ResultOf<(ramflux_test_support::TestPath, AccountDb)> {
    let root = crate::tests::temp_root(label);
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", &h(2))?;
    let key = AccountDbKey::derive("acct", label.as_bytes());
    Ok((root, AccountDb::open(&index, "acct", &key)?))
}
fn seed(db: &AccountDb, value: u8, generation: u64) -> ResultOf {
    db.connection.execute(
        "UPDATE account_erasure_generation SET generation=?1",
        rusqlite::params![generation],
    )?;
    db.connection
        .execute("INSERT INTO object_erasure_fence VALUES(?1)", rusqlite::params![h(value)])?;
    db.connection.execute(
        "INSERT INTO object_identity_replacement VALUES(?1)",
        rusqlite::params![h(value + 1)],
    )?;
    db.connection.execute(
        "INSERT INTO object_segment_reference_veto VALUES(?1)",
        rusqlite::params![[value + 2; 32].as_slice()],
    )?;
    db.connection.execute(
        "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
        rusqlite::params![h(value + 3), h(value)],
    )?;
    db.connection.execute(
        "INSERT INTO object_payload_dependency VALUES(?1,?2)",
        rusqlite::params![h(value), h(value + 1)],
    )?;
    let original = reference(&format!("historical-{value}"));
    db.connection.call(move |raw| {
        let keys = Zeroizing::new([value; 192]);
        let id = super::super::super::mac_subkeys::bundle_id(keys.as_slice());
        Ok(super::super::super::mac_subkeys::full::import_into_private_generation(
            raw,
            &original,
            &id,
            keys.as_slice(),
        ))
    })??;
    Ok(())
}
#[derive(Default)]
struct Buffer(Zeroizing<Vec<u8>>);
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn stream(db: &AccountDb) -> ResultOf<Buffer> {
    let mut source = db.prepare_full_transfer_source()?;
    let snapshot = h(60);
    source.capture_base_cut(&snapshot)?;
    Ok(source.encode_fixed_base_source(&snapshot, Buffer::default())?.0)
}
fn apply(
    private: &mut BackupDatabase,
    source: &DeviceRef,
    bytes: &[u8],
) -> Result<(), StorageError> {
    for restrictive in [true, false] {
        let mut input = bytes;
        while let Some(header) = read_record_header(&mut input)
            .map_err(|_| StorageError::PairingField("UnsupportedRecord"))?
        {
            let rule = crate::full_transfer_catalog()
                .iter()
                .find(|rule| rule.id == header.family)
                .ok_or(StorageError::PairingField("UnsupportedRecord"))?;
            if rule.restrictive == restrictive {
                private.apply_full_fixed_base_record(source, &header, &mut input)?;
            } else {
                crate::copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
            }
        }
    }
    Ok(())
}

#[test]
fn pairing_full_fixed_base_merge_preserves_target_fences_floor_and_current_mac() -> ResultOf {
    let (source_root, source) = database("full-fixed-union-source")?;
    seed(&source, 11, 8)?;
    let (target_root, target) = database("full-fixed-union-target")?;
    seed(&target, 21, 9)?;
    let bytes = stream(&source)?;
    let current: String = target.connection.query_row(
        "SELECT bundle_id FROM account_mac_bundle WHERE is_current=1",
        [],
        |r| r.get(0),
    )?;
    let path = target_root.join("private-union.db");
    let (cut, observation) = target.pin_full_transfer_target()?;
    let snapshot = cut.write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    let mut private = BackupDatabase::open(&path, &snapshot.key)?;
    private.db.execute_batch("BEGIN IMMEDIATE")?;
    apply(&mut private, &reference("source-A"), &bytes.0)?;
    // Exact replay is set-union/max/immutable deduplication, not another current bundle.
    apply(&mut private, &reference("source-A"), &bytes.0)?;
    private.db.execute_batch("COMMIT")?;
    observation.require_current(&target)?;
    assert_eq!(
        private.db.query_row(
            "SELECT count(*) FROM object_erasure_fence WHERE commitment IN(?1,?2)",
            rusqlite::params![h(11), h(21)],
            |r| r.get::<_, u64>(0)
        )?,
        2
    );
    assert_eq!(
        private.db.query_row("SELECT count(*) FROM object_segment_reference_veto", [], |r| r
            .get::<_, u64>(0))?,
        2
    );
    assert_eq!(
        private.db.query_row("SELECT count(*) FROM object_payload_dependency", [], |r| r
            .get::<_, u64>(0))?,
        2
    );
    assert_eq!(
        private.db.query_row("SELECT generation FROM account_erasure_generation", [], |r| r
            .get::<_, u64>(0))?,
        9,
        "target erasure floor decreased"
    );
    assert_eq!(
        private.db.query_row(
            "SELECT bundle_id FROM account_mac_bundle WHERE is_current=1",
            [],
            |r| r.get::<_, String>(0)
        )?,
        current
    );
    assert_eq!(
        private.db.query_row("SELECT count(*) FROM full_imported_mac_bundle", [], |r| r
            .get::<_, u64>(0))?,
        3
    );
    assert_eq!(
        target
            .connection
            .query_row("SELECT count(*) FROM object_erasure_fence", [], |r| r.get::<_, u64>(0))?,
        1,
        "private projection became live"
    );
    drop(private);
    drop(target);
    drop(source);
    std::fs::remove_dir_all(source_root)?;
    std::fs::remove_dir_all(target_root)?;
    Ok(())
}

#[test]
fn pairing_full_fixed_base_lookup_conflict_rolls_back_all_provisional_projection() -> ResultOf {
    let (source_root, source) = database("full-fixed-union-conflict-source")?;
    seed(&source, 11, 8)?;
    let (target_root, target) = database("full-fixed-union-conflict-target")?;
    seed(&target, 21, 9)?;
    let bytes = stream(&source)?;
    let path = target_root.join("private-union.db");
    let snapshot = target
        .pin_full_transfer_cut()?
        .write_private_snapshot(&path, Arc::new(AtomicBool::new(false)))?;
    let mut private = BackupDatabase::open(&path, &snapshot.key)?;
    private.db.execute(
        "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
        rusqlite::params![h(14), h(21)],
    )?;
    private.db.execute_batch("BEGIN IMMEDIATE")?;
    assert!(
        matches!(
            apply(&mut private, &reference("source-A"), &bytes.0),
            Err(StorageError::PairingField("TransferConflict"))
        ),
        "conflicting target lookup was overwritten"
    );
    private.db.execute_batch("ROLLBACK")?;
    assert_eq!(
        private
            .db
            .query_row("SELECT count(*) FROM object_erasure_fence", [], |r| r.get::<_, u64>(0))?,
        1,
        "failed union kept earlier source rows"
    );
    assert_eq!(
        private.db.query_row("SELECT count(*) FROM full_imported_mac_bundle", [], |r| r
            .get::<_, u64>(0))?,
        1,
        "failed union kept imported keys"
    );
    assert_eq!(
        private.db.query_row(
            "SELECT commitment FROM object_erasure_lookup WHERE lookup=?1",
            rusqlite::params![h(14)],
            |r| r.get::<_, String>(0)
        )?,
        h(21)
    );
    assert!(
        matches!(
            apply(&mut private, &reference("source-A"), &bytes.0),
            Err(StorageError::PairingField("WrongContext"))
        ),
        "projection accepted no transaction"
    );
    let mut input = bytes.0.as_slice();
    let mut absent = read_record_header(&mut input)?.ok_or("base header")?;
    absent.op = RecordOp::Absent;
    absent.cell_types.clear();
    absent.cell_lengths.clear();
    private.db.execute_batch("BEGIN IMMEDIATE")?;
    assert!(
        matches!(
            private.apply_full_fixed_base_record(
                &reference("source-A"),
                &absent,
                &mut std::io::empty()
            ),
            Err(StorageError::PairingField("UnsupportedRecord"))
        ),
        "base primitive admitted an absence without contribution ownership"
    );
    private.db.execute_batch("ROLLBACK")?;
    drop(private);
    drop(target);
    drop(source);
    std::fs::remove_dir_all(source_root)?;
    std::fs::remove_dir_all(target_root)?;
    Ok(())
}
