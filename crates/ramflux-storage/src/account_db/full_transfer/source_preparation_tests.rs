// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::FullSourcePreparationCancel;
use ramflux_crypto::custody::pairing::PairingRole;
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn pairing_full_source_preparation_encodes_without_any_resume_or_approval_record() -> TestResult {
    let (_root, db) = crate::tests::test_db("full-source-preparation-no-trust")?;
    let mut preparation = db.prepare_full_transfer_source()?;
    let id = preparation.preparation_id().to_owned();
    let snapshot_id = ramflux_protocol::encode_base64url([31; 32]);
    preparation.capture_base_cut(&snapshot_id)?;
    let (_, encoded) = preparation.encode_fixed_base_source(&snapshot_id, std::io::sink())?;
    assert!(encoded.total_bytes > 0);
    assert_eq!(
        encoded.schema.families.iter().map(|family| family.portable_records.0).sum::<u64>(),
        2
    );
    assert_eq!(preparation.connection.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('stage','resume','manifest','native_floor')",[],|row|row.get::<_,u64>(0))?,0);
    assert_eq!(db.pairing_live_rows()?.len(), 0);
    assert!(db.open_full_transfer_stage(&id, PairingRole::Initiator, 100).is_err());
    drop(preparation);
    assert!(db.open_full_transfer_stage(&id, PairingRole::Initiator, 100).is_err());
    Ok(())
}
struct CancelOnWrite {
    cancel: FullSourcePreparationCancel,
    calls: Arc<AtomicUsize>,
}
impl Write for CancelOnWrite {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.cancel.cancel();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn pairing_full_source_preparation_cancel_is_one_way_and_stops_before_next_row() -> TestResult {
    let (root, db) = crate::tests::test_db("full-source-preparation-cancel")?;
    let mut preparation = db.prepare_full_transfer_source()?;
    let snapshot_id = ramflux_protocol::encode_base64url([32; 32]);
    let private = root.join("cancelled-pre-bootstrap.db");
    let snapshot = db
        .pin_full_transfer_cut()?
        .write_private_snapshot(&private, Arc::new(AtomicBool::new(false)))?;
    preparation.adopt_base_cut(&snapshot_id, &private, snapshot)?;
    let control = preparation.cancel_handle();
    let calls = Arc::new(AtomicUsize::new(0));
    let destination = CancelOnWrite { cancel: control.clone(), calls: calls.clone() };
    assert!(matches!(
        preparation.encode_fixed_base_source(&snapshot_id, destination),
        Err(crate::StorageError::PairingField("Cancelled"))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    control.cancel();
    assert!(matches!(
        preparation.encode_fixed_base_source(&snapshot_id, std::io::sink()),
        Err(crate::StorageError::PairingField("Cancelled"))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn pairing_full_source_preparation_checkpoint_releases_owner_and_reopens_data_only() -> TestResult {
    let (root, db) = crate::tests::test_db("full-source-preparation-checkpoint")?;
    let mut owner = db.prepare_full_transfer_source()?;
    let snapshot_id = ramflux_protocol::encode_base64url([33; 32]);
    owner.capture_base_cut(&snapshot_id)?;
    let (_, encoded) = owner.encode_fixed_base_source(&snapshot_id, std::io::sink())?;
    let expected_root = encoded.chunks_root;
    let expected_bytes = encoded.total_bytes;
    let ready = owner.close_ready()?;
    assert_eq!(ready.encoding().chunks_root, expected_root);
    assert_eq!(ready.snapshot_id(), snapshot_id);
    drop(db); // No borrowed account/key/connection is retained by the data-only checkpoint.
    let index = crate::AccountIndex::open(&root)?;
    let db = crate::AccountDb::open(
        &index,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    let mut reopened = db.open_full_source_preparation(&ready)?;
    let (_, encoded) = reopened.encode_fixed_base_source(&snapshot_id, std::io::sink())?;
    assert_eq!(encoded.chunks_root, expected_root);
    assert_eq!(encoded.total_bytes, expected_bytes);
    assert_eq!(
        reopened.connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('stage','resume')",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        0
    );
    drop(reopened);
    let (_foreign_root, foreign) = crate::tests::test_db("full-source-preparation-foreign")?;
    assert!(foreign.open_full_source_preparation(&ready).is_err());
    Ok(())
}

#[test]
fn pairing_full_source_preparation_checkpoint_cannot_revive_after_cancel() -> TestResult {
    let (_root, db) = crate::tests::test_db("full-source-preparation-cancel-ready")?;
    let mut owner = db.prepare_full_transfer_source()?;
    let snapshot_id = ramflux_protocol::encode_base64url([34; 32]);
    owner.capture_base_cut(&snapshot_id)?;
    owner.encode_fixed_base_source(&snapshot_id, std::io::sink())?;
    let cancel = owner.cancel_handle();
    let ready = owner.close_ready()?;
    cancel.cancel();
    assert!(matches!(
        db.open_full_source_preparation(&ready),
        Err(crate::StorageError::PairingField("Cancelled"))
    ));
    Ok(())
}

#[test]
fn pairing_full_source_preparation_checkpoint_refuses_changed_ready_digest() -> TestResult {
    let (_root, db) = crate::tests::test_db("full-source-preparation-ready-digest")?;
    let mut owner = db.prepare_full_transfer_source()?;
    let snapshot_id = ramflux_protocol::encode_base64url([35; 32]);
    owner.capture_base_cut(&snapshot_id)?;
    owner.encode_fixed_base_source(&snapshot_id, std::io::sink())?;
    let ready = owner.close_ready()?;
    let reopened = db.open_full_source_preparation(&ready)?;
    reopened.connection.execute(
        "UPDATE source_preparation_ready SET digest=?1 WHERE singleton=1",
        rusqlite::params![[0_u8; 32].as_slice()],
    )?;
    drop(reopened);
    assert!(matches!(
        db.open_full_source_preparation(&ready),
        Err(crate::StorageError::PairingField("WrongContext"))
    ));
    Ok(())
}

#[test]
fn pairing_full_source_preparation_rejects_live_schema_change_after_cut() -> TestResult {
    let (_root, db) = crate::tests::test_db("full-source-preparation-live-schema")?;
    let mut owner = db.prepare_full_transfer_source()?;
    let snapshot_id = ramflux_protocol::encode_base64url([36; 32]);
    owner.capture_base_cut(&snapshot_id)?;
    db.connection.execute_batch("UPDATE schema_migration SET schema_version=10000 WHERE schema_version=(SELECT max(schema_version) FROM schema_migration)")?;
    assert!(matches!(
        owner.encode_fixed_base_source(&snapshot_id, std::io::sink()),
        Err(crate::StorageError::PairingField("SnapshotInvalidated"))
    ));
    assert_eq!(
        owner
            .connection
            .query_row("SELECT count(*) FROM source_scalar_row", [], |row| row.get::<_, u64>(0))?,
        0
    );
    Ok(())
}

mod bind;
