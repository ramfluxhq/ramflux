// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native ledger admission uses a real keyed source cut, never an omitted-table fallback.
use super::*;
use crate::account_db::full_transfer::{full_transfer_catalog, test_support::owned_source_test_db};
use rusqlite::params;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn source() -> Result<(tempfile::TempDir, crate::AccountDb), StorageError> {
    let (root, db) = owned_source_test_db("native-receive-census")?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("source-only-target", "source-only-incarnation")?;
    Ok((root, db))
}

#[test]
fn native_receive_coordinates_are_declared_but_not_portable() -> TestResult {
    let (_root, db) = source()?;
    db.connection.execute("INSERT INTO gateway_receive_receipt VALUES('source-only-target','source-only-incarnation',?1,'completed',100,1)",params![1_u64.to_be_bytes().as_slice()])?;
    db.connection.execute("INSERT INTO gateway_ack_intent VALUES('source-only-target','source-only-incarnation',?1,1,0,1,100)",params![1_u64.to_be_bytes().as_slice()])?;
    let mut preparation = db.prepare_full_transfer_source()?;
    let snapshot = ramflux_protocol::encode_base64url([70; 32]);
    preparation.capture_base_cut(&snapshot)?;
    let (_, encoded) = preparation.encode_fixed_base_source(&snapshot, std::io::sink())?;
    for rule in [ACK, EPOCH, RECEIPT, WORK] {
        let family = encoded
            .schema
            .families
            .iter()
            .find(|family| family.id == rule.id)
            .ok_or("missing native receive declaration")?;
        assert_eq!(family.disposition, Disposition::Rebuild);
        assert_eq!(family.portable_records.0, 0);
        assert_eq!(family.encoded_bytes.0, 0);
    }
    assert_eq!(
        db.connection
            .query_row("SELECT count(*) FROM gateway_ack_intent", [], |row| row.get::<_, u64>(0))?,
        1
    );
    assert_eq!(
        db.connection
            .query_row("SELECT disposition FROM gateway_receive_receipt", [], |row| row
                .get::<_, String>(0))?,
        "completed"
    );
    assert_eq!(
        db.connection
            .query_row("SELECT incarnation_id FROM gateway_receive_epoch", [], |row| row
                .get::<_, String>(0))?,
        "source-only-incarnation"
    );
    Ok(())
}

#[test]
fn native_receive_pending_input_refuses_cut_without_removing_work() -> TestResult {
    let (_root, db) = source()?;
    let bytes = b"retained authenticated input fixture";
    db.connection.execute("INSERT INTO gateway_receive_receipt VALUES('source-only-target','source-only-incarnation',?1,'staged',100,1)",params![1_u64.to_be_bytes().as_slice()])?;
    db.connection.execute("INSERT INTO gateway_receive_work VALUES('source-only-target','source-only-incarnation',?1,?2,'input',?3)",params![1_u64.to_be_bytes().as_slice(),bytes.as_slice(),bytes.len()])?;
    let mut preparation = db.prepare_full_transfer_source()?;
    let snapshot = ramflux_protocol::encode_base64url([71; 32]);
    assert!(matches!(
        preparation.capture_base_cut(&snapshot),
        Err(StorageError::PairingField("SnapshotBusy"))
    ));
    assert_eq!(
        db.connection.query_row("SELECT entry_json FROM gateway_receive_work", [], |row| row
            .get::<_, Vec<u8>>(0))?,
        bytes
    );
    assert_eq!(
        db.connection
            .query_row("SELECT disposition FROM gateway_receive_receipt", [], |row| row
                .get::<_, String>(0))?,
        "staged"
    );
    Ok(())
}

#[test]
fn native_receive_held_receipt_cannot_bypass_cut_gate_without_work() -> TestResult {
    let (_root, db) = source()?;
    db.connection.execute("INSERT INTO gateway_receive_receipt VALUES('source-only-target','source-only-incarnation',?1,'held',100,1)",params![1_u64.to_be_bytes().as_slice()])?;
    assert!(matches!(
        db.inspect_full_transfer_schema(full_transfer_catalog()),
        Err(StorageError::PairingField("SnapshotBusy"))
    ));
    Ok(())
}

#[test]
fn native_loss_history_remains_refused_until_its_inert_owner_exists() -> TestResult {
    let (_root, db) = source()?;
    db.connection.execute("INSERT INTO gateway_inbox_loss VALUES('source-only-target','source-only-incarnation',?1,?1,?1,'expired',1,'verified')",params![1_u64.to_be_bytes().as_slice()])?;
    let schema = db.inspect_full_transfer_schema(full_transfer_catalog())?;
    assert!(matches!(
        schema.require_typed_owners(full_transfer_catalog()),
        Err(StorageError::PairingField("UnsupportedRecord"))
    ));
    assert_eq!(
        db.connection
            .query_row("SELECT count(*) FROM gateway_inbox_loss", [], |row| row.get::<_, u64>(0))?,
        1
    );
    Ok(())
}
