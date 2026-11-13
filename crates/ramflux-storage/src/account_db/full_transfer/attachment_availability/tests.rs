// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The availability gate is independent from the still-closed portable object owner.
use super::*;
use crate::account_db::full_transfer::{full_transfer_catalog, test_support::owned_source_test_db};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn pairing_full_present_attachment_never_becomes_missing_and_frozen_cut_can_observe_upload()
-> TestResult {
    let (root, db) = owned_source_test_db("full-local-availability")?;
    let hash = ramflux_protocol::encode_base64url([73; 32]);
    db.connection.execute("INSERT INTO object_index(object_id,chunk_manifest_hash,object_state,total_cipher_size,chunk_count,created_at,updated_at,manifest_hash,ciphertext) VALUES('local-media',x'00','present',3,1,1,1,?1,x'010203')",params![hash.as_bytes()])?;
    let path = root.path().join("frozen-j6.db");
    let cut = db.pin_full_transfer_cut()?.write_private_snapshot(
        &path,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let snapshot = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    crate::encryption::apply_key(&snapshot, &cut.key)?;
    assert!(
        matches!(
            require(&snapshot, &db.connection),
            Err(StorageError::PairingField("AttachmentNotRemote"))
        ),
        "test: present local ciphertext bypassed availability gate"
    );
    assert!(
        matches!(
            db.inspect_full_transfer_schema(full_transfer_catalog()),
            Err(StorageError::PairingField("AttachmentNotRemote"))
        ),
        "test: begin preflight hid local bytes behind unknown owner refusal"
    );
    db.connection.execute("INSERT INTO object_transfer_state(transfer_id,object_id,peer_device_id,manifest_hash,missing_chunk_bitmap,completed_chunk_bitmap,state,updated_at,direction,relay_endpoint,total_chunks,total_bytes,done_bytes,expires_at) VALUES('ordinary-upload','local-media','',?1,x'5b5d',x'5b305d','running',1,'upload','quic://relay.example:443',1,3,3,9223372036854775807)",params![hash.as_bytes()])?;
    assert!(
        require(&snapshot, &db.connection).is_err(),
        "test: incomplete ordinary upload admitted a data completion"
    );
    db.connection.execute("UPDATE object_transfer_state SET state='complete'", [])?;
    require(&snapshot, &db.connection)?;
    // Availability alone grants no portable codec, DV or native authority.
    let census = db.inspect_full_transfer_schema(full_transfer_catalog())?;
    assert!(
        matches!(
            census.require_typed_owners(full_transfer_catalog()),
            Err(StorageError::PairingField("UnsupportedRecord"))
        ),
        "test: upload weakened undeclared portable owners"
    );
    db.connection.execute("UPDATE object_transfer_state SET expires_at=0", [])?;
    assert!(
        matches!(
            require(&snapshot, &db.connection),
            Err(StorageError::PairingField("AttachmentNotRemote"))
        ),
        "test: expired remote receipt promised fetchability"
    );
    let retained: Vec<u8> = db.connection.query_row(
        "SELECT ciphertext FROM object_index WHERE object_id='local-media'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        retained, b"\x01\x02\x03",
        "test: availability failure changed present source bytes"
    );
    let missing:bool=db.connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='backup_missing_attachment')",[],|row|row.get(0))?;
    assert!(!missing, "test: availability gate invented a missing-attachment manifest");
    Ok(())
}
