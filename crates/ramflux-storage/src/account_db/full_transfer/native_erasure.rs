// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Content-free restrictive native identity coupling, never a deletion command.
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::read_record_header;
use rusqlite::{Connection, params};
use zeroize::Zeroizing;

pub(super) const FAMILY: &str = "sql/runtime_native_erasure";
pub(in crate::account_db) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS runtime_native_erasure(original_id TEXT NOT NULL,current_id TEXT NOT NULL,conversation_id TEXT NOT NULL,PRIMARY KEY(original_id,current_id)) WITHOUT ROWID; CREATE INDEX IF NOT EXISTS runtime_native_erasure_current ON runtime_native_erasure(current_id);";
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
pub(super) fn check(original: &str, current: &str, conversation: &str) -> Result<(), StorageError> {
    for value in [original, current, conversation.strip_prefix("dm:").ok_or_else(invalid)?] {
        if value.len() != 43 {
            return Err(invalid());
        }
        let bytes = ramflux_protocol::decode_base64url(value).map_err(|_| invalid())?;
        if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != value {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(super) fn validate(value: &super::fixed_union::Cells) -> Result<(), StorageError> {
    check(value.text(0)?, value.text(1)?, value.text(2)?)
}
/// The caller has verified the original/current native identities and an existing denial.
pub(super) fn retain(
    db: &Connection,
    original: &str,
    current: &str,
    conversation: &str,
) -> Result<(), StorageError> {
    if db.is_autocommit() {
        return Err(StorageError::PairingField("WrongContext"));
    }
    check(original, current, conversation)?;
    let changed=db.execute("INSERT INTO runtime_native_erasure VALUES(?1,?2,?3) ON CONFLICT(original_id,current_id) DO UPDATE SET conversation_id=excluded.conversation_id WHERE runtime_native_erasure.conversation_id=excluded.conversation_id",params![original,current,conversation])?;
    if changed != 1 {
        return Err(StorageError::PairingField("TransferConflict"));
    }
    Ok(())
}
/// Derive expected denial bytes from the verified original contributor, never a
/// read of the normalized private database. Retain after erasing its body/capture.
pub(super) fn retain_expected(
    db: &Connection,
    nonce: &[u8; 32],
    owner: &str,
    original: &str,
    current: &str,
    conversation: &str,
) -> Result<(), StorageError> {
    check(original, current, conversation)?;
    let rule = super::source_scalar::compiled(FAMILY)?;
    let mut bytes = Zeroizing::new(Vec::new());
    db.query_row(
        "SELECT ?1 AS original_id,?2 AS current_id,?3 AS conversation_id",
        params![original, current, conversation],
        |row| Ok(super::write_full_scalar_sql_row(rule, row, &mut *bytes)),
    )??;
    let header = super::record_spool::PrivateHeader(
        read_record_header(&mut bytes.as_slice()).map_err(|_| invalid())?.ok_or_else(invalid)?,
    );
    let changed=db.execute("INSERT INTO full_union_record(generation_nonce,owner,family,key,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(generation_nonce,owner,family,key) DO UPDATE SET record=excluded.record WHERE full_union_record.record=excluded.record",params![nonce.as_slice(),owner,FAMILY,header.0.key,bytes.as_slice()])?;
    if changed != 1 {
        return Err(StorageError::PairingField("TransferConflict"));
    }
    Ok(())
}
