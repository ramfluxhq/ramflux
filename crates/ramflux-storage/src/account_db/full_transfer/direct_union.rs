// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native content is reconstructed from separately retained original contributions.
use super::{FullDirectRecord, source_scalar::SourceGuard};
use crate::{BackupDatabase, StorageError};
use ramflux_protocol::custody::{
    DeviceRef,
    pairing::full_transfer::{RecordHeader, RecordOp, read_record_header},
};
use rusqlite::{Connection, params};
use std::io::Read;
use zeroize::Zeroizing;

pub(super) const FAMILY: &str = "sql/runtime_message_content";
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn conflict() -> StorageError {
    StorageError::PairingField("TransferConflict")
}
fn rule() -> Result<&'static super::FamilyRule, StorageError> {
    super::source_scalar::compiled(FAMILY)
}

pub(super) fn read_row(
    header: &RecordHeader,
    input: &mut impl Read,
    own: &str,
) -> Result<FullDirectRecord, StorageError> {
    if header.family != FAMILY || header.op != RecordOp::Put || header.cell_lengths.len() != 3 {
        return Err(invalid());
    }
    // Only this compiled three-cell shape gets the native allowance. No allocation
    // size comes from a peer length, and the scalar owner checks all lengths/types/key.
    let mut encoded = Zeroizing::new(Vec::with_capacity(super::FULL_DIRECT_RECORD_LIMIT + 299));
    super::copy_full_scalar_record(rule()?, header, input, &mut *encoded)?;
    let mut bytes = encoded.as_slice();
    let mut parts = [&[][..]; 3];
    for ((part, length), limit) in
        parts.iter_mut().zip(&header.cell_lengths).zip([43, 256, super::FULL_DIRECT_RECORD_LIMIT])
    {
        let size = usize::try_from(length.0).map_err(|_| invalid())?;
        if size > limit {
            return Err(invalid());
        }
        *part = bytes.get(..size).ok_or_else(invalid)?;
        bytes = bytes.get(size..).ok_or_else(invalid)?;
    }
    let [message, conversation, payload] = parts;
    if !bytes.is_empty() {
        return Err(invalid());
    }
    let value = FullDirectRecord::read(payload, own)?;
    let projection = value.projection(own)?;
    if projection.message_id.as_bytes() != message
        || projection.conversation_id.as_bytes() != conversation
    {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn apply(
    db: &Connection,
    source: &DeviceRef,
    header: &RecordHeader,
    input: &mut impl Read,
) -> Result<(), StorageError> {
    let value = read_row(header, input, &source.account_anchor)?;
    value.merge_on(db, source).map(|_| ())
}

fn encode(
    db: &Connection,
    value: &FullDirectRecord,
    own: &str,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let row = value.projection(own)?;
    let mut payload = Zeroizing::new(Vec::new());
    value.write(own, &mut *payload)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(super::FULL_DIRECT_RECORD_LIMIT + 1024));
    let rule = rule()?;
    db.query_row(
        "SELECT ?1 AS message_id,?2 AS conversation_id,?3 AS body",
        params![row.message_id, row.conversation_id, payload.as_slice()],
        |row| Ok(super::write_full_scalar_sql_row(rule, row, &mut *bytes)),
    )??;
    Ok(bytes)
}

pub(super) fn normalize(
    db: &Connection,
    nonce: &[u8; 32],
    private: &BackupDatabase,
    owners: &[String; 2],
    guard: &SourceGuard,
) -> Result<(), StorageError> {
    let mut query = db.prepare("SELECT DISTINCT key FROM full_union_record WHERE generation_nonce=?1 AND family=?2 ORDER BY key")?;
    let mut keys = query.query(params![nonce.as_slice(), FAMILY])?;
    while let Some(row) = keys.next()? {
        guard.require()?;
        let key = row.get_ref(0)?.as_str().map_err(|_| invalid())?;
        normalize_key(db, nonce, private, owners, key, guard)?;
    }
    Ok(())
}
fn normalize_key(
    db: &Connection,
    nonce: &[u8; 32],
    private: &BackupDatabase,
    owners: &[String; 2],
    key: &str,
    guard: &SourceGuard,
) -> Result<(), StorageError> {
    let source = super::super::mac_subkeys::full::decode_source_ref(
        owners.get(1).ok_or_else(invalid)?.as_bytes(),
    )?;
    let mut query = db.prepare("SELECT owner,rowid,length(record) FROM full_union_input WHERE generation_nonce=?1 AND family=?2 AND key=?3 ORDER BY CASE WHEN owner=?4 THEN 0 ELSE 1 END,owner")?;
    let mut rows =
        query.query(params![nonce.as_slice(), FAMILY, key, owners.get(1).ok_or_else(invalid)?])?;
    let mut expected: Option<FullDirectRecord> = None;
    let mut denied = false;
    while let Some(row) = rows.next()? {
        guard.require()?;
        let contributor = row.get_ref(0)?.as_str().map_err(|_| invalid())?;
        if !owners.iter().any(|owner| owner == contributor) {
            return Err(invalid());
        }
        let mut blob = super::record_spool::checked_blob(
            db,
            "full_union_input",
            row.get(1)?,
            row.get(2)?,
            rule()?,
            key,
        )?;
        let header = super::record_spool::PrivateHeader(
            read_record_header(&mut blob).map_err(|_| invalid())?.ok_or_else(invalid)?,
        );
        let value = read_row(&header.0, &mut blob, &source.account_anchor)?;
        // Check every original contributor's event, including a superseded event
        // that would disappear from the preferred normalized native version.
        let erased = value.erase_if_denied(&private.db, &source.account_anchor)?;
        if erased {
            value.retain_expected_erasure(db, nonce, contributor, &source.account_anchor)?;
        }
        denied |= erased;
        expected = Some(match expected {
            Some(old) => old.merge(&value, &source.account_anchor)?,
            None => value,
        });
    }
    let expected = expected.ok_or_else(invalid)?;
    let projection = expected.projection(&source.account_anchor)?;
    if denied || expected.erase_if_denied(&private.db, &source.account_anchor)? {
        if private.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_message_content WHERE message_id=?1)",
            [&projection.message_id],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(conflict());
        }
        db.execute(
            "DELETE FROM full_union_record WHERE generation_nonce=?1 AND family=?2 AND key=?3",
            params![nonce.as_slice(), FAMILY, key],
        )?;
        // A permanent denial dominates every original version too. Do not retain an
        // extra native body/capture copy solely for future preference reconstruction.
        db.execute(
            "DELETE FROM full_union_input WHERE generation_nonce=?1 AND family=?2 AND key=?3",
            params![nonce.as_slice(), FAMILY, key],
        )?;
        return Ok(());
    }
    expected.project_original_contributions(private, &source)?;
    let record = encode(db, &expected, &source.account_anchor)?;
    db.execute(
        "UPDATE full_union_record SET record=?1 WHERE generation_nonce=?2 AND family=?3 AND key=?4",
        params![record.as_slice(), nonce.as_slice(), FAMILY, key],
    )?;
    Ok(())
}

pub(super) fn absent(
    db: &Connection,
    private: &BackupDatabase,
    nonce: &[u8; 32],
    owners: &[String; 2],
    owner: &str,
    header: &RecordHeader,
    input: &mut impl Read,
) -> Result<(), StorageError> {
    if private.db.is_autocommit() {
        return Err(StorageError::PairingField("WrongContext"));
    }
    if !owners.iter().any(|candidate| candidate == owner) {
        return Err(invalid());
    }
    let source = super::super::mac_subkeys::full::decode_source_ref(owner.as_bytes())?;
    let value = read_row(header, input, &source.account_anchor)?;
    let row = value.projection(&source.account_anchor)?;
    for table in ["full_union_input", "full_union_record"] {
        db.execute(&format!("DELETE FROM {table} WHERE generation_nonce=?1 AND owner=?2 AND family=?3 AND key=?4"), params![nonce.as_slice(), owner, FAMILY, header.key])?;
    }
    let retained: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM full_union_record WHERE generation_nonce=?1 AND family=?2 AND key=?3)", params![nonce.as_slice(), FAMILY, header.key], |row| row.get(0))?;
    if !retained {
        super::direct_install::retire(&private.db, &row.message_id)?;
        private.db.execute(
            "DELETE FROM runtime_message_content WHERE message_id=?1 AND conversation_id=?2",
            params![row.message_id, row.conversation_id],
        )?;
        // Retain erased narrow rows; a live projection has no remaining content contributor.
        private.db.execute("DELETE FROM direct_message_projection WHERE message_id=?1 AND conversation_id=?2 AND deleted=0", params![row.message_id, row.conversation_id])?;
    }
    Ok(())
}
