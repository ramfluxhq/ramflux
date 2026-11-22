// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Message erasure is a denial, never an imported command or sender authorization.
use super::{CodecRule, FamilyRule, FamilySelector, MergeRule, full_transfer_catalog};
use crate::StorageError;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{
        CellType, Disposition, MAX_STABLE_KEY_BYTES, RecordHeader, RecordOp, U64,
        encode_stable_key, write_record_header,
    },
};
use rusqlite::{OptionalExtension as _, params, types::ValueRef};
use std::io::{Read, Write};
use zeroize::{Zeroize as _, Zeroizing};

pub(super) const FAMILY: &str = "sql/message_tombstone_projection";
const NAMES: [&str; 5] =
    ["tombstone_id", "conversation_id", "message_id", "delete_scope", "created_at"];
const TEXT_LIMIT: usize = MAX_STABLE_KEY_BYTES - 5;
pub(super) const MAX_BODY_BYTES: u64 = (4 * TEXT_LIMIT + 8) as u64;

fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn mismatch() -> StorageError {
    StorageError::PairingField("SchemaMismatch")
}
fn conflict() -> StorageError {
    StorageError::PairingField("TransferConflict")
}

pub(super) fn require_rule(rule: &FamilyRule) -> Result<(), StorageError> {
    if rule.id != FAMILY
        || !matches!(rule.selector, FamilySelector::Table("message_tombstone_projection"))
        || rule.codec_version != U64(2)
        || rule.disposition != Disposition::Transfer
        || rule.merge != MergeRule::RestrictUnion
        || !rule.restrictive
        || rule.key != ["tombstone_id"]
        || rule.cells.len() != NAMES.len()
        || rule.codec.len() != NAMES.len()
        || !rule.excluded.is_empty()
    {
        return Err(mismatch());
    }
    for (index, ((cell, field), name)) in rule.cells.iter().zip(rule.codec).zip(NAMES).enumerate() {
        let kind = if index == 4 { CellType::I64 } else { CellType::Utf8 };
        let codec = if index == 0 {
            matches!(field.codec, CodecRule::SqlMessageTombstone)
        } else {
            matches!(field.codec, CodecRule::Scalar { cell_type } if cell_type == kind)
        };
        if cell.name != name
            || field.name != name
            || cell.cell_type != kind
            || field.disposition != Disposition::Transfer
            || !codec
        {
            return Err(mismatch());
        }
    }
    Ok(())
}

struct Denial {
    text: [Zeroizing<String>; 4],
    created_at: i64,
}
impl Denial {
    fn validate(&self) -> Result<(), StorageError> {
        if self.text.iter().any(|text| text.is_empty() || text.len() > TEXT_LIMIT) {
            return Err(invalid());
        }
        Ok(())
    }
    fn key(&self) -> Result<String, StorageError> {
        Ok(encode_stable_key([(CellType::Utf8, self.text.first().ok_or_else(invalid)?.as_bytes())])
            .map_err(|_| invalid())?
            .to_string())
    }
    fn header(&self) -> Result<RecordHeader, StorageError> {
        Ok(RecordHeader {
            family: FAMILY.into(),
            codec_version: U64(2),
            key: self.key()?,
            op: RecordOp::Put,
            cell_types: vec![
                CellType::Utf8,
                CellType::Utf8,
                CellType::Utf8,
                CellType::Utf8,
                CellType::I64,
            ],
            cell_lengths: self
                .text
                .iter()
                .map(|text| U64(text.len() as u64))
                .chain([U64(8)])
                .collect(),
        })
    }
    fn write(&self, output: &mut impl Write) -> Result<u64, StorageError> {
        let mut total = 8_u64;
        for text in &self.text {
            output.write_all(text.as_bytes())?;
            total = total.checked_add(text.len() as u64).ok_or_else(invalid)?;
        }
        output.write_all(&self.created_at.to_be_bytes())?;
        Ok(total)
    }
}

pub(super) fn encode(
    rule: &FamilyRule,
    row: &rusqlite::Row<'_>,
    output: &mut impl Write,
) -> Result<u64, StorageError> {
    require_rule(rule)?;
    if row.as_ref().column_count() != NAMES.len() {
        return Err(mismatch());
    }
    let mut text = std::array::from_fn(|_| Zeroizing::new(String::new()));
    for (index, (value, name)) in text.iter_mut().zip(NAMES).enumerate() {
        if row.as_ref().column_name(index)? != name {
            return Err(mismatch());
        }
        let ValueRef::Text(bytes) = row.get_ref(index)? else {
            return Err(invalid());
        };
        if bytes.is_empty() || bytes.len() > TEXT_LIMIT {
            return Err(invalid());
        }
        value.push_str(std::str::from_utf8(bytes).map_err(|_| invalid())?);
    }
    if row.as_ref().column_name(4)? != "created_at" {
        return Err(mismatch());
    }
    let value = Denial { text, created_at: row.get(4)? };
    value.validate()?;
    let mut header = value.header()?;
    let mut encoded = Zeroizing::new(Vec::new());
    let result = write_record_header(&mut *encoded, &header).map_err(|_| invalid());
    header.key.zeroize();
    result?;
    output.write_all(&encoded)?;
    (encoded.len() as u64).checked_add(value.write(output)?).ok_or_else(invalid)
}

fn read(
    rule: &FamilyRule,
    header: &RecordHeader,
    input: &mut impl Read,
) -> Result<Option<Denial>, StorageError> {
    require_rule(rule)?;
    header.validate().map_err(|_| invalid())?;
    if header.family != FAMILY || header.codec_version != U64(2) {
        return Err(mismatch());
    }
    if header.op == RecordOp::Absent {
        // A denial survives absence at its source. Still validate its original stable key.
        let bytes =
            Zeroizing::new(ramflux_protocol::decode_base64url(&header.key).map_err(|_| invalid())?);
        let Some((tag, rest)) = bytes.split_first() else {
            return Err(invalid());
        };
        let length = rest.get(..4).ok_or_else(invalid)?;
        let size = u32::from_be_bytes(length.try_into().map_err(|_| invalid())?) as usize;
        let text = rest.get(4..).ok_or_else(invalid)?;
        if *tag != 3
            || size != text.len()
            || size == 0
            || size > TEXT_LIMIT
            || std::str::from_utf8(text).is_err()
            || ramflux_protocol::encode_base64url(bytes.as_slice()) != header.key
        {
            return Err(invalid());
        }
        return Ok(None);
    }
    if header.cell_lengths.len() != 5
        || header.cell_types
            != [CellType::Utf8, CellType::Utf8, CellType::Utf8, CellType::Utf8, CellType::I64]
    {
        return Err(mismatch());
    }
    let mut text = std::array::from_fn(|_| Zeroizing::new(String::new()));
    let mut scratch = Zeroizing::new(vec![0_u8; TEXT_LIMIT]);
    for (value, length) in text.iter_mut().zip(&header.cell_lengths) {
        let count = usize::try_from(length.0).map_err(|_| invalid())?;
        if count == 0 {
            return Err(invalid());
        }
        let bytes = scratch.get_mut(..count).ok_or_else(invalid)?;
        input.read_exact(bytes)?;
        value.push_str(std::str::from_utf8(bytes).map_err(|_| invalid())?);
        bytes.zeroize();
    }
    let mut timestamp = [0_u8; 8];
    input.read_exact(&mut timestamp)?;
    let value = Denial { text, created_at: i64::from_be_bytes(timestamp) };
    value.validate()?;
    let mut expected = value.key()?;
    let matches = expected == header.key;
    expected.zeroize();
    if !matches {
        return Err(invalid());
    }
    Ok(Some(value))
}

pub(super) fn copy(
    rule: &FamilyRule,
    header: &RecordHeader,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), StorageError> {
    if let Some(value) = read(rule, header, input)? {
        value.write(output)?;
    }
    Ok(())
}

pub(super) fn apply(
    db: &rusqlite::Connection,
    header: &RecordHeader,
    input: &mut impl Read,
) -> Result<(), StorageError> {
    let rule = full_transfer_catalog().iter().find(|rule| rule.id == FAMILY).ok_or_else(invalid)?;
    let value = read(rule, header, input)?.ok_or_else(invalid)?;
    let [id, conversation, message, scope] = &value.text;
    let old: Option<(String, String, String, i64)> = db.query_row(
        "SELECT conversation_id,message_id,delete_scope,created_at FROM message_tombstone_projection WHERE tombstone_id=?1",
        [id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional()?;
    if old.is_some_and(|old| {
        old.0 != conversation.as_str()
            || old.1 != message.as_str()
            || old.2 != scope.as_str()
            || old.3 != value.created_at
    }) {
        return Err(conflict());
    }
    // Capture before the existing erasure triggers retire the message's copy bindings.
    super::super::receive::erased_capture::capture_for(db, &[message.as_str()], crate::unix_now())?;
    super::super::deleted_messages::retain_deletion_marker_on(db, message.as_str())?;
    db.execute("INSERT INTO message_tombstone_projection(tombstone_id,conversation_id,message_id,delete_scope,created_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(tombstone_id) DO NOTHING",
        params![id.as_str(),conversation.as_str(),message.as_str(),scope.as_str(),value.created_at])?;
    db.execute("UPDATE direct_message_projection SET sender_id='',encrypted_body=x'',metadata_json=x'7b7d',deleted=1 WHERE conversation_id=?1 AND message_id=?2",
        params![conversation.as_str(),message.as_str()])?;
    db.execute(
        "DELETE FROM runtime_message_content WHERE conversation_id=?1 AND message_id=?2",
        params![conversation.as_str(), message.as_str()],
    )?;
    Ok(())
}

/// A source-qualified deletion marker may already deny a B row without a public
/// tombstone projection. Apply that existing denial through the same erasure graph
/// before any native content is imported or normalized; synthesize no tombstone.
pub(super) fn erase_if_denied(
    db: &rusqlite::Connection,
    conversation: &str,
    message: &str,
) -> Result<bool, StorageError> {
    if db.is_autocommit() {
        return Err(StorageError::PairingField("WrongContext"));
    }
    if !super::super::deleted_messages::message_is_deleted_on(db, message)? {
        return Ok(false);
    }
    super::super::receive::erased_capture::capture_for(db, &[message], crate::unix_now())?;
    super::super::deleted_messages::retain_deletion_marker_on(db, message)?;
    db.execute("UPDATE direct_message_projection SET sender_id='',encrypted_body=x'',metadata_json=x'7b7d',deleted=1 WHERE conversation_id=?1 AND message_id=?2", params![conversation, message])?;
    db.execute(
        "DELETE FROM runtime_message_content WHERE conversation_id=?1 AND message_id=?2",
        params![conversation, message],
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests;
