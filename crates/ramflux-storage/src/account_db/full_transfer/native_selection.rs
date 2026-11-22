// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local proof preference, never source authority or a portable execution selector.
use crate::StorageError;
use prost::Message as _;
use ramflux_protocol::message as g;
use rusqlite::{Connection, OptionalExtension as _, params};
use zeroize::Zeroize as _;

pub(in crate::account_db) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS runtime_native_history_selection(
 message_id TEXT PRIMARY KEY NOT NULL,evidence_class TEXT NOT NULL CHECK(evidence_class IN ('received','authored','own_copy')),
 current_id BLOB NOT NULL CHECK(length(current_id)=32),body_hash BLOB NOT NULL CHECK(length(body_hash)=32));
CREATE TRIGGER IF NOT EXISTS native_selection_body_changed AFTER UPDATE ON runtime_message_content WHEN OLD.body IS NOT NEW.body OR OLD.conversation_id IS NOT NEW.conversation_id BEGIN
 DELETE FROM runtime_native_history_selection WHERE message_id=OLD.message_id; END;
CREATE TRIGGER IF NOT EXISTS native_selection_body_removed AFTER DELETE ON runtime_message_content BEGIN
 DELETE FROM runtime_native_history_selection WHERE message_id=OLD.message_id; END;";
#[derive(Clone, Copy)]
pub(super) enum Selected {
    Received,
    Authored,
    OwnCopy,
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
pub(super) fn read(
    db: &Connection,
    message: &str,
    body: &[u8],
) -> Result<Option<Selected>, StorageError> {
    let value:Option<(String,Vec<u8>,Vec<u8>)>=db.query_row("SELECT CASE WHEN length(evidence_class)<=8 THEN evidence_class END,CASE WHEN length(current_id)=32 THEN current_id END,CASE WHEN length(body_hash)=32 THEN body_hash END FROM runtime_native_history_selection WHERE message_id=?1",[message],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
    let Some((class, current, hash)) = value else { return Ok(None) };
    let mut inner = g::Inner::decode(body).map_err(|_| invalid())?;
    inner.body.zeroize();
    if inner.identity.as_ref().is_none_or(|identity| identity.id != current)
        || hash.as_slice() != blake3::hash(body).as_bytes()
    {
        return Err(invalid());
    }
    Ok(Some(match class.as_str() {
        "received" => Selected::Received,
        "authored" => Selected::Authored,
        "own_copy" => Selected::OwnCopy,
        _ => return Err(invalid()),
    }))
}
/// No orphan or malformed preference may hide behind a zero body-family count.
pub(super) fn require_rows(db: &Connection) -> Result<(), StorageError> {
    let mut query=db.prepare("SELECT CASE WHEN length(message_id)=43 THEN message_id END FROM runtime_native_history_selection")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let message: String = row.get(0)?;
        let decoded = ramflux_protocol::decode_base64url(&message).map_err(|_| invalid())?;
        if decoded.len() != 32 || ramflux_protocol::encode_base64url(&decoded) != message {
            return Err(invalid());
        }
        let body:Option<Vec<u8>>=db.query_row("SELECT CASE WHEN length(body)<=?2 THEN body END FROM runtime_message_content WHERE message_id=?1",params![&message,g::validation::MAX_INNER_BYTES],|row|row.get(0)).optional()?.flatten();
        let body = zeroize::Zeroizing::new(body.ok_or_else(invalid)?);
        read(db, &message, &body)?.ok_or_else(invalid)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
