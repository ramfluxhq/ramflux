// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Content-free current MAC denials. These records can only restrict future reads.
use super::{CodecRule, FieldRule, MergeRule, fixed_union::Cells};
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{CellType, Disposition};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub(super) const FAMILY: &str = "sql/runtime_actor_state/message_denials";
pub(super) const LIMIT: usize = 32;
pub(super) const FILTER: &str = "(substr(state_kind,1,16)='message/deleted/' OR substr(state_kind,1,25)='message/deleted-envelope/' OR substr(state_kind,1,25)='message/deleted-raw-copy/')";
pub(super) const FIELDS: &[FieldRule] = &[FieldRule {
    name: "version",
    nullable: false,
    disposition: Disposition::Transfer,
    merge: MergeRule::Immutable,
    codec: CodecRule::Scalar { cell_type: CellType::I64 },
}];
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u8,
}
fn read(bytes: &[u8]) -> Result<Marker, StorageError> {
    if bytes.is_empty() || bytes.len() > LIMIT {
        return Err(invalid());
    }
    let value: Marker = ramflux_protocol::parse_i_json_secret(bytes).map_err(|_| invalid())?;
    if !matches!(value.version, 1 | 2) {
        return Err(invalid());
    }
    Ok(value)
}
pub(super) fn source(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    Ok(Zeroizing::new(ramflux_protocol::canonical_json_bytes(&read(bytes)?)?))
}
pub(super) fn portable(bytes: &[u8]) -> Result<(), StorageError> {
    if source(bytes)?.as_slice() != bytes {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn require_key(key: &str, bytes: &[u8]) -> Result<(), StorageError> {
    let marker = read(bytes)?;
    let (suffix, version) = if let Some(value) = key.strip_prefix("message/deleted/") {
        (value, 2)
    } else if let Some(value) = key.strip_prefix("message/deleted-envelope/") {
        (value, 1)
    } else if let Some(value) = key.strip_prefix("message/deleted-raw-copy/") {
        (value, 1)
    } else {
        return Err(invalid());
    };
    if marker.version != version || suffix.len() != 43 {
        return Err(invalid());
    }
    let decoded = ramflux_protocol::decode_base64url(suffix).map_err(|_| invalid())?;
    if decoded.len() != 32 || ramflux_protocol::encode_base64url(&decoded) != suffix {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn validate(value: &Cells) -> Result<(), StorageError> {
    require_key(value.text(0)?, value.bytes(1)?)
}
pub(super) fn rows(db: &Connection) -> Result<u64, StorageError> {
    let mut query = db.prepare(&format!("SELECT CASE WHEN length(CAST(state_kind AS BLOB))<=80 THEN state_kind END,CASE WHEN typeof(state_json)='blob' AND length(state_json)<=?1 THEN state_json END FROM runtime_actor_state WHERE {FILTER}"))?;
    let mut rows = query.query([LIMIT])?;
    let mut count = 0_u64;
    while let Some(row) = rows.next()? {
        require_key(
            row.get_ref(0)?.as_str().map_err(|_| invalid())?,
            row.get_ref(1)?.as_blob().map_err(|_| invalid())?,
        )?;
        count = count.checked_add(1).ok_or_else(invalid)?;
    }
    Ok(count)
}
