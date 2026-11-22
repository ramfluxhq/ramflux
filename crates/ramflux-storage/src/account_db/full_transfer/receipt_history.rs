// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Inert qualified receipt observations, subject to the ordinary erasure owner.
use super::fixed_union::Cells;
use crate::StorageError;
use rusqlite::Connection;

pub(super) const FAMILY: &str = "sql/receipt_projection";

pub(super) fn validate(key: &str) -> Result<(), StorageError> {
    let invalid = || StorageError::PairingField("UnsupportedRecord");
    let digest = key.strip_prefix("receipt/v3/").ok_or_else(invalid)?;
    let bytes = ramflux_protocol::decode_base64url(digest).map_err(|_| invalid())?;
    if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != digest {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn erased(db: &Connection, value: &Cells) -> Result<bool, StorageError> {
    super::super::deleted_messages::message_is_deleted_on(db, value.text(2)?)
}
