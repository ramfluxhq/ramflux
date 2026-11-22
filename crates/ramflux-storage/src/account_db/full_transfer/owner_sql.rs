// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One SQL read adapter for actual source, B contributions and independent materialization.
use super::{CodecRule, FamilyRule, write_full_scalar_sql_row};
use crate::StorageError;
use rusqlite::{Connection, params};
use std::io::Write;
use zeroize::Zeroizing;
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}

pub(super) fn write(
    source: &Connection,
    rule: &FamilyRule,
    row: &rusqlite::Row<'_>,
    output: &mut impl Write,
    account: Option<&str>,
) -> Result<u64, StorageError> {
    rule.require_typed_codec()?;
    if rule.id == super::receipt_history::FAMILY {
        super::receipt_history::validate(row.get_ref(0)?.as_str().map_err(|_| invalid())?)?;
    }
    if rule.id == "sql/device_directory" {
        super::device_directory::validate(
            row.get_ref(0)?.as_str().map_err(|_| invalid())?,
            row.get_ref(1)?.as_str().map_err(|_| invalid())?,
            row.get_ref(4)?.as_str().map_err(|_| invalid())?,
        )?;
    }
    if !rule.codec.iter().any(|field| matches!(field.codec, CodecRule::SqlNativePayload { .. })) {
        return write_full_scalar_sql_row(rule, row, output);
    }
    if rule.id != "sql/runtime_message_content" || row.as_ref().column_count() != 3 {
        return Err(invalid());
    }
    for (index, name) in ["message_id", "conversation_id", "body"].iter().enumerate() {
        if row.as_ref().column_name(index)? != *name {
            return Err(invalid());
        }
    }
    let message = row.get_ref(0)?.as_str().map_err(|_| invalid())?;
    let conversation = row.get_ref(1)?.as_str().map_err(|_| invalid())?;
    let own:String=source.query_row("SELECT CASE WHEN length(principal_commitment)=43 THEN principal_commitment END FROM runtime_account_identity WHERE singleton=1",[],|row|row.get(0))?;
    if account != Some(own.as_str()) {
        return Err(invalid());
    }
    let native = super::direct_source::read(source, &own, message)?.ok_or_else(invalid)?;
    if native.verify(&own)?.original().conversation_id != conversation
        || native.exact_inner() != row.get_ref(2)?.as_blob().map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    native.write(&mut *bytes)?;
    // Prepared logical cells only: identifiers are fixed and the original native
    // record was assembled from the same immutable/transactional SQL read owner.
    source.query_row(
        "SELECT ?1 AS message_id,?2 AS conversation_id,?3 AS body",
        params![message, conversation, bytes.as_slice()],
        |projected| Ok(write_full_scalar_sql_row(rule, projected, output)),
    )?
}
