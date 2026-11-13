// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable mailbox row keys use node-assigned delivery coordinates, never sender-chosen IDs.
use crate::{NodeCoreError, ROUTER_INBOX_ENTRY_TABLE};
use redb::{ReadableTable, TableDefinition};
const FORMAT: TableDefinition<&str, u8> = TableDefinition::new("router_mailbox_key_format_v1");

pub(crate) fn storage_key(target: &str, sequence: u64) -> String {
    format!("delivery/v1/{}/{sequence:020}", ramflux_protocol::encode_base64url(target))
}

/// Establish the current marker only for a new empty mailbox; never rekey persisted rows.
pub(super) fn initialize(transaction: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    let mut format = transaction.open_table(FORMAT).map_err(db_error)?;
    if let Some(version) = format.get("version").map_err(db_error)? {
        return if version.value() == 1 {
            Ok(())
        } else {
            Err(NodeCoreError::UnsupportedPersistedFormat("router mailbox keys"))
        };
    }
    let table = transaction.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(db_error)?;
    if table.iter().map_err(db_error)?.next().is_some() {
        return Err(NodeCoreError::UnsupportedPersistedFormat("router mailbox keys"));
    }
    format.insert("version", 1).map_err(db_error)?;
    Ok(())
}
fn db_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
