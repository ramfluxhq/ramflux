// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable mailbox row keys use node-assigned delivery coordinates, never sender-chosen IDs.
use crate::{InboxEntry, NodeCoreError, ROUTER_INBOX_ENTRY_TABLE};
use redb::{ReadableTable, TableDefinition};
use std::collections::BTreeMap;
const FORMAT: TableDefinition<&str, u8> = TableDefinition::new("router_mailbox_key_format_v1");

pub(super) fn storage_key(target: &str, sequence: u64) -> String {
    format!("delivery/v1/{}/{sequence:020}", ramflux_protocol::encode_base64url(target))
}

pub(super) fn upgrade(transaction: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    let mut format = transaction.open_table(FORMAT).map_err(db_error)?;
    if let Some(version) = format.get("version").map_err(db_error)? {
        return if version.value() == 1 {
            Ok(())
        } else {
            Err(NodeCoreError::SnapshotSerialization("unsupported mailbox key format".into()))
        };
    }
    let mut table = transaction.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(db_error)?;
    let mut old_keys = Vec::new();
    let mut entries = BTreeMap::new();
    for row in table.iter().map_err(db_error)? {
        let (key, bytes) = row.map_err(db_error)?;
        let entry: InboxEntry = serde_json::from_slice(bytes.value())
            .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?;
        let delivery = storage_key(&entry.target_delivery_id, entry.inbox_seq);
        let bytes = bytes.value().to_vec();
        if entries.get(&delivery).is_some_and(|previous| previous != &bytes) {
            return Err(NodeCoreError::SnapshotSerialization(
                "conflicting mailbox delivery coordinates".into(),
            ));
        }
        entries.insert(delivery, bytes);
        old_keys.push(key.value().to_owned());
    }
    // The trusted format marker, not the spelling of an old untrusted envelope ID, selects
    // the migration. A legacy sender may have chosen an ID that resembles a current row key.
    for key in old_keys {
        table.remove(key.as_str()).map_err(db_error)?;
    }
    for (key, bytes) in entries {
        table.insert(key.as_str(), bytes.as_slice()).map_err(db_error)?;
    }
    format.insert("version", 1).map_err(db_error)?;
    Ok(())
}
fn db_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
