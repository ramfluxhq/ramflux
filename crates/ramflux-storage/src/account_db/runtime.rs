// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account runtime persistence facade.

mod acknowledgements;
mod actor_backoff;
mod config;
mod control;
pub(super) mod message_origin;
mod operations;
pub use operations::OperationLookup;
mod outbox;
mod own_copy;
mod ratchet_metadata;
mod ratchet_retirement;
mod receipt_retention;
mod recovery;
mod retention;
mod schema;

/// Install journal and runtime tables on a clean backup file.
///
/// The live opener also turns on WAL. This file stays in DELETE mode, so the backup
/// path does not call `enable_runtime`. Home-migration tables are removed before the
/// copy list is read; a snapshot does not publish them.
pub(in crate::account_db) fn install_backup_schema(
    connection: &crate::database::Connection,
) -> Result<(), crate::StorageError> {
    super::journal::install_journal_tables(connection)?;
    schema::install_runtime_tables(connection, None)?;
    connection.call(|db| super::home_migration::strip_from_backup(db))?;
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AccountOutboxEntry {
    pub sequence: i64,
    pub table_name: String,
    pub change_kind: String,
    pub row_id: i64,
    #[serde(default)]
    pub keys: serde_json::Value,
}
