// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Idempotent runtime schema and transaction-local domain-change triggers.

use super::super::AccountDb;
use crate::StorageError;
use rusqlite::params;

impl AccountDb {
    pub(super) fn install_runtime_schema(&self) -> Result<(), StorageError> {
        let transaction = self.connection.unchecked_transaction()?;
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS runtime_outbox (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                table_name TEXT NOT NULL,
                change_kind TEXT NOT NULL,
                row_id INTEGER NOT NULL,
                published INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS runtime_outbox_pending ON runtime_outbox(sequence) WHERE published=0;
             CREATE TABLE IF NOT EXISTS runtime_ack (envelope_id TEXT PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS runtime_scoped_ack (receiver TEXT NOT NULL,target TEXT NOT NULL,inbox_seq INTEGER NOT NULL,PRIMARY KEY(receiver,target,inbox_seq));
             CREATE TABLE IF NOT EXISTS runtime_actor_state (state_kind TEXT PRIMARY KEY, state_json BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS runtime_operation (
                operation_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                response_json TEXT
             );",
        )?;
        let columns: i64 = self.connection.query_row(
            "SELECT count(*) FROM pragma_table_info('runtime_outbox') WHERE name='keys_json'",
            [],
            |row| row.get(0),
        )?;
        if columns == 0 {
            self.connection
                .execute_batch("ALTER TABLE runtime_outbox ADD COLUMN keys_json TEXT")?;
        }
        let mut statement = self.connection.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'
             AND name NOT LIKE 'backup_archived_%' AND name NOT IN ('runtime_outbox','runtime_operation','schema_migration','account_key_check','runtime_journal','runtime_journal_bounds','runtime_unrouted','runtime_message_content','runtime_inbox_dead_letter','runtime_inbox_retry','runtime_inbox_recovery','runtime_inbox_policy','runtime_inbox_changes')"
        )?;
        let tables = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // AFTER triggers execute in the domain statement's transaction, including all rollback paths.
        // Events contain invalidation keys only; no encrypted business payload or key is published.
        for table in tables {
            let quoted = table.replace('"', "\"\"");
            let literal = table.replace('\'', "''");
            let mut columns = self.connection.prepare("SELECT name FROM pragma_table_info(?1)")?;
            let names = columns
                .query_map(params![table], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let changed = names
                .iter()
                .map(|column| {
                    let column = column.replace('"', "\"\"");
                    format!("OLD.\"{column}\" IS NOT NEW.\"{column}\"")
                })
                .collect::<Vec<_>>()
                .join(" OR ");
            for (operation, source) in [("insert", "NEW"), ("update", "NEW"), ("delete", "OLD")] {
                let guard =
                    if operation == "update" { format!("WHEN {changed}") } else { String::new() };
                let fields = names
                    .iter()
                    .filter(|name| {
                        matches!(
                            name.as_str(),
                            "conversation_id"
                                | "message_id"
                                | "sender_id"
                                | "object_id"
                                | "group_id"
                                | "member_principal_id"
                                | "link_id"
                                | "requester_id"
                                | "target_id"
                                | "state_kind"
                                | "contact_identity_commitment"
                                | "identity_commitment"
                                | "transfer_id"
                                | "envelope_id"
                                | "receiver_device_id"
                                | "receipt_id"
                                | "server_id"
                        )
                    })
                    .map(|name| format!("'{name}',{source}.\"{name}\""))
                    .collect::<Vec<_>>()
                    .join(",");
                let keys = if fields.is_empty() {
                    "'{}'".to_owned()
                } else {
                    format!("json_object({fields})")
                };
                self.connection.execute_batch(&format!(
                    "DROP TRIGGER IF EXISTS \"runtime_{quoted}_{operation}\""
                ))?;
                self.connection.execute_batch(&format!(
                    "CREATE TRIGGER IF NOT EXISTS \"runtime_{quoted}_{operation}\" AFTER {operation} ON \"{quoted}\" {guard}
                     BEGIN INSERT INTO runtime_outbox(table_name,change_kind,row_id,keys_json)
                     VALUES('{literal}','{operation}',{source}.rowid,{keys}); END;"
                ))?;
            }
        }
        self.install_inbox_recovery_schema()?;
        transaction.commit()?;
        Ok(())
    }
}
