// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Idempotent runtime schema and transaction-local domain-change triggers.

use super::super::AccountDb;
use crate::StorageError;
use rusqlite::params;

impl AccountDb {
    pub(super) fn install_runtime_schema(&self) -> Result<(), StorageError> {
        let transaction = self.connection.immediate_transaction()?;
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS runtime_outbox (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                table_name TEXT NOT NULL,
                change_kind TEXT NOT NULL,
                row_id INTEGER NOT NULL,
                published INTEGER NOT NULL DEFAULT 0,
                keys_json TEXT,
                actor_state_kind TEXT GENERATED ALWAYS AS (
                    CASE WHEN table_name='runtime_actor_state'
                         THEN json_extract(keys_json,'$.state_kind') END) VIRTUAL
             );
             CREATE INDEX IF NOT EXISTS runtime_outbox_pending ON runtime_outbox(sequence) WHERE published=0;
             CREATE TABLE IF NOT EXISTS runtime_ack (envelope_id TEXT PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS runtime_scoped_ack (receiver TEXT NOT NULL,target TEXT NOT NULL,inbox_seq INTEGER NOT NULL,PRIMARY KEY(receiver,target,inbox_seq));
             CREATE TABLE IF NOT EXISTS runtime_actor_state (state_kind TEXT PRIMARY KEY, state_json BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS runtime_privacy_maintenance (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                erasure_pending INTEGER NOT NULL DEFAULT 0
             );
             INSERT OR IGNORE INTO runtime_privacy_maintenance VALUES(1,0);
             CREATE INDEX IF NOT EXISTS runtime_actor_deleted_message ON runtime_actor_state(
                 CASE WHEN json_valid(CAST(state_json AS TEXT)) THEN json_extract(CAST(state_json AS TEXT),'$.routing.message_id') END
             ) WHERE state_kind >= 'routed/committed/' AND state_kind < 'routed/committed0';
             DROP INDEX IF EXISTS runtime_actor_receipt_message;
             CREATE TABLE IF NOT EXISTS runtime_account_identity (
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 principal_commitment TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS runtime_operation (
                operation_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                response_json TEXT
             );",
        )?;
        // This value comes from the supervisor account record, never from a contact directory.
        self.connection.execute(
            "INSERT INTO runtime_account_identity VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET principal_commitment=excluded.principal_commitment WHERE principal_commitment<>excluded.principal_commitment",
            params![self.principal_commitment],
        )?;
        self.install_event_counter_schema()?;
        self.install_group_message_retention_schema()?;
        let columns: i64 = self.connection.query_row(
            "SELECT count(*) FROM pragma_table_info('runtime_outbox') WHERE name='keys_json'",
            [],
            |row| row.get(0),
        )?;
        if columns == 0 {
            self.connection
                .execute_batch("ALTER TABLE runtime_outbox ADD COLUMN keys_json TEXT")?;
        }
        let actor_columns: i64 = self.connection.query_row(
            "SELECT count(*) FROM pragma_table_xinfo('runtime_outbox')
             WHERE name='actor_state_kind'",
            [],
            |row| row.get(0),
        )?;
        if actor_columns == 0 {
            self.connection.execute_batch(
                "ALTER TABLE runtime_outbox ADD COLUMN actor_state_kind TEXT
                 GENERATED ALWAYS AS (
                    CASE WHEN table_name='runtime_actor_state'
                         THEN json_extract(keys_json,'$.state_kind') END) VIRTUAL",
            )?;
        }
        self.connection.execute_batch(
            "CREATE INDEX IF NOT EXISTS runtime_outbox_source
                 ON runtime_outbox(table_name,row_id);
             CREATE INDEX IF NOT EXISTS runtime_outbox_actor_kind
                 ON runtime_outbox(actor_state_kind,table_name,change_kind);",
        )?;
        self.install_receipt_retention_schema()?;
        self.remove_consent_bookkeeping_triggers()?;
        self.install_domain_change_triggers()?;
        self.install_inbox_recovery_schema()?;
        self.connection.call(|db| super::super::message_footprint::install(db))?;
        transaction.commit()?;
        Ok(())
    }

    fn install_domain_change_triggers(&self) -> Result<(), StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'
             AND name NOT LIKE 'backup_archived_%' AND name NOT IN ('local_event_counter','message_footprint','message_copy_binding','message_footprint_actor_stage','message_footprint_outbox_stage','message_footprint_journal_stage','runtime_account_identity','runtime_privacy_maintenance','runtime_outbox','runtime_receipt_retention','runtime_operation','schema_migration','account_key_check','runtime_journal','runtime_journal_bounds','runtime_unrouted','runtime_message_content','runtime_inbox_dead_letter','runtime_inbox_retry','runtime_inbox_recovery','runtime_inbox_policy','runtime_inbox_changes','contact_request_decision','contact_link_decision','contact_message_fence_retention')"
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
                // A privacy fence can erase an inserted/updated copy in an earlier AFTER
                // trigger. Do not publish its original identity-bearing keys afterward.
                let present = format!("EXISTS(SELECT 1 FROM \"{quoted}\" WHERE rowid=NEW.rowid)");
                let guard = match operation {
                    "insert" => format!("WHEN {present}"),
                    "update" => format!("WHEN {present} AND ({changed})"),
                    _ => String::new(),
                };
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
        Ok(())
    }

    fn remove_consent_bookkeeping_triggers(&self) -> Result<(), StorageError> {
        // Decision clocks and expiry bookkeeping are not domain projections. Existing domain
        // rows still generate their ordinary invalidations in the same transaction.
        for table in
            ["contact_request_decision", "contact_link_decision", "contact_message_fence_retention"]
        {
            for operation in ["insert", "update", "delete"] {
                self.connection.execute_batch(&format!(
                    "DROP TRIGGER IF EXISTS runtime_{table}_{operation}"
                ))?;
            }
        }
        Ok(())
    }
}
