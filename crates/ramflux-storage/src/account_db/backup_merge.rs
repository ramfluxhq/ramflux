// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Merge private generations; large object BLOBs use incremental copy rather than SQL values.

use super::backup_consent_merge::consent_supersedes_projection;
use super::backup_database::BackupDatabase;
use crate::{AccountDbKey, BackupCounts, StorageError};
use rusqlite::{OptionalExtension, params};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Default, Debug)]
pub struct BackupMergeReport {
    pub restored: BackupCounts,
    pub kept_newer: BackupCounts,
}
fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
struct RowSelection<'a> {
    table: &'a str,
    join: &'a str,
    newer: &'a str,
    filter: &'a str,
}
fn skip_merge_table(table: &str) -> bool {
    matches!(
        table,
        "shared_group_removal_floor"
            | "shared_group_floor_generation"
            | "shared_group_member_projection"
            | "contact_request_fence"
            | "contact_request_authority_floor"
            | "contact_message_request_fence"
            | "contact_request_decision"
            | "contact_link_decision"
            | "contact_message_fence_retention"
    ) || table.starts_with("backup_archived_")
        || table == "account_key_check"
        || table.starts_with("schema_")
        || matches!(
            table,
            "runtime_outbox" | "runtime_operation" | "runtime_journal" | "runtime_journal_bounds"
        )
        || matches!(
            table,
            "outbox_queue" | "ack_state" | "nack_state" | "backup_archived_actor_state"
        )
}
impl BackupDatabase {
    /// Checks immutable relationship roots and member keys before preview or installation.
    /// # Errors
    /// Rejects a changed identity or member pin; returns SQLite errors.
    pub fn check_backup_pins(&self, path: &Path, key: &AccountDbKey) -> Result<(), StorageError> {
        self.attach(path, key)?;
        let result = (|| {
            let roots:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM runtime_actor_state l JOIN incoming.runtime_actor_state r USING(state_kind) WHERE l.state_kind LIKE 'directory/identity/%' AND json_extract(CAST(l.state_json AS TEXT),'$.contact_identity_commitment') IS NOT NULL AND json_extract(CAST(r.state_json AS TEXT),'$.contact_identity_commitment') IS NOT NULL AND json_extract(CAST(l.state_json AS TEXT),'$.contact_identity_commitment')<>json_extract(CAST(r.state_json AS TEXT),'$.contact_identity_commitment'))",[],|row|row.get(0))?;
            let pins:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM group_member_device_key l JOIN incoming.group_member_device_key r USING(group_id,member_id) WHERE l.device_signing_public_key<>r.device_signing_public_key)",[],|row|row.get(0))?;
            let links:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM friend_link_projection l JOIN incoming.friend_link_projection r USING(link_id) WHERE l.requester_id<>r.requester_id OR l.target_id<>r.target_id)",[],|row|row.get(0))?;
            if roots || pins || links {
                return Err(StorageError::AuthorizationRejected);
            }
            Ok(())
        })();
        self.db.execute_batch("DETACH DATABASE incoming")?;
        result
    }
    fn attach(&self, path: &Path, key: &AccountDbKey) -> Result<(), StorageError> {
        self.db.execute(
            &format!("ATTACH DATABASE ?1 AS incoming KEY \"x'{}'\"", key.sqlcipher_hex()),
            params![path.to_string_lossy()],
        )?;
        Ok(())
    }
    /// Verifies only archive-supplied payloads and exact imported references after a merge.
    /// Existing local undownloaded references are retained and counted, never source omissions.
    /// # Errors
    /// Returns authentication, SQLite or I/O errors; the caller owns a private generation.
    pub fn verify_archive_contribution(
        &self,
        path: &Path,
        key: &AccountDbKey,
        progress: impl FnMut(u64, u64) -> Result<(), StorageError>,
    ) -> Result<super::backup_database::BackupAttachmentVerification, StorageError> {
        self.attach(path, key)?;
        let result = self.verify_attachments_scope(true, progress);
        self.db.execute_batch("DETACH DATABASE incoming")?;
        result
    }
    /// Merges into a private snapshot. The live generation is not involved.
    /// # Errors
    /// Returns schema incompatibility, pin conflicts, cancellation or I/O/SQL errors.
    pub fn merge_backup(
        &mut self,
        path: &Path,
        key: &AccountDbKey,
        progress: impl FnMut() -> Result<(), StorageError>,
    ) -> Result<BackupMergeReport, StorageError> {
        self.merge_backup_with_group_actor(path, key, None, progress)
    }
    /// Merge while rebuilding shared groups from verified snapshots and durable removal floors.
    /// # Errors
    /// Refuses incompatible authorities, unsafe removal rollback, or missing local certification.
    pub fn merge_backup_with_group_actor(
        &mut self,
        path: &Path,
        key: &AccountDbKey,
        local: Option<&ramflux_protocol::GroupStateActor>,
        mut progress: impl FnMut() -> Result<(), StorageError>,
    ) -> Result<BackupMergeReport, StorageError> {
        self.check_backup_pins(path, key)?;
        self.attach(path, key)?;
        let result = (|| {
            let tables = self.incoming_tables()?;
            self.db.execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;")?;
            let shared_groups = self.select_backup_shared_groups(local)?;
            self.preserve_imported_archives(key)?;
            self.merge_contact_fences()?;
            self.prepare_conversation_counts()?;
            let mut report = BackupMergeReport::default();
            for table in tables {
                progress()?;
                if table == "object_index" {
                    self.merge_objects(&mut report, &mut progress)?;
                    continue;
                }
                if skip_merge_table(&table) {
                    continue;
                }
                let incoming = columns(&self.db, "incoming", &table)?;
                let columns = columns(&self.db, "main", &table)?;
                if columns != incoming {
                    return Err(StorageError::AuthorizationRejected);
                }
                let names =
                    columns.iter().map(|(name, _)| quoted(name)).collect::<Vec<_>>().join(",");
                let keys = columns
                    .iter()
                    .filter(|(_, pk)| *pk > 0)
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>();
                let keys = if keys.is_empty() { vec!["rowid"] } else { keys };
                let join = keys
                    .iter()
                    .map(|name| format!("l.{0} IS r.{0}", quoted(name)))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                let newer = newer_expression(&table, &columns);
                let filter = if table == "runtime_actor_state" {
                    "r.state_kind NOT LIKE 'backup/%' AND r.state_kind NOT LIKE 'dm-pair/active/%' AND r.state_kind NOT LIKE 'dm-pair/reset-work/%' AND r.state_kind NOT LIKE 'dm-pair/bootstrap/%' AND r.state_kind NOT LIKE 'own-copy/%' AND r.state_kind NOT LIKE 'own-device/%'"
                } else if table == "friend_link_projection" {
                    "NOT ((r.blocked=1 OR r.state='rejected') AND EXISTS(SELECT 1 FROM contact_link_decision d WHERE d.link_id=r.link_id AND d.state='lifted'))"
                } else if table == "contact_request_projection" {
                    "NOT (r.state IN ('blocked','declined') AND EXISTS(SELECT 1 FROM contact_request_decision d WHERE d.root=r.contact_identity_commitment AND d.state='lifted'))"
                } else if table == "contact_message_request" {
                    "NOT EXISTS(SELECT 1 FROM contact_message_request_fence f WHERE f.sender_identity=r.sender_identity AND f.message_id=r.message_id) AND NOT EXISTS(SELECT 1 FROM direct_message_projection d WHERE d.message_id=r.message_id AND d.conversation_id=r.conversation_id) AND NOT EXISTS(SELECT 1 FROM message_tombstone_projection t WHERE t.message_id=r.message_id AND t.conversation_id=r.conversation_id)"
                } else if table == "runtime_message_content" {
                    "NOT EXISTS(SELECT 1 FROM direct_message_projection d WHERE d.message_id=r.message_id AND d.deleted=1)"
                } else if matches!(
                    table.as_str(),
                    "group_member_projection" | "group_ban_projection"
                ) {
                    "NOT EXISTS(SELECT 1 FROM incoming.group_projection source JOIN main.group_projection live USING(group_id) WHERE source.group_id=r.group_id AND source.group_epoch<live.group_epoch)"
                } else if table == "projection_checkpoint" {
                    "NOT EXISTS(SELECT 1 FROM incoming.local_event_log e WHERE e.event_id=r.last_event_id AND e.event_type='group.sender_key.state' AND CASE WHEN json_valid(CAST(e.event_body AS TEXT)) THEN json_extract(CAST(e.event_body AS TEXT),'$.session_snapshot.is_initiator_side') END=1)"
                } else if table == "message_projection" {
                    "NOT EXISTS(SELECT 1 FROM direct_message_projection d WHERE d.message_id=r.message_id)"
                } else {
                    "1"
                };
                let kept:u64=self.db.query_row(&format!("SELECT count(*) FROM incoming.{t} r JOIN main.{t} l ON {join} WHERE {filter} AND NOT ({newer})",t=quoted(&table)),[],|row|row.get(0))?;
                if table == "runtime_actor_state" {
                    self.count_actor_states(filter, &join, &newer, &mut report)?;
                }
                self.record_conversation_changes(&RowSelection {
                    table: &table,
                    join: &join,
                    newer: &newer,
                    filter,
                })?;
                if table == "contact_message_request" {
                    self.db
                        .execute_batch("DROP TRIGGER IF EXISTS contact_message_erasure_fence")?;
                }
                let replacements=self.db.execute(&format!("DELETE FROM main.{t} AS l WHERE EXISTS(SELECT 1 FROM incoming.{t} r WHERE {join} AND {filter} AND ({newer}))",t=quoted(&table)),[])?;
                let inserted=self.db.execute(&format!("INSERT OR IGNORE INTO main.{t}({names}) SELECT {names} FROM incoming.{t} r WHERE {filter}",t=quoted(&table)),[])?;
                if table == "contact_message_request" {
                    self.db.execute_batch(crate::schema_contact_requests::HELD_MESSAGE_FENCES)?;
                }
                add_count(&mut report.restored, &table, inserted as u64);
                add_count(&mut report.kept_newer, &table, kept);
                let _ = replacements;
            }
            self.db.execute_batch("CREATE TABLE IF NOT EXISTS backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind)); INSERT OR IGNORE INTO backup_archived_actor_state SELECT 'import',state_kind,state_json FROM incoming.runtime_actor_state WHERE state_kind LIKE 'dm-pair/%'; INSERT OR IGNORE INTO runtime_actor_state SELECT 'backup/inactive-pair/'||substr(state_kind,17),CAST(strftime('%s','now') AS BLOB) FROM incoming.runtime_actor_state WHERE state_kind LIKE 'dm-pair/session/%' AND NOT EXISTS(SELECT 1 FROM backup_local_pair l WHERE l.state_kind=incoming.runtime_actor_state.state_kind) AND NOT EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind LIKE 'dm-pair/active/%' AND json_extract(CAST(a.state_json AS TEXT),'$')=substr(incoming.runtime_actor_state.state_kind,17));")?;
            if let Some(local) = local {
                self.project_backup_shared_groups(&shared_groups, local)?;
            }
            self.apply_merged_contact_fences()?;
            self.discard_retired_pair_secrets()?;
            self.finish_conversation_counts(&mut report)?;
            self.db.execute_batch("UPDATE direct_message_projection SET deleted=1,encrypted_body=x'' WHERE deleted=0 AND (EXISTS(SELECT 1 FROM message_tombstone_projection t WHERE t.message_id=direct_message_projection.message_id AND t.conversation_id=direct_message_projection.conversation_id) OR EXISTS(SELECT 1 FROM group_message_tombstone_projection t WHERE t.message_id=direct_message_projection.message_id)); DROP TABLE backup_local_pair; DROP TABLE backup_local_conversation; DROP TABLE backup_source_conversation; DROP TABLE backup_changed_conversation; DROP TABLE backup_local_consent; DROP TABLE backup_source_consent; DROP TABLE backup_local_link_consent; DROP TABLE backup_source_link_consent; COMMIT;")?;
            Ok(report)
        })();
        if result.is_err() {
            let _ = self.db.execute_batch("ROLLBACK");
        }
        self.db.execute_batch("DROP TABLE IF EXISTS main.backup_local_pair; DROP TABLE IF EXISTS main.backup_local_conversation; DROP TABLE IF EXISTS main.backup_source_conversation; DROP TABLE IF EXISTS main.backup_changed_conversation; DETACH DATABASE incoming")?;
        result
    }
    fn incoming_tables(&self) -> Result<Vec<String>, StorageError> {
        let mut statement = self.db.prepare("SELECT name FROM incoming.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
        Ok(statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    fn prepare_conversation_counts(&self) -> Result<(), StorageError> {
        // These scratch indexes live in the encrypted private generation, not SQLite temp files.
        self.db.execute_batch("CREATE TABLE backup_local_pair AS SELECT state_kind FROM runtime_actor_state WHERE state_kind LIKE 'dm-pair/session/%';CREATE TABLE backup_local_conversation(conversation_id TEXT PRIMARY KEY);CREATE TABLE backup_source_conversation(conversation_id TEXT PRIMARY KEY);CREATE TABLE backup_changed_conversation(conversation_id TEXT PRIMARY KEY);")?;
        for (database, target) in
            [("main", "backup_local_conversation"), ("incoming", "backup_source_conversation")]
        {
            for table in
                ["conversation_projection", "conversation_list_state", "direct_message_projection"]
            {
                self.db.execute(&format!("INSERT OR IGNORE INTO main.{target} SELECT conversation_id FROM {database}.{table}"),[])?;
            }
            self.db.execute(&format!("INSERT OR IGNORE INTO main.{target} SELECT substr(state_kind,length('directory/conversation/')+1) FROM {database}.runtime_actor_state WHERE state_kind LIKE 'directory/conversation/%'"),[])?;
        }
        Ok(())
    }
    fn record_conversation_changes(
        &self,
        selection: &RowSelection<'_>,
    ) -> Result<(), StorageError> {
        let RowSelection { table, join, newer, filter } = selection;
        let (id, scope) = match *table {
            "runtime_actor_state" => (
                "substr(r.state_kind,length('directory/conversation/')+1)",
                "r.state_kind LIKE 'directory/conversation/%'",
            ),
            "conversation_projection"
            | "conversation_list_state"
            | "direct_message_projection"
            | "conversation_read_state"
            | "conversation_delivery_state"
            | "conversation_unread_marker" => ("r.conversation_id", "1"),
            _ => return Ok(()),
        };
        self.db.execute(&format!("INSERT OR IGNORE INTO main.backup_changed_conversation SELECT {id} FROM incoming.{table} r WHERE ({filter}) AND ({scope}) AND NOT EXISTS(SELECT 1 FROM main.{table} l WHERE {join} AND NOT ({newer}))"),[])?;
        Ok(())
    }
    fn finish_conversation_counts(
        &self,
        report: &mut BackupMergeReport,
    ) -> Result<(), StorageError> {
        let total: u64 =
            self.db.query_row("SELECT count(*) FROM main.backup_source_conversation", [], |r| {
                r.get(0)
            })?;
        report.restored.conversations=self.db.query_row("SELECT count(*) FROM main.backup_source_conversation s WHERE EXISTS(SELECT 1 FROM main.backup_changed_conversation c WHERE c.conversation_id=s.conversation_id) OR NOT EXISTS(SELECT 1 FROM main.backup_local_conversation l WHERE l.conversation_id=s.conversation_id)",[],|r|r.get(0))?;
        report.kept_newer.conversations = total - report.restored.conversations;
        Ok(())
    }
    fn count_actor_states(
        &self,
        filter: &str,
        join: &str,
        newer: &str,
        report: &mut BackupMergeReport,
    ) -> Result<(), StorageError> {
        for (prefix, is_surface) in [("surface/state/%", true), ("task/view/%", false)] {
            let selected = format!("({filter}) AND r.state_kind LIKE ?1");
            let incoming_count:u64=self.db.query_row(&format!("SELECT count(*) FROM incoming.runtime_actor_state r WHERE {selected} AND NOT EXISTS(SELECT 1 FROM runtime_actor_state l WHERE {join} AND NOT ({newer}))"),params![prefix],|r|r.get(0))?;
            let retained:u64=self.db.query_row(&format!("SELECT count(*) FROM incoming.runtime_actor_state r JOIN runtime_actor_state l ON {join} WHERE {selected} AND NOT ({newer})"),params![prefix],|r|r.get(0))?;
            if is_surface {
                report.restored.surfaces += incoming_count;
                report.kept_newer.surfaces += retained;
            } else {
                report.restored.tasks += incoming_count;
                report.kept_newer.tasks += retained;
            }
        }
        Ok(())
    }
    fn preserve_imported_archives(&self, key: &AccountDbKey) -> Result<(), StorageError> {
        let source = key.fingerprint();
        self.db.execute_batch("CREATE TABLE IF NOT EXISTS backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind)); CREATE TABLE IF NOT EXISTS backup_archived_local_event AS SELECT '' AS source,* FROM incoming.local_event_log WHERE 0; CREATE UNIQUE INDEX IF NOT EXISTS backup_archive_event_key ON backup_archived_local_event(source,event_id);")?;
        self.db.execute("INSERT OR IGNORE INTO backup_archived_actor_state SELECT ?1,state_kind,state_json FROM incoming.runtime_actor_state",params![source])?;
        self.db.execute("INSERT OR IGNORE INTO backup_archived_local_event SELECT ?1,* FROM incoming.local_event_log",params![source])?;
        for table in ["backup_archived_actor_state", "backup_archived_local_event"] {
            let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE type='table' AND name=?1)",params![table],|r|r.get(0))?;
            if exists {
                let names = columns(&self.db, "incoming", table)?
                    .into_iter()
                    .filter(|(name, _)| name != "source")
                    .map(|(name, _)| quoted(&name))
                    .collect::<Vec<_>>()
                    .join(",");
                self.db.execute(&format!("INSERT OR IGNORE INTO {table}(source,{names}) SELECT ?1||'/'||source,{names} FROM incoming.{table}"),params![source])?;
            }
        }
        Ok(())
    }
    fn merge_objects(
        &self,
        report: &mut BackupMergeReport,
        progress: &mut impl FnMut() -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let cols = columns(&self.db, "main", "object_index")?;
        let names = cols.iter().map(|(name, _)| quoted(name)).collect::<Vec<_>>().join(",");
        let values = cols
            .iter()
            .map(|(name, _)| {
                if matches!(name.as_str(), "ciphertext" | "object_body") {
                    format!("zeroblob(length({}))", quoted(name))
                } else {
                    quoted(name)
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let mut query=self.db.prepare("SELECT rowid,object_id,updated_at,length(ciphertext),backup_excluded,tombstoned FROM incoming.object_index ORDER BY rowid")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            progress()?;
            let source_row: i64 = row.get(0)?;
            let id: String = row.get(1)?;
            let at: i64 = row.get(2)?;
            let bytes: u64 = row.get(3)?;
            let excluded: bool = row.get(4)?;
            let source_deleted: bool = row.get(5)?;
            let current: Option<(i64, bool)> = self
                .db
                .query_row(
                    "SELECT updated_at,tombstoned FROM object_index WHERE object_id=?1",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if current.is_some_and(|(current, tombstoned)| {
                tombstoned || current > at || (current == at && !source_deleted)
            }) {
                if !excluded {
                    report.kept_newer.attachments += 1;
                    report.kept_newer.attachment_bytes += bytes;
                }
                continue;
            }
            self.db.execute(&format!("INSERT OR REPLACE INTO object_index({names}) SELECT {values} FROM incoming.object_index WHERE rowid=?1"),params![source_row])?;
            let target_row: i64 = self.db.query_row(
                "SELECT rowid FROM object_index WHERE object_id=?1",
                params![id],
                |row| row.get(0),
            )?;
            for column in ["ciphertext", "object_body"] {
                let mut source =
                    self.db.blob_open("incoming", "object_index", column, source_row, true)?;
                let mut target =
                    self.db.blob_open("main", "object_index", column, target_row, false)?;
                let mut buffer = vec![0_u8; 64 * 1024];
                loop {
                    progress()?;
                    let count = source.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    target.write_all(&buffer[..count])?;
                }
            }
            if !excluded {
                report.restored.attachments += 1;
                report.restored.attachment_bytes += bytes;
            }
        }
        Ok(())
    }
    /// Makes imported send state receive-only before fresh activation.
    /// # Errors
    /// Returns SQL errors without changing any live generation.
    pub fn archive_outbound(&self) -> Result<(), StorageError> {
        self.db.execute_batch("CREATE TABLE IF NOT EXISTS backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind)); INSERT OR IGNORE INTO backup_archived_actor_state SELECT 'restore',state_kind,state_json FROM runtime_actor_state WHERE state_kind LIKE 'dm-pair/%'; INSERT OR IGNORE INTO runtime_actor_state SELECT 'backup/inactive-pair/'||substr(state_kind,17),CAST(strftime('%s','now') AS BLOB) FROM runtime_actor_state WHERE state_kind LIKE 'dm-pair/session/%'; DELETE FROM runtime_actor_state WHERE state_kind LIKE 'dm-pair/active/%' OR state_kind LIKE 'dm-pair/reset-work/%' OR state_kind LIKE 'dm-pair/bootstrap/%'; DELETE FROM projection_checkpoint WHERE last_event_id IN (SELECT event_id FROM local_event_log WHERE event_type='group.sender_key.state' AND CASE WHEN json_valid(CAST(event_body AS TEXT)) THEN json_extract(CAST(event_body AS TEXT),'$.session_snapshot.is_initiator_side') END=1); INSERT OR IGNORE INTO backup_archived_actor_state SELECT 'restore',state_kind,state_json FROM runtime_actor_state WHERE state_kind LIKE 'own-device/send/%'; DELETE FROM runtime_actor_state WHERE state_kind LIKE 'own-device/send/%'; DELETE FROM outbox_queue;")?;
        Ok(())
    }
}
fn columns(
    db: &rusqlite::Connection,
    database: &str,
    table: &str,
) -> Result<Vec<(String, u32)>, StorageError> {
    let mut statement = db.prepare(&format!("PRAGMA {database}.table_info({})", quoted(table)))?;
    Ok(statement
        .query_map([], |row| Ok((row.get(1)?, row.get(5)?)))?
        .collect::<rusqlite::Result<_>>()?)
}
const ORDER_FIELDS: &[&str] = &[
    "group_epoch",
    "device_epoch",
    "lifecycle_epoch",
    "version",
    "edit_counter",
    "deleted_epoch",
    "removed_epoch",
    "banned_epoch",
    "group_key_epoch",
    "invite_epoch",
    "marker_epoch",
    "updated_at",
    "deleted_at",
    "revoked_at",
    "removed_at",
    "blocked_at",
    "capability_revoked_at",
    "read_at",
    "delivered_at",
    "cleared_at",
    "hidden_at",
    "pinned_at",
    "verified_at",
    "shared_at",
    "seen_at",
    "applied_at",
    "accepted_at",
    "approved_at",
    "rejected_at",
    "received_at",
    "cached_at",
    "created_at",
    "lamport_time",
];
fn newer_expression(table: &str, columns: &[(String, u32)]) -> String {
    if table == "friend_link_projection" {
        return format!(
            "r.updated_at>l.updated_at OR (r.updated_at=l.updated_at AND (r.blocked>l.blocked OR (r.capability_revoked_at IS NOT NULL AND l.capability_revoked_at IS NULL) OR (r.state IN ('removed','rejected') AND l.state IN ('accepted','pending')))) OR EXISTS(SELECT 1 FROM backup_source_link_consent s LEFT JOIN backup_local_link_consent old USING(link_id) WHERE s.link_id=r.link_id AND {} AND ((s.state='lifted' AND r.state='accepted' AND r.blocked=0) OR (s.state='blocked' AND r.blocked=1) OR (s.state='declined' AND r.state='rejected')))",
            consent_supersedes_projection(
                "s",
                "old",
                "CASE WHEN l.blocked=1 THEN 'blocked' WHEN l.state='rejected' THEN 'declined' ELSE 'lifted' END"
            )
        );
    }
    if table == "direct_message_projection" {
        return "r.deleted>l.deleted OR (r.deleted=l.deleted AND r.created_at>l.created_at)".into();
    }
    if table == "group_member_projection" {
        return "EXISTS(SELECT 1 FROM incoming.group_projection source JOIN main.group_projection live USING(group_id) WHERE source.group_id=r.group_id AND source.group_epoch>live.group_epoch) OR r.updated_at>l.updated_at".into();
    }
    if table == "contact_request_projection" {
        let rank = |alias: &str| {
            format!(
                "CASE {alias}.state WHEN 'blocked' THEN 4 WHEN 'declined' THEN 3 WHEN 'expired' THEN 2 WHEN 'accepted' THEN 1 ELSE 0 END"
            )
        };
        return format!(
            "r.updated_at>l.updated_at OR (r.updated_at=l.updated_at AND ({})>({})) OR EXISTS(SELECT 1 FROM backup_source_consent s LEFT JOIN backup_local_consent old USING(root) WHERE s.root=r.contact_identity_commitment AND {} AND ((s.state='lifted' AND r.state='accepted') OR s.state=r.state))",
            rank("r"),
            rank("l"),
            consent_supersedes_projection(
                "s",
                "old",
                "CASE WHEN l.state='accepted' THEN 'lifted' ELSE l.state END"
            )
        );
    }
    if table == "runtime_actor_state" {
        let timestamp = |alias: &str| {
            format!(
                "coalesce(json_extract(CAST({alias}.state_json AS TEXT),'$.signed_device_set.device_set_epoch'),json_extract(CAST({alias}.state_json AS TEXT),'$.revision'),json_extract(CAST({alias}.state_json AS TEXT),'$.updated_at'),json_extract(CAST({alias}.state_json AS TEXT),'$.seq'),json_extract(CAST({alias}.state_json AS TEXT),'$.group_epoch'),0)"
            )
        };
        return format!(
            "{}>{} AND r.state_kind NOT LIKE 'dm-pair/%' AND r.state_kind NOT LIKE 'identity/%'",
            timestamp("r"),
            timestamp("l")
        );
    }
    let fields = ORDER_FIELDS
        .iter()
        .copied()
        .filter(|name| columns.iter().any(|(column, _)| column == name))
        .collect::<Vec<_>>();
    if fields.is_empty()
        || table == "local_event_log"
        || table == "group_member_device_key"
        || table == "projection_checkpoint"
    {
        return "0".into();
    }
    let expr = |alias| {
        format!(
            "({})",
            fields
                .iter()
                .map(|field| format!("coalesce({alias}.{},0)", quoted(field)))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    format!("{}>{}", expr("r"), expr("l"))
}
fn add_count(counts: &mut BackupCounts, table: &str, n: u64) {
    match table {
        "friend_link_projection" => counts.contacts += n,
        "conversation_projection" => counts.conversations += n,
        "message_projection" | "direct_message_projection" => counts.messages += n,
        "group_projection" => counts.groups += n,
        _ => {}
    }
}
