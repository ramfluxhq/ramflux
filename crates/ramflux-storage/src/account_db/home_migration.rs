// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned migration state and immutable public transitions in the same FULL transaction.
use super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;

const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROGRESS_BYTES: usize = 4096;
const MAX_JOBS: u64 = 64;
const MAX_PENDING: u64 = 128;
const TAG: &str = "home_migration_progress";

#[derive(Clone, PartialEq, Eq)]
pub struct HomeMigrationStateRow {
    pub operation_id: String,
    pub account_anchor: String,
    pub intent_hash: String,
    pub revision: u64,
    pub active: bool,
    pub recovery_blocked: bool,
    pub next_attempt_at: u64,
    pub state: Vec<u8>,
    pub progress: Value,
}
impl std::fmt::Debug for HomeMigrationStateRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HomeMigrationStateRow")
            .field("operation_id", &self.operation_id)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy)]
pub struct HomeMigrationWrite<'a> {
    pub operation_id: &'a str,
    pub account_anchor: &'a str,
    pub intent_hash: &'a str,
    pub expected_revision: Option<u64>,
    pub revision: u64,
    pub active: bool,
    pub recovery_blocked: bool,
    pub next_attempt_at: u64,
    pub state: &'a [u8],
    pub progress: &'a Value,
}

fn digest(value: &str) -> bool {
    ramflux_protocol::decode_base64url(value)
        .is_ok_and(|bytes| bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == value)
}
fn identifier(value: &Value, nullable: bool, maximum: usize) -> bool {
    (nullable && value.is_null())
        || value.as_str().is_some_and(|s| {
            !s.is_empty() && s.len() <= maximum && !s.chars().any(char::is_control)
        })
}
fn counter(value: &Value, nullable: bool) -> bool {
    (nullable && value.is_null())
        || value.as_u64().is_some_and(|v| v <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
}
fn valid_progress(input: &HomeMigrationWrite<'_>) -> Result<Vec<u8>, StorageError> {
    const REQUIRED: &[&str] = &[
        "operation_id",
        "seq",
        "phase",
        "source",
        "target",
        "home_epoch",
        "home_hash",
        "commit_deadline",
        "forward_until",
        "backlog",
    ];
    let object = input.progress.as_object().ok_or(StorageError::AuthorizationRejected)?;
    if object.keys().any(|k| !REQUIRED.contains(&k.as_str()) && k != "reason")
        || REQUIRED.iter().any(|key| !object.contains_key(*key))
        || input.progress["operation_id"].as_str() != Some(input.operation_id)
        || input.progress["seq"].as_u64() != Some(input.revision)
        || !identifier(&input.progress["phase"], false, 64)
        || !identifier(&input.progress["source"], false, 256)
        || !identifier(&input.progress["target"], true, 256)
        || !identifier(&input.progress["reason"], true, 64)
        || ["home_epoch", "commit_deadline", "forward_until"]
            .iter()
            .any(|k| !counter(&input.progress[*k], true))
        || !(input.progress["home_hash"].is_null()
            || input.progress["home_hash"].as_str().is_some_and(digest))
    {
        return Err(StorageError::AuthorizationRejected);
    }
    let backlog: ramflux_protocol::home_migration::BacklogProgress =
        serde_json::from_value(input.progress["backlog"].clone())?;
    let total = [
        backlog.forwarded,
        backlog.receiver_acked,
        backlog.expired,
        backlog.rejected,
        backlog.remaining,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add);
    if total != Some(backlog.scheduled)
        || backlog.evidence_required > backlog.remaining
        || backlog.scheduled > ramflux_protocol::MAX_SAFE_JSON_INTEGER
    {
        return Err(StorageError::AuthorizationRejected);
    }
    let bytes = serde_json::to_vec(input.progress)?;
    if bytes.len() > MAX_PROGRESS_BYTES {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(bytes)
}

impl AccountDb {
    pub(super) fn install_home_migration_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS runtime_home_migration_job(
            operation_id TEXT PRIMARY KEY, account_anchor TEXT NOT NULL, intent_hash TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision>0 AND revision<=9007199254740991),
            active INTEGER NOT NULL CHECK(active IN(0,1)),
            recovery_blocked INTEGER NOT NULL CHECK(recovery_blocked IN(0,1) AND recovery_blocked<=active),
            next_attempt_at INTEGER NOT NULL, state_json BLOB NOT NULL CHECK(length(state_json)<=8388608),
            progress_json BLOB NOT NULL CHECK(length(progress_json)<=4096));
            CREATE UNIQUE INDEX IF NOT EXISTS runtime_home_migration_active ON runtime_home_migration_job(active) WHERE active=1;
            CREATE TABLE IF NOT EXISTS runtime_home_migration_transition(
                id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, revision INTEGER NOT NULL,
                progress_json BLOB NOT NULL CHECK(length(progress_json)<=4096),UNIQUE(operation_id,revision));
            CREATE TRIGGER IF NOT EXISTS runtime_home_migration_progress_insert AFTER INSERT ON runtime_home_migration_transition
            BEGIN INSERT INTO runtime_outbox(table_name,change_kind,row_id,keys_json)
              VALUES('home_migration_progress','insert',NEW.id,json_object('operation_id',NEW.operation_id,'seq',NEW.revision)); END;")?;
        Ok(())
    }
    /// Read an opaque private job; callers must validate its version and account binding.
    /// # Errors
    /// Returns SQL or stored metadata decoding errors.
    pub fn home_migration_job(
        &self,
        operation: &str,
    ) -> Result<Option<HomeMigrationStateRow>, StorageError> {
        Ok(self.connection.query_row("SELECT operation_id,account_anchor,intent_hash,revision,active,recovery_blocked,next_attempt_at,state_json,progress_json FROM runtime_home_migration_job WHERE operation_id=?1",params![operation],row).optional()?)
    }
    /// Return the single live operation without decoding unrelated account state.
    /// # Errors
    /// Returns SQL or stored metadata decoding errors.
    pub fn active_home_migration(&self) -> Result<Option<HomeMigrationStateRow>, StorageError> {
        Ok(self.connection.query_row("SELECT operation_id,account_anchor,intent_hash,revision,active,recovery_blocked,next_attempt_at,state_json,progress_json FROM runtime_home_migration_job WHERE active=1",[],row).optional()?)
    }
    /// Return immutable public progress for an outbox row, never a mutable current snapshot.
    /// # Errors
    /// Returns SQL or metadata decoding errors.
    pub fn home_migration_transition(&self, id: i64) -> Result<Option<Value>, StorageError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT progress_json FROM runtime_home_migration_transition WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        bytes.map(|b| serde_json::from_slice(&b).map_err(StorageError::from)).transpose()
    }
    /// Persist before external effects. A failed CAS or outbox write rolls back everything.
    /// # Errors
    /// Rejects changed intent, stale revision, concurrent live jobs and bounded-queue exhaustion.
    pub fn persist_home_migration(
        &self,
        input: HomeMigrationWrite<'_>,
    ) -> Result<(), StorageError> {
        if !digest(input.operation_id)
            || !digest(input.account_anchor)
            || !digest(input.intent_hash)
            || input.state.is_empty()
            || input.state.len() > MAX_STATE_BYTES
            || input.expected_revision.unwrap_or(0).checked_add(1) != Some(input.revision)
            || input.revision > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            || input.next_attempt_at > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            || (input.recovery_blocked && !input.active)
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let progress = valid_progress(&input)?;
        self.write_transaction(|| {
            self.prune_home_migration_history()?;
            let prior = self.home_migration_job(input.operation_id)?;
            if prior.as_ref().map(|r|r.revision) != input.expected_revision
                || prior.as_ref().is_some_and(|r|r.intent_hash != input.intent_hash || r.account_anchor != input.account_anchor) {
                return Err(StorageError::EventIdConflict(input.operation_id.into()));
            }
            if input.active && self.active_home_migration()?.is_some_and(|r|r.operation_id != input.operation_id) {
                return Err(StorageError::AuthorizationRejected);
            }
            let jobs: u64 = self.connection.query_row("SELECT count(*) FROM runtime_home_migration_job",[],|r|r.get(0))?;
            let pending: u64 = self.connection.query_row("SELECT count(*) FROM runtime_outbox WHERE table_name=?1 AND published=0",params![TAG],|r|r.get(0))?;
            if (prior.is_none() && jobs >= MAX_JOBS) || pending >= MAX_PENDING { return Err(StorageError::AuthorizationRejected); }
            self.connection.execute("INSERT INTO runtime_home_migration_job(operation_id,account_anchor,intent_hash,revision,active,recovery_blocked,next_attempt_at,state_json,progress_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(operation_id) DO UPDATE SET revision=excluded.revision,active=excluded.active,recovery_blocked=excluded.recovery_blocked,next_attempt_at=excluded.next_attempt_at,state_json=excluded.state_json,progress_json=excluded.progress_json",params![input.operation_id,input.account_anchor,input.intent_hash,input.revision,input.active,input.recovery_blocked,input.next_attempt_at,input.state,progress])?;
            self.connection.execute("INSERT INTO runtime_home_migration_transition(operation_id,revision,progress_json) VALUES(?1,?2,?3)",params![input.operation_id,input.revision,progress])?;
            Ok(())
        })
    }
    fn prune_home_migration_history(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("DELETE FROM runtime_home_migration_transition WHERE revision<(SELECT max(revision)-32 FROM runtime_home_migration_transition newer WHERE newer.operation_id=runtime_home_migration_transition.operation_id) AND NOT EXISTS(SELECT 1 FROM runtime_outbox o WHERE o.table_name='home_migration_progress' AND o.row_id=runtime_home_migration_transition.id AND o.published=0);
            DELETE FROM runtime_home_migration_job WHERE operation_id IN(SELECT operation_id FROM runtime_home_migration_job WHERE active=0 ORDER BY rowid DESC LIMIT -1 OFFSET 8) AND NOT EXISTS(SELECT 1 FROM runtime_home_migration_transition t JOIN runtime_outbox o ON o.table_name='home_migration_progress' AND o.row_id=t.id AND o.published=0 WHERE t.operation_id=runtime_home_migration_job.operation_id);
            DELETE FROM runtime_home_migration_transition WHERE NOT EXISTS(SELECT 1 FROM runtime_home_migration_job j WHERE j.operation_id=runtime_home_migration_transition.operation_id) AND NOT EXISTS(SELECT 1 FROM runtime_outbox o WHERE o.table_name='home_migration_progress' AND o.row_id=runtime_home_migration_transition.id AND o.published=0);")?;
        Ok(())
    }
}
fn row(row: &crate::database::Row) -> rusqlite::Result<HomeMigrationStateRow> {
    let progress: Vec<u8> = row.get(8)?;
    Ok(HomeMigrationStateRow {
        operation_id: row.get(0)?,
        account_anchor: row.get(1)?,
        intent_hash: row.get(2)?,
        revision: row.get(3)?,
        active: row.get(4)?,
        recovery_blocked: row.get(5)?,
        next_attempt_at: row.get(6)?,
        state: row.get(7)?,
        progress: serde_json::from_slice(&progress).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Blob, Box::new(e))
        })?,
    })
}

/// Backup generations never export or re-arm private migration work or its progress history.
pub(super) fn strip_from_backup(db: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    db.execute_batch("DROP TABLE IF EXISTS runtime_home_migration_transition; DROP TABLE IF EXISTS runtime_home_migration_job;")?;
    for (table, predicate) in [
        ("runtime_outbox", "table_name='home_migration_progress'"),
        ("runtime_journal", "topic='home_migration.progress'"),
    ] {
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            params![table],
            |r| r.get(0),
        )?;
        if exists {
            db.execute(&format!("DELETE FROM {table} WHERE {predicate}"), [])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
