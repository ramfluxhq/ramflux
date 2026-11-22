// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `open_verified`: B's hardened read-only open of a received export file (A7, design r3 N1).
//! Order before the FIRST statement on the file: size from metadata only; open READONLY,
//! NOFOLLOW, URI `immutable=1`; engine pragmas that do no I/O; every `db_config` flag; every
//! `sqlite3_limit`; the progress handler; the phase authorizer; then `PRAGMA key`. Then the
//! schema compare (no table is read before it passes), `quick_check`, the root check.
//! Backup restore uses this same owner (`backup_hardened`), with its own limits and a
//! row copy into a database this binary migrated. The export open below is unchanged.
use super::builder::{self, Built, Side};
use super::contract::{SchemaRow, canonical_schema_rows, schema_rows};
use super::tables::EXPORT_TABLES;
use crate::schema::MAX_DECLARED_TRIGGER_STEPS;
use crate::{AccountDbKey, StorageError};
use rusqlite::config::DbConfig;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// B's own hard cap on a received export file, independent of A's signed `total_bytes`.
pub(crate) const RECEIVED_FILE_CAP: u64 =
    ramflux_protocol::custody::pairing::full_transfer::PREPUBLICATION_DELTA_STOP_BYTES;
/// `SQLCipher` page size this storage keys every database with (`cipher_page_size` default).
pub(crate) const CIPHER_PAGE_BYTES: u64 = 4096;
const LIMIT_LENGTH: i32 = 4 * 1024 * 1024;
const LIMIT_SQL_LENGTH: i32 = 8 * 1024;
const LIMIT_COLUMN: i32 = 16;
const LIMIT_EXPR_DEPTH: i32 = 8;
const LIMIT_COMPOUND_SELECT: i32 = 2;
const LIMIT_VDBE_OP: i32 = 25_000;
const LIMIT_FUNCTION_ARG: i32 = 2;
const LIMIT_LIKE_PATTERN: i32 = 8;
const LIMIT_VARIABLE_NUMBER: i32 = 1;
const LIMIT_PARSER_DEPTH: i32 = 64;
const PROGRESS_PERIOD_OPS: i32 = 1_000;

/// SQLite limits applied by [`harden`]. Transfer and backup share the call; the numbers differ.
pub(crate) struct EngineLimits {
    pub(crate) length: i32,
    pub(crate) sql_length: i32,
    pub(crate) column: i32,
    pub(crate) expr_depth: i32,
    pub(crate) compound_select: i32,
    pub(crate) vdbe_op: i32,
    pub(crate) function_arg: i32,
    pub(crate) like_pattern: i32,
    pub(crate) variable_number: i32,
    pub(crate) parser_depth: i32,
    pub(crate) schema: i32,
}

/// The limits `VerifiedExport::open` already applied, including its schema-object cap.
pub(crate) fn transfer_limits(schema_objects: i32) -> EngineLimits {
    EngineLimits {
        length: LIMIT_LENGTH,
        sql_length: LIMIT_SQL_LENGTH,
        column: LIMIT_COLUMN,
        expr_depth: LIMIT_EXPR_DEPTH,
        compound_select: LIMIT_COMPOUND_SELECT,
        vdbe_op: LIMIT_VDBE_OP,
        function_arg: LIMIT_FUNCTION_ARG,
        like_pattern: LIMIT_LIKE_PATTERN,
        variable_number: LIMIT_VARIABLE_NUMBER,
        parser_depth: LIMIT_PARSER_DEPTH,
        schema: schema_objects,
    }
}
/// Progress callbacks allowed per page of input, per phase (open checks, then the copy).
const PROGRESS_CALLS_PER_PAGE: u64 = 64;
const PROGRESS_CALLS_BASE: u64 = 4_096;
const OPEN_DEADLINE: Duration = Duration::from_secs(60);
const COPY_DEADLINE: Duration = Duration::from_secs(300);

const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
pub(crate) const PHASE_KEY: u8 = 0;
pub(crate) const PHASE_SCHEMA: u8 = 1;
pub(crate) const PHASE_QUICK_CHECK: u8 = 2;
pub(crate) const PHASE_ROWS: u8 = 3;
pub(crate) const PHASE_CLOSED: u8 = 4;
/// Column introspection (`PRAGMA table_xinfo`) for a backup row copy. Transfer never enters it.
pub(crate) const PHASE_COLUMNS: u8 = 5;

pub(crate) fn refused(step: &'static str) -> StorageError {
    StorageError::TransferExportRefused(step)
}

/// Refusal with the engine's error code and message logged (they hold no key or row value).
pub(crate) fn refused_by(step: &'static str, error: &dyn std::fmt::Display) -> StorageError {
    tracing::warn!(step, %error, "received export refused");
    refused(step)
}

/// Step budget of the progress handler: a call count and a wall-clock deadline.
pub(crate) struct Budget {
    start: Instant,
    calls: AtomicU64,
    max_calls: AtomicU64,
    deadline_ms: AtomicU64,
}

impl Budget {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            calls: AtomicU64::new(0),
            max_calls: AtomicU64::new(0),
            deadline_ms: AtomicU64::new(0),
        })
    }
    pub(crate) fn reset(&self, max_calls: u64, deadline: Duration) {
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let limit = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
        self.calls.store(0, Ordering::SeqCst);
        self.max_calls.store(max_calls, Ordering::SeqCst);
        self.deadline_ms.store(elapsed.saturating_add(limit), Ordering::SeqCst);
    }
    /// True interrupts the running statement.
    fn exhausted(&self) -> bool {
        let calls = self.calls.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        calls > self.max_calls.load(Ordering::SeqCst)
            || elapsed > self.deadline_ms.load(Ordering::SeqCst)
    }
}

/// A received export file that passed every check of `open_verified`.
pub(crate) struct VerifiedExport {
    db: Connection,
    phase: Arc<AtomicU8>,
    budget: Arc<Budget>,
    pages: u64,
}

/// Step 1: size from file metadata only.
pub(crate) fn checked_size(path: &Path, cap: u64) -> Result<u64, StorageError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| refused("size"))?;
    let len = metadata.len();
    if !metadata.is_file() || len == 0 || len % CIPHER_PAGE_BYTES != 0 || len > cap {
        return Err(refused("size"));
    }
    builder::require_no_sidecar_files(path)?;
    Ok(len / CIPHER_PAGE_BYTES)
}

/// `file:` URI of an absolute path with every byte outside the unreserved set escaped.
fn immutable_uri(path: &Path) -> Result<String, StorageError> {
    let text = path.to_str().ok_or_else(|| refused("open"))?.replace('\\', "/");
    if !path.is_absolute() {
        return Err(refused("open"));
    }
    let mut uri = String::from("file:");
    if !text.starts_with('/') {
        uri.push('/');
    }
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"/._-~:".contains(&byte) {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX_DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or(b'0')));
            uri.push(char::from(HEX_DIGITS.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0')));
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Ok(uri)
}

/// Steps 2–6: open, engine pragmas without I/O, `db_config`, limits, progress handler.
pub(crate) fn harden(
    path: &Path,
    limits: &EngineLimits,
    budget: &Arc<Budget>,
) -> Result<Connection, StorageError> {
    let mut db = Connection::open_with_flags(
        immutable_uri(path)?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| refused("open"))?;
    // Flag pragmas without PragFlg_NeedSchema: they set connection state and read no page.
    db.execute_batch("PRAGMA cell_size_check=ON; PRAGMA mmap_size=0; PRAGMA query_only=ON;")
        .map_err(|error| refused_by("harden", &error))?;
    let flags = [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER, false),
    ];
    for (flag, value) in flags {
        if db.set_db_config(flag, value).map_err(|error| refused_by("harden", &error))? != value {
            return Err(refused("harden"));
        }
    }
    let applied = [
        (Limit::SQLITE_LIMIT_LENGTH, limits.length),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, limits.sql_length),
        (Limit::SQLITE_LIMIT_COLUMN, limits.column),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, limits.expr_depth),
        (Limit::SQLITE_LIMIT_COMPOUND_SELECT, limits.compound_select),
        (Limit::SQLITE_LIMIT_VDBE_OP, limits.vdbe_op),
        (Limit::SQLITE_LIMIT_FUNCTION_ARG, limits.function_arg),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_LIKE_PATTERN_LENGTH, limits.like_pattern),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, limits.variable_number),
        (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 1),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
        (Limit::SQLITE_LIMIT_PARSER_DEPTH, limits.parser_depth),
        (Limit::SQLITE_LIMIT_SCHEMA, limits.schema),
        (Limit::SQLITE_LIMIT_TRIGGER_STEPS, MAX_DECLARED_TRIGGER_STEPS),
    ];
    for (limit, value) in applied {
        db.set_limit(limit, value).map_err(|error| refused_by("harden", &error))?;
        if db.limit(limit).map_err(|error| refused_by("harden", &error))? > value {
            return Err(refused("harden"));
        }
    }
    let handler = Arc::clone(budget);
    db.progress_handler(PROGRESS_PERIOD_OPS, Some(move || handler.exhausted()))
        .map_err(|error| refused_by("harden", &error))?;
    Ok(db)
}

/// Step 7: the phase authorizer. Everything is denied except, per phase: `PRAGMA key`;
/// SELECT and READ of `sqlite_schema`; `PRAGMA quick_check`; SELECT and READ of listed tables.
pub(crate) fn authorize(
    phase: &AtomicU8,
    tables: &[String],
    context: &AuthContext<'_>,
) -> Authorization {
    let main = matches!(context.database_name, None | Some("main"));
    let allowed = match (phase.load(Ordering::SeqCst), context.action) {
        (PHASE_KEY, AuthAction::Pragma { pragma_name, .. }) => pragma_name == "key",
        (PHASE_SCHEMA | PHASE_ROWS | PHASE_COLUMNS, AuthAction::Select)
        | (PHASE_COLUMNS, AuthAction::Function { .. }) => true,
        (PHASE_SCHEMA, AuthAction::Read { table_name, .. }) => {
            main && matches!(table_name, "sqlite_master" | "sqlite_schema")
        }
        (PHASE_COLUMNS, AuthAction::Read { table_name, .. }) => {
            main && (matches!(table_name, "sqlite_master" | "sqlite_schema")
                || tables.iter().any(|table| table == table_name))
        }
        (PHASE_QUICK_CHECK, AuthAction::Pragma { pragma_name, pragma_value }) => {
            pragma_name == "quick_check" && pragma_value.is_none()
        }
        (PHASE_COLUMNS, AuthAction::Pragma { pragma_name, .. }) => {
            matches!(pragma_name, "table_info" | "table_xinfo")
        }
        (PHASE_ROWS, AuthAction::Read { table_name, .. }) => {
            main && tables.iter().any(|table| table == table_name)
        }
        _ => false,
    };
    if allowed { Authorization::Allow } else { Authorization::Deny }
}

impl VerifiedExport {
    /// Opens a received export file through every hardening step and check, in order.
    /// # Errors
    /// `TransferExportRefused(step)` naming the first step that refused: `size`, `sidecar`,
    /// `open`, `harden`, `key`, `schema_load`, `schema`, `quick_check`, `root`.
    pub(crate) fn open(
        path: &Path,
        key: &AccountDbKey,
        expected_root: &str,
    ) -> Result<Self, StorageError> {
        let pages = checked_size(path, RECEIVED_FILE_CAP)?;
        let reference: Vec<SchemaRow> = canonical_schema_rows()?;
        let budget = Budget::new();
        budget.reset(
            PROGRESS_CALLS_BASE.saturating_add(pages.saturating_mul(PROGRESS_CALLS_PER_PAGE)),
            OPEN_DEADLINE,
        );
        // SQLite's limit counts its in-memory schema objects: its own schema table, every table,
        // and the primary-key index of every WITHOUT ROWID table besides the stored rows.
        let objects = reference.len().saturating_add(EXPORT_TABLES.len()).saturating_add(1);
        let schema_objects = i32::try_from(objects).map_err(|_| refused("harden"))?;
        let mut db = harden(path, &transfer_limits(schema_objects), &budget)?;
        let phase = Arc::new(AtomicU8::new(PHASE_KEY));
        let gate = Arc::clone(&phase);
        let tables: Vec<String> =
            EXPORT_TABLES.iter().map(|table| table.name.to_string()).collect();
        db.authorizer(Some(move |context: AuthContext<'_>| authorize(&gate, &tables, &context)))
            .map_err(|error| refused_by("harden", &error))?;
        let pragma = Zeroizing::new(format!(
            "PRAGMA key=\"x'{}'\";",
            Zeroizing::new(key.sqlcipher_hex()).as_str()
        ));
        db.execute_batch(&pragma).map_err(|error| refused_by("key", &error))?;
        phase.store(PHASE_SCHEMA, Ordering::SeqCst);
        // The first statement that reads the file: the schema loads under the limits and
        // the step budget, and no table is read before this compare passes.
        let rows = schema_rows(&db).map_err(|error| refused_by("schema_load", &error))?;
        if rows != reference {
            return Err(refused("schema"));
        }
        phase.store(PHASE_QUICK_CHECK, Ordering::SeqCst);
        quick_check(&db)?;
        phase.store(PHASE_ROWS, Ordering::SeqCst);
        let verified = Self { db, phase, budget, pages };
        verified.require_root(expected_root)?;
        Ok(verified)
    }

    /// Builds B's clean copy from this handle through the shared builder, under B's key.
    /// # Errors
    /// `TransferExportRefused(step)` for any row outside the contract; SQL and I/O errors.
    pub(crate) fn clean_copy(
        &self,
        target: &Path,
        key: &AccountDbKey,
    ) -> Result<Built, StorageError> {
        self.budget.reset(
            PROGRESS_CALLS_BASE.saturating_add(self.pages.saturating_mul(PROGRESS_CALLS_PER_PAGE)),
            COPY_DEADLINE,
        );
        builder::build(&self.db, Side::Received, target, key)
    }

    /// Reset the step budget for a full row walk after the open checks.
    pub(crate) fn allow_row_read(&self) {
        self.budget.reset(
            PROGRESS_CALLS_BASE.saturating_add(self.pages.saturating_mul(PROGRESS_CALLS_PER_PAGE)),
            COPY_DEADLINE,
        );
    }

    /// The hardened connection, still under the row-phase authorizer.
    #[must_use]
    pub(crate) fn connection(&self) -> &rusqlite::Connection {
        &self.db
    }

    fn require_root(&self, expected_root: &str) -> Result<(), StorageError> {
        let mut statement = self
            .db
            .prepare(
                "SELECT \"singleton\",\"principal_commitment\" FROM \"runtime_account_identity\"",
            )
            .map_err(|error| refused_by("root", &error))?;
        let rows: Vec<(i64, String)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .and_then(Iterator::collect)
            .map_err(|error| refused_by("root", &error))?;
        match rows.as_slice() {
            [(1, root)] if root == expected_root => Ok(()),
            _ => Err(refused("root")),
        }
    }
}

impl Drop for VerifiedExport {
    fn drop(&mut self) {
        self.phase.store(PHASE_CLOSED, Ordering::SeqCst);
    }
}

pub(crate) fn quick_check(db: &Connection) -> Result<(), StorageError> {
    let mut statement =
        db.prepare("PRAGMA quick_check").map_err(|error| refused_by("quick_check", &error))?;
    let rows: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .and_then(Iterator::collect)
        .map_err(|error| refused_by("quick_check", &error))?;
    if rows.as_slice() != ["ok"] {
        return Err(refused("quick_check"));
    }
    Ok(())
}
