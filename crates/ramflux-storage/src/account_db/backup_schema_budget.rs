// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Hardened-open limits measured from the account catalog this binary installs.
//! The reference is not a fresh empty file. It is a backup snapshot of two accounts
//! after one contact row, one conversation, two messages, one journal row, a second
//! open, and the mac-bundle migration (`schema_version` 14). Search tables are not
//! part of that snapshot: `LOCAL_SEARCH_V1` is off, and the snapshot writer strips
//! the `local_search_*` family when it is present.
//!
//! Object names do not grow per message or per contact. They grow when an installer
//! runs (runtime schema, migrations, the second open's domain triggers) or when
//! SQLite adds one `sqlite_sequence` / `sqlite_stat*` table. The sqlite object cap
//! is that catalog count plus headroom. Names outside the catalog are refused.

use super::transfer_export::open_verified::{self, EngineLimits};
use crate::{AccountDb, AccountDbKey, AccountIndex, StorageError};
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use zeroize::Zeroizing;

const TEXT_HEADROOM: i32 = 1024;
const COLUMN_HEADROOM: i32 = 4;
const DEPTH_HEADROOM: i32 = 8;
const COMPOUND_HEADROOM: i32 = 1;
const ARG_HEADROOM: i32 = 2;
const STEP_HEADROOM: i32 = 4;
const SCHEMA_HEADROOM: i32 = 32;
const LIKE_HEADROOM: i32 = 64;
const TRIAL_HIGH: i32 = 1_000_000_000;
/// Copy-phase cell cap. Payload bytes grow with the message; this is the parser bound.
pub(crate) const ROW_CELL_LIMIT: i32 = 256 * 1024 * 1024;

const POPULATE_SQL: &str = "
INSERT INTO runtime_journal(at,topic,body_json,source_key) VALUES(1,'catalog',x'00','catalog-row');
INSERT INTO friend_link_projection(link_id,requester_id,target_id,state,updated_at)
    VALUES('link-1','acct','peer','accepted',1);
INSERT INTO conversation_projection(conversation_id,conversation_kind,projection_version,updated_at)
    VALUES('conv-1','direct',1,1);
INSERT INTO conversation_list_state(conversation_id,archived,updated_at) VALUES('conv-1',0,1);
INSERT INTO direct_message_projection(
    conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at)
    VALUES('conv-1','msg-a','acct',x'01',x'7b7d',0,1,1);
INSERT INTO direct_message_projection(
    conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at)
    VALUES('conv-1','msg-b','peer',x'02',x'7b7d',0,0,2);
";

pub(crate) struct SchemaBudget {
    pub(crate) limits: EngineLimits,
    pub(crate) row_cell: i32,
    names: BTreeSet<String>,
}

struct CatalogDir {
    path: PathBuf,
}

struct RawLimits {
    length: i32,
    sql_length: i32,
    columns: i32,
    names: BTreeSet<String>,
    expr_depth: i32,
    compound_select: i32,
    vdbe_op: i32,
    function_arg: i32,
    parser_depth: i32,
    schema: i32,
    trigger_steps: i32,
    attached: i32,
    like_pattern: i32,
    variable_number: i32,
    trigger_depth: i32,
    worker_threads: i32,
}

struct CompileMinimums {
    expr_depth: i32,
    compound_select: i32,
    vdbe_op: i32,
    function_arg: i32,
    parser_depth: i32,
    schema: i32,
    trigger_steps: i32,
}

struct SecurityCaps {
    attached: i32,
    like_pattern: i32,
    variable_number: i32,
    trigger_depth: i32,
    worker_threads: i32,
    base: EngineLimits,
}

pub(crate) fn budget() -> Result<&'static SchemaBudget, StorageError> {
    static SLOT: OnceLock<SchemaBudget> = OnceLock::new();
    if let Some(ready) = SLOT.get() {
        return Ok(ready);
    }
    let built = build()?;
    Ok(SLOT.get_or_init(|| built))
}

pub(crate) fn require_known(
    objects: &[(String, String, Option<String>)],
) -> Result<(), StorageError> {
    let catalog = budget()?;
    for (kind, name, _) in objects {
        if !known_kind(kind) || (!catalog.names.contains(name) && !sqlite_owned(name)) {
            return Err(open_verified::refused("schema"));
        }
    }
    Ok(())
}

fn build() -> Result<SchemaBudget, StorageError> {
    let dir = catalog_dir()?;
    let snap_key = write_reference(&dir)?;
    let path = dir.path.join("snapshot.db");
    let measured = measure(&path, &snap_key)?;
    let limits = widen(&measured);
    if !accepts(&path, &snap_key, &limits)? {
        return Err(catalog_error());
    }
    Ok(SchemaBudget { limits, row_cell: ROW_CELL_LIMIT, names: measured.names })
}

fn write_reference(dir: &CatalogDir) -> Result<AccountDbKey, StorageError> {
    let (acct_key, peer_key) = first_session(dir)?;
    let index = AccountIndex::open(&dir.path)?;
    let acct = AccountDb::open(&index, "acct", &acct_key)?;
    let _peer = AccountDb::open(&index, "peer", &peer_key)?;
    Ok(acct.write_backup_snapshot(&dir.path.join("snapshot.db"))?.key)
}

fn first_session(dir: &CatalogDir) -> Result<(AccountDbKey, AccountDbKey), StorageError> {
    let index = AccountIndex::open(&dir.path)?;
    index.create_account("acct", "acct-principal")?;
    index.create_account("peer", "peer-principal")?;
    let acct_key = AccountDbKey::generate()?;
    let peer_key = AccountDbKey::generate()?;
    let acct = AccountDb::open(&index, "acct", &acct_key)?;
    let _peer = AccountDb::open(&index, "peer", &peer_key)?;
    populate(&acct)?;
    age_mac_bundle(&acct)?;
    Ok((acct_key, peer_key))
}

fn populate(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.execute_batch(POPULATE_SQL)?;
    Ok(())
}

fn age_mac_bundle(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.execute_batch(
        "DROP TABLE IF EXISTS account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
    )?;
    Ok(())
}

fn measure(path: &Path, key: &AccountDbKey) -> Result<RawLimits, StorageError> {
    let db = open_plain(path, key)?;
    let (length, columns) = text_bounds(&db)?;
    let names = object_names(&db)?;
    drop(db);
    let wide = wide_limits();
    if !accepts(path, key, &wide)? {
        return Err(catalog_error());
    }
    let secure = security_caps(path, key, wide)?;
    let (length, sql_length, columns, base) =
        text_minimums(path, key, secure.base, length, columns)?;
    let compiled = compile_minimums(path, key, base)?;
    Ok(RawLimits {
        length,
        sql_length,
        columns,
        names,
        expr_depth: compiled.expr_depth,
        compound_select: compiled.compound_select,
        vdbe_op: compiled.vdbe_op,
        function_arg: compiled.function_arg,
        parser_depth: compiled.parser_depth,
        schema: compiled.schema,
        trigger_steps: compiled.trigger_steps,
        attached: secure.attached,
        like_pattern: secure.like_pattern,
        variable_number: secure.variable_number,
        trigger_depth: secure.trigger_depth,
        worker_threads: secure.worker_threads,
    })
}

fn text_minimums(
    path: &Path,
    key: &AccountDbKey,
    base: EngineLimits,
    text_length: i32,
    text_columns: i32,
) -> Result<(i32, i32, i32, EngineLimits), StorageError> {
    let length = lowest(path, key, base, |limits, value| limits.length = value)?.max(text_length);
    let sql_length =
        lowest(path, key, base, |limits, value| limits.sql_length = value)?.max(text_length);
    let columns = lowest(path, key, base, |limits, value| limits.column = value)?.max(text_columns);
    let mut tightened = base;
    tightened.length = length;
    tightened.sql_length = sql_length;
    tightened.column = columns;
    Ok((length, sql_length, columns, tightened))
}

fn compile_minimums(
    path: &Path,
    key: &AccountDbKey,
    base: EngineLimits,
) -> Result<CompileMinimums, StorageError> {
    Ok(CompileMinimums {
        expr_depth: lowest(path, key, base, |limits, value| limits.expr_depth = value)?,
        compound_select: lowest(path, key, base, |limits, value| limits.compound_select = value)?,
        vdbe_op: lowest(path, key, base, |limits, value| limits.vdbe_op = value)?,
        function_arg: lowest(path, key, base, |limits, value| limits.function_arg = value)?,
        parser_depth: lowest(path, key, base, |limits, value| limits.parser_depth = value)?,
        schema: lowest(path, key, base, |limits, value| limits.schema = value)?,
        trigger_steps: lowest(path, key, base, |limits, value| limits.trigger_steps = value)?,
    })
}

fn security_caps(
    path: &Path,
    key: &AccountDbKey,
    wide: EngineLimits,
) -> Result<SecurityCaps, StorageError> {
    let mut trial = wide;
    trial.attached = 0;
    trial.like_pattern = 0;
    trial.variable_number = 0;
    trial.trigger_depth = 0;
    trial.worker_threads = 0;
    if accepts(path, key, &trial)? {
        return Ok(SecurityCaps {
            attached: 0,
            like_pattern: 0,
            variable_number: 0,
            trigger_depth: 0,
            worker_threads: 0,
            base: trial,
        });
    }
    let attached = lowest(path, key, wide, |limits, value| limits.attached = value)?;
    let like_pattern = lowest(path, key, wide, |limits, value| limits.like_pattern = value)?;
    let variable_number = lowest(path, key, wide, |limits, value| limits.variable_number = value)?;
    let trigger_depth = lowest(path, key, wide, |limits, value| limits.trigger_depth = value)?;
    let worker_threads = lowest(path, key, wide, |limits, value| limits.worker_threads = value)?;
    let mut base = wide;
    base.attached = attached;
    base.like_pattern = like_pattern;
    base.variable_number = variable_number;
    base.trigger_depth = trigger_depth;
    base.worker_threads = worker_threads;
    Ok(SecurityCaps {
        attached,
        like_pattern,
        variable_number,
        trigger_depth,
        worker_threads,
        base,
    })
}

fn lowest(
    path: &Path,
    key: &AccountDbKey,
    base: EngineLimits,
    set: impl Fn(&mut EngineLimits, i32),
) -> Result<i32, StorageError> {
    let mut limits = base;
    set(&mut limits, 0);
    // SQLite skips the compound-select check when the limit is 0, so a
    // successful 0 is not a cap unless 1 also loads.
    if accepts(path, key, &limits)? {
        set(&mut limits, 1);
        if accepts(path, key, &limits)? {
            return Ok(0);
        }
    }
    let mut lo = 0_i32;
    let mut hi = 1_i32;
    while hi < TRIAL_HIGH {
        set(&mut limits, hi);
        if accepts(path, key, &limits)? {
            break;
        }
        lo = hi;
        let next = hi.saturating_mul(2);
        if next <= hi {
            hi = TRIAL_HIGH;
            break;
        }
        hi = next;
    }
    if hi > TRIAL_HIGH {
        hi = TRIAL_HIGH;
    }
    set(&mut limits, hi);
    if !accepts(path, key, &limits)? {
        return Err(catalog_error());
    }
    while lo.saturating_add(1) < hi {
        let mid = lo + (hi - lo) / 2;
        set(&mut limits, mid);
        if accepts(path, key, &limits)? {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    Ok(hi)
}

fn accepts(path: &Path, key: &AccountDbKey, limits: &EngineLimits) -> Result<bool, StorageError> {
    let budget = open_verified::Budget::new();
    budget.reset(50_000_000, Duration::from_secs(60));
    let db = match open_verified::harden(path, limits, &budget) {
        Ok(db) => db,
        Err(StorageError::TransferExportRefused(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    let pragma = Zeroizing::new(format!("PRAGMA key=\"x'{}'\";", key.sqlcipher_hex()));
    if db.execute_batch(&pragma).is_err() {
        return Ok(false);
    }
    if db.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get::<_, i64>(0)).is_err() {
        return Ok(false);
    }
    match open_verified::quick_check(&db) {
        Ok(()) => Ok(true),
        Err(StorageError::TransferExportRefused(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn widen(raw: &RawLimits) -> EngineLimits {
    EngineLimits {
        length: raw.length.saturating_add(TEXT_HEADROOM),
        sql_length: raw.sql_length.saturating_add(TEXT_HEADROOM),
        column: raw.columns.saturating_add(COLUMN_HEADROOM),
        expr_depth: raw.expr_depth.saturating_add(DEPTH_HEADROOM),
        compound_select: raw.compound_select.saturating_add(COMPOUND_HEADROOM),
        vdbe_op: vdbe_limit(raw.vdbe_op),
        function_arg: raw.function_arg.saturating_add(ARG_HEADROOM),
        like_pattern: if raw.like_pattern == 0 {
            0
        } else {
            raw.like_pattern.saturating_add(LIKE_HEADROOM)
        },
        variable_number: raw.variable_number,
        parser_depth: raw.parser_depth.saturating_add(DEPTH_HEADROOM),
        schema: raw.schema.saturating_add(SCHEMA_HEADROOM),
        attached: raw.attached,
        trigger_depth: raw.trigger_depth,
        worker_threads: raw.worker_threads,
        trigger_steps: raw.trigger_steps.saturating_add(STEP_HEADROOM),
    }
}

fn vdbe_limit(minimum: i32) -> i32 {
    let quarter = minimum / 4;
    let grown = minimum.saturating_add(quarter);
    let at_least = minimum.saturating_add(64);
    if grown > at_least { grown } else { at_least }
}

fn text_bounds(db: &Connection) -> Result<(i32, i32), StorageError> {
    let length: i64 =
        db.query_row("SELECT COALESCE(MAX(length(sql)),0) FROM sqlite_schema", [], |row| {
            row.get(0)
        })?;
    let mut tables = db.prepare("SELECT name FROM sqlite_schema WHERE type='table'")?;
    let names = tables.query_map([], |row| row.get::<_, String>(0))?;
    let names = names.collect::<Result<Vec<_>, _>>()?;
    let mut columns = 0_i64;
    for name in names {
        let count: i64 =
            db.query_row("SELECT count(*) FROM pragma_table_info(?1)", [name], |row| row.get(0))?;
        if count > columns {
            columns = count;
        }
    }
    Ok((fit(length)?, fit(columns)?))
}

fn object_names(db: &Connection) -> Result<BTreeSet<String>, StorageError> {
    let mut statement = db.prepare("SELECT name FROM sqlite_schema")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<_, _>>().map_err(StorageError::from)
}

fn open_plain(path: &Path, key: &AccountDbKey) -> Result<Connection, StorageError> {
    let db = Connection::open(path)?;
    let pragma = Zeroizing::new(format!("PRAGMA key=\"x'{}'\";", key.sqlcipher_hex()));
    db.execute_batch(&pragma)?;
    Ok(db)
}

fn wide_limits() -> EngineLimits {
    EngineLimits {
        length: TRIAL_HIGH,
        sql_length: TRIAL_HIGH,
        column: TRIAL_HIGH,
        expr_depth: TRIAL_HIGH,
        compound_select: TRIAL_HIGH,
        vdbe_op: TRIAL_HIGH,
        function_arg: TRIAL_HIGH,
        like_pattern: TRIAL_HIGH,
        variable_number: TRIAL_HIGH,
        parser_depth: TRIAL_HIGH,
        schema: TRIAL_HIGH,
        attached: TRIAL_HIGH,
        trigger_depth: TRIAL_HIGH,
        worker_threads: TRIAL_HIGH,
        trigger_steps: TRIAL_HIGH,
    }
}

fn catalog_dir() -> Result<CatalogDir, StorageError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let path =
        std::env::temp_dir().join(format!("ramflux-schema-budget-{nanos}-{}", std::process::id()));
    std::fs::create_dir_all(&path).map_err(|_| catalog_error())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| catalog_error())?;
    }
    Ok(CatalogDir { path })
}

impl Drop for CatalogDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn known_kind(kind: &str) -> bool {
    matches!(kind, "table" | "index" | "trigger" | "view")
}

fn sqlite_owned(name: &str) -> bool {
    matches!(
        name,
        "sqlite_sequence" | "sqlite_stat1" | "sqlite_stat4" | "sqlite_schema" | "sqlite_master"
    )
}

fn fit(value: i64) -> Result<i32, StorageError> {
    i32::try_from(value).map_err(|_| catalog_error())
}

fn catalog_error() -> StorageError {
    StorageError::Integrity("account schema budget")
}
