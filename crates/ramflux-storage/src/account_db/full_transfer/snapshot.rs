// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary-transfer sanitizer: a closed allowlist over table names, actor namespaces and
//! event types decides what of A's database may reach B. Device secrets, receive ratchets
//! and device authority never leave A; an unclassified non-empty category refuses.
use crate::{AccountDbKey, BackupDatabase, StorageError};
use rusqlite::{Connection, params};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

mod tables;
use tables::KNOWN_TABLES;

/// Domain tag that starts every snapshot family stream.
pub(super) const FRAME_TAG: &[u8; 28] = b"ramflux.transfer.snapshot.v1";
/// Tag, 32-byte snapshot database key and big-endian u64 file length.
pub(super) const FRAME_HEADER: u64 = 28 + 32 + 8;
const MAX_NEEDLES: usize = 65_536;
const MIN_NEEDLE: usize = 16;
const COPY_BLOCK: usize = 65_536;

/// Event bodies that hold device private keys or ratchet state.
const SECRET_EVENTS: &[&str] = &["x3dh.prekey.private", "dm.ratchet_session", "group.sender_key.state"];
/// Event type prefixes that are inert account history.
const CARRY_EVENTS: &[&str] = &[
    "message.", "call.", "friend.", "object.", "group.", "gateway.", "identity.", "bot.",
    "contact.", "native.",
];
/// Actor namespaces that are device-local, credentials, secrets or live authority.
const STRIP_ACTORS: &[&str] = &[
    "dm-pair/",
    "group-state/send/",
    "secrets/",
    "identity/owned_",
    "identity/custody/",
    "identity/contact_safety_confirmation/",
    "identity/contact_safety_origin_inner/",
    "account/",
    "gateway/",
    "sync/",
    "own-device/",
    "own-copy/",
    "own-history/",
    "history-out/",
    "self-sync/pending/",
    "self-sync/repair/",
    "self-sync/repair-sent/",
    "backup/",
    "pairing/",
    "recovery/",
    "restore/",
    "lease/",
    "queue/",
    "retry/",
    "source-hold/",
    "group-transfer/",
    "group-courier/",
    "raw-capacity/",
    "message-identity/",
    "pending/",
    "inbox/",
];
/// Actor namespaces that are account data or public evidence the merge may use.
const CARRY_ACTORS: &[&str] = &[
    "routed/",
    "attachment/",
    "task/",
    "surface/",
    "receipt/",
    "delivery-receipt/",
    "message/",
    "message-send/",
    "message-delete-fence/",
    "directory/",
    "contact/",
    "contact-request/",
    "contact-admission/",
    "conversation-send/",
    "conversation-intent/",
    "conversation-operation/",
    "conversation-edit-reservation/",
    "group-state/",
    "group-message/",
    "group-beacon/",
    "own-contact/",
    "own-group/",
    "safety/",
    "settings/",
    "voice/",
    "call/",
    "draft/",
    "history/",
    "a2i/",
    "mcp/",
    "self-sync/",
    "erase/",
    "legacy/",
    "identity/",
];
/// Device authority, evidence and grants that confer authority: never carried.
const STRIP_TABLES: &[&str] = &[
    "device_identity",
    "lineage_checkpoint",
    "home_node_binding",
    "session_capability_cache",
    "device_directory",
    "identity_lifecycle_projection",
    "contact_verification_projection",
    "mcp_grant",
    "mcp_standing_approval",
    "bot_trust_pin",
    "bot_install_grant",
    "guardian_recovery_share_projection",
    "pending_recovery_projection",
    "pending_recovery_approval_projection",
];

fn refused(kind: &'static str, name: &str) -> StorageError {
    // Category names only; never a value, key or identifier suffix.
    let shown: String = name.chars().take(64).collect();
    tracing::warn!(kind, category = %shown, "transfer sanitizer refused an unclassified category");
    StorageError::PairingField("UnsupportedRecord")
}
fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
fn namespace(kind: &str) -> &str {
    let mut ends = kind.match_indices('/').map(|(index, _)| index);
    match (ends.next(), ends.next()) {
        (Some(_), Some(second)) => kind.get(..=second).unwrap_or(kind),
        (Some(first), None) => kind.get(..=first).unwrap_or(kind),
        _ => kind,
    }
}
fn actor_stripped(kind: &str) -> bool {
    STRIP_ACTORS.iter().any(|prefix| kind.starts_with(prefix))
}
fn actor_known(kind: &str) -> bool {
    actor_stripped(kind) || CARRY_ACTORS.iter().any(|prefix| kind.starts_with(prefix))
}
fn event_known(kind: &str) -> bool {
    SECRET_EVENTS.contains(&kind) || CARRY_EVENTS.iter().any(|prefix| kind.starts_with(prefix))
}
fn table_exists(db: &Connection, table: &str) -> Result<bool, StorageError> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        params![table],
        |row| row.get(0),
    )?)
}
fn table_names(db: &Connection) -> Result<Vec<String>, StorageError> {
    let mut statement = db.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let names = statement.query_map([], |row| row.get::<_, String>(0))?;
    Ok(names.collect::<rusqlite::Result<_>>()?)
}
fn nonempty(db: &Connection, table: &str) -> Result<bool, StorageError> {
    Ok(db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {})", quoted(table)), [], |row| {
        row.get(0)
    })?)
}
fn actor_filter(column: &str) -> String {
    STRIP_ACTORS
        .iter()
        .map(|prefix| format!("{column} LIKE '{}%'", prefix.replace('_', "\\_")))
        .map(|clause| format!("{clause} ESCAPE '\\'"))
        .collect::<Vec<_>>()
        .join(" OR ")
}
fn event_list() -> String {
    SECRET_EVENTS.iter().map(|kind| format!("'{kind}'")).collect::<Vec<_>>().join(",")
}

/// Classify every non-empty table, actor namespace and event type of a source database.
/// # Errors
/// Refuses `UnsupportedRecord` on the first unclassified non-empty category.
pub(super) fn preflight(db: &Connection) -> Result<(), StorageError> {
    for table in table_names(db)? {
        let known = KNOWN_TABLES.contains(&table.as_str())
            || crate::account_db::local_search::lifecycle::is_namespace(&table);
        if !known && nonempty(db, &table)? {
            return Err(refused("table", &table));
        }
    }
    if table_exists(db, "runtime_actor_state")? {
        let mut statement = db.prepare("SELECT state_kind FROM runtime_actor_state")?;
        let mut rows = statement.query([])?;
        let mut seen = BTreeSet::new();
        while let Some(row) = rows.next()? {
            let kind: String = row.get(0)?;
            if !actor_known(&kind) && seen.insert(namespace(&kind).to_owned()) {
                return Err(refused("actor", namespace(&kind)));
            }
        }
    }
    if table_exists(db, "local_event_log")? {
        let mut statement = db.prepare("SELECT DISTINCT event_type FROM local_event_log")?;
        let kinds = statement.query_map([], |row| row.get::<_, String>(0))?;
        for kind in kinds {
            let kind = kind?;
            if !event_known(&kind) {
                return Err(refused("event", &kind));
            }
        }
    }
    Ok(())
}

/// Refuse a snapshot that still holds any stripped category. Runs on A after sanitizing
/// and again on B before its merge, independently of A's sanitizer.
/// # Errors
/// Refuses `UnsupportedRecord` naming the category; never a value.
pub(super) fn structural_canary(db: &Connection) -> Result<(), StorageError> {
    preflight(db)?;
    let actors: bool = db.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE {})", actor_filter("state_kind")),
        [],
        |row| row.get(0),
    )?;
    if actors {
        return Err(refused("canary", "stripped actor namespace present"));
    }
    let events: bool = db.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM local_event_log WHERE event_type IN ({}))", event_list()),
        [],
        |row| row.get(0),
    )?;
    if events {
        return Err(refused("canary", "secret event type present"));
    }
    for table in STRIP_TABLES {
        if table_exists(db, table)? && nonempty(db, table)? {
            return Err(refused("canary", table));
        }
    }
    for table in ["backup_archived_actor_state", "backup_archived_local_event"] {
        if !table_exists(db, table)? {
            continue;
        }
        let present: bool = if table == "backup_archived_actor_state" {
            db.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {})", actor_filter("state_kind")),
                [],
                |row| row.get(0),
            )?
        } else {
            db.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE event_type IN ({}))", event_list()),
                [],
                |row| row.get(0),
            )?
        };
        if present {
            return Err(refused("canary", table));
        }
    }
    Ok(())
}

/// Secret values of A's cut, erased when dropped.
struct Needles(BTreeSet<Vec<u8>>);
impl Drop for Needles {
    fn drop(&mut self) {
        for mut needle in std::mem::take(&mut self.0) {
            zeroize::Zeroize::zeroize(&mut needle);
        }
    }
}
fn secret_name(key: &str) -> bool {
    ["seed", "secret", "private", "chain_key", "root_key", "message_key", "collapse_key"]
        .iter()
        .any(|part| key.contains(part))
}
fn push_needle(needles: &mut Needles, bytes: &[u8]) {
    let distinct = bytes.iter().collect::<BTreeSet<_>>().len();
    if bytes.len() >= MIN_NEEDLE && distinct >= 8 && needles.0.len() < MAX_NEEDLES {
        needles.0.insert(bytes.to_vec());
    }
}
fn walk(value: &serde_json::Value, secret: bool, needles: &mut Needles) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                walk(child, secret || secret_name(key), needles);
            }
        }
        serde_json::Value::Array(items) if secret => {
            let raw: Option<Vec<u8>> = items
                .iter()
                .map(|item| item.as_u64().and_then(|value| u8::try_from(value).ok()))
                .collect();
            match raw {
                Some(raw) if !raw.is_empty() => {
                    push_needle(needles, &raw);
                    if let Ok(text) = serde_json::to_vec(value) {
                        push_needle(needles, &text);
                    }
                }
                _ => items.iter().for_each(|item| walk(item, secret, needles)),
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| walk(item, false, needles)),
        serde_json::Value::String(text) if secret => push_needle(needles, text.as_bytes()),
        _ => {}
    }
}
/// Exact secret values of A's cut, kept in memory only for the self-scan.
fn collect_needles(db: &Connection) -> Result<Needles, StorageError> {
    let mut needles = Needles(BTreeSet::new());
    let mut bodies: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    {
        let sql = format!("SELECT event_body FROM local_event_log WHERE event_type IN ({})", event_list());
        let mut statement = db.prepare(&sql)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            bodies.push(Zeroizing::new(row.get::<_, Vec<u8>>(0)?));
        }
        let sql = format!("SELECT state_json FROM runtime_actor_state WHERE {}", actor_filter("state_kind"));
        let mut statement = db.prepare(&sql)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            bodies.push(Zeroizing::new(row.get::<_, Vec<u8>>(0)?));
        }
    }
    for body in &bodies {
        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(value) => walk(&value, false, &mut needles),
            Err(_) => push_needle(&mut needles, body),
        }
    }
    Ok(needles)
}
/// Search every column of every table for every needle; count hits, print no value.
fn self_scan(db: &Connection, needles: &Needles) -> Result<(), StorageError> {
    db.execute_batch("PRAGMA temp_store=MEMORY; CREATE TEMP TABLE transfer_needle(b BLOB NOT NULL);")?;
    for needle in &needles.0 {
        db.execute("INSERT INTO temp.transfer_needle(b) VALUES(?1)", params![needle.as_slice()])?;
    }
    let mut hits = 0_u64;
    let mut cells = 0_u64;
    for table in table_names(db)? {
        let mut statement = db.prepare(&format!("PRAGMA main.table_info({})", quoted(&table)))?;
        let columns: Vec<String> =
            statement.query_map([], |row| row.get(1))?.collect::<rusqlite::Result<_>>()?;
        for column in columns {
            let found: u64 = db.query_row(
                &format!(
                    "SELECT count(*) FROM main.{t} r, temp.transfer_needle n WHERE instr(CAST(r.{c} AS BLOB), n.b)>0",
                    t = quoted(&table),
                    c = quoted(&column)
                ),
                [],
                |row| row.get(0),
            )?;
            cells = cells.saturating_add(1);
            if found > 0 {
                tracing::warn!(table = %table, column = %column, found, "transfer self-scan found A secret material");
                hits = hits.saturating_add(found);
            }
        }
    }
    db.execute_batch("DROP TABLE temp.transfer_needle;")?;
    tracing::info!(needles = needles.0.len(), columns = cells, hits, "transfer sanitizer self-scan");
    if hits > 0 {
        return Err(StorageError::PairingField("UnsupportedRecord"));
    }
    Ok(())
}
fn strip(db: &Connection) -> Result<(), StorageError> {
    let actors = actor_filter("state_kind");
    let events = event_list();
    db.execute_batch("PRAGMA secure_delete=ON; BEGIN IMMEDIATE;")?;
    let result = (|| -> Result<(), StorageError> {
        db.execute_batch(&format!(
            "DELETE FROM projection_checkpoint WHERE projection_name LIKE 'x3dh\\_private:%' ESCAPE '\\' OR last_event_id IN (SELECT event_id FROM local_event_log WHERE event_type IN ({events}));
             DELETE FROM local_event_log WHERE event_type IN ({events});
             DELETE FROM runtime_actor_state WHERE {actors};"
        ))?;
        if table_exists(db, "backup_archived_actor_state")? {
            db.execute_batch(&format!("DELETE FROM backup_archived_actor_state WHERE {actors};"))?;
        }
        if table_exists(db, "backup_archived_local_event")? {
            db.execute_batch(&format!(
                "DELETE FROM backup_archived_local_event WHERE event_type IN ({events});"
            ))?;
        }
        for table in STRIP_TABLES {
            if table_exists(db, table)? {
                db.execute_batch(&format!("DELETE FROM {};", quoted(table)))?;
            }
        }
        db.execute_batch("COMMIT;")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = db.execute_batch("ROLLBACK");
    }
    result?;
    db.execute_batch("VACUUM;")?;
    Ok(())
}

/// Copy A's pinned private cut to `destination` under a fresh key and sanitize it there.
/// The input is read only. The returned key is the only way to open the result.
/// # Errors
/// Refuses unclassified categories, a self-scan hit, low space or any SQL/I/O failure;
/// the caller must remove `destination` on error.
pub(super) fn write_sanitized(
    input: &mut Connection,
    destination: &Path,
) -> Result<AccountDbKey, StorageError> {
    preflight(input)?;
    let needles = collect_needles(input)?;
    let parent = destination.parent().ok_or(StorageError::AuthorizationRejected)?;
    let estimate: u64 = input.query_row(
        "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()",
        [],
        |row| row.get(0),
    )?;
    crate::account_db::backup_database::require_space(parent, estimate.saturating_mul(2))?;
    let file = std::fs::OpenOptions::new().create_new(true).write(true).open(destination)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    drop(file);
    let key = AccountDbKey::generate()?;
    {
        let mut target = Connection::open(destination)?;
        let hex = Zeroizing::new(key.sqlcipher_hex());
        target.execute_batch(&Zeroizing::new(format!(
            "PRAGMA key=\"x'{}'\"; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA cache_size=-2048; PRAGMA secure_delete=ON;",
            hex.as_str()
        )))?;
        {
            let copy = rusqlite::backup::Backup::new(input, &mut target)?;
            loop {
                match copy.step(128)? {
                    rusqlite::backup::StepResult::Done => break,
                    rusqlite::backup::StepResult::More => {
                        crate::account_db::backup_database::require_space(parent, 2 * 1024 * 1024)?;
                    }
                    _ => return Err(StorageError::PairingField("Busy")),
                }
            }
        }
        target.execute(
            "UPDATE account_key_check SET key_fingerprint=?1 WHERE singleton_id=1",
            params![key.fingerprint()],
        )?;
        crate::account_db::backup::sanitize_backup_copy(&target)?;
    }
    let sanitized = BackupDatabase::open(destination, &key)?;
    sanitized.sanitize_native_backup()?;
    strip(&sanitized.db)?;
    structural_canary(&sanitized.db)?;
    self_scan(&sanitized.db, &needles)?;
    sanitized.check_integrity()?;
    drop(sanitized);
    crate::sync_path::sync_path(destination)?;
    Ok(key)
}

/// Stream the framed snapshot: tag, key, length, then the exact file bytes.
/// # Errors
/// Refuses a file whose length changed while streaming, and any I/O failure.
pub(super) fn write_frame(
    output: &mut impl Write,
    key: &AccountDbKey,
    path: &Path,
) -> Result<u64, StorageError> {
    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    output.write_all(FRAME_TAG)?;
    output.write_all(key.bytes())?;
    output.write_all(&length.to_be_bytes())?;
    let mut buffer = Zeroizing::new(vec![0_u8; COPY_BLOCK]);
    let mut copied = 0_u64;
    loop {
        let read = file.read(buffer.as_mut_slice())?;
        if read == 0 {
            break;
        }
        output.write_all(buffer.get(..read).ok_or(StorageError::AuthorizationRejected)?)?;
        copied = copied.saturating_add(read as u64);
    }
    if copied != length {
        return Err(StorageError::PairingField("SnapshotInvalidated"));
    }
    Ok(FRAME_HEADER.saturating_add(length))
}

/// Rebuild the snapshot file from an authenticated stream of exactly `total` bytes.
/// # Errors
/// Refuses a wrong tag, a length that disagrees with `total`, or I/O failure.
pub(super) fn reassemble(
    input: &mut impl Read,
    total: u64,
    destination: &Path,
) -> Result<AccountDbKey, StorageError> {
    let mismatch = || StorageError::PairingField("ManifestMismatch");
    let mut tag = [0_u8; 28];
    input.read_exact(&mut tag)?;
    if &tag != FRAME_TAG {
        return Err(mismatch());
    }
    let mut raw = Zeroizing::new([0_u8; 32]);
    input.read_exact(raw.as_mut_slice())?;
    let mut length = [0_u8; 8];
    input.read_exact(&mut length)?;
    let length = u64::from_be_bytes(length);
    if FRAME_HEADER.checked_add(length) != Some(total) {
        return Err(mismatch());
    }
    let mut file = std::fs::OpenOptions::new().create_new(true).write(true).open(destination)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let copied = std::io::copy(&mut input.take(length), &mut file)?;
    if copied != length {
        return Err(mismatch());
    }
    file.sync_all()?;
    Ok(AccountDbKey::from_bytes(*raw))
}

/// B's independent checks of a reassembled snapshot before any merge.
/// # Errors
/// Refuses integrity failure, a foreign key, or any stripped category.
pub(super) fn verify_incoming(path: &Path, key: &AccountDbKey) -> Result<(), StorageError> {
    let incoming = BackupDatabase::open(path, key)?;
    incoming.check_integrity()?;
    structural_canary(&incoming.db)
}

/// Deterministic digest of a generation's content, excluding this device's pairing and
/// key-check rows. Rows are hashed in full-column order, so equal content gives an
/// equal root regardless of physical page layout.
/// # Errors
/// Returns SQL errors.
pub(super) fn content_root(db: &Connection) -> Result<[u8; 32], StorageError> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"ramflux.transfer.snapshot.content.v1");
    for table in table_names(db)? {
        if table.starts_with("pairing_") || table == "account_key_check" {
            continue;
        }
        let mut info = db.prepare(&format!("PRAGMA main.table_info({})", quoted(&table)))?;
        let width = info.query_map([], |_| Ok(()))?.count();
        if width == 0 {
            continue;
        }
        hash.update(&u32::try_from(table.len()).map_err(|_| StorageError::AuthorizationRejected)?.to_be_bytes());
        hash.update(table.as_bytes());
        let order = (1..=width).map(|index| index.to_string()).collect::<Vec<_>>().join(",");
        let mut statement =
            db.prepare(&format!("SELECT * FROM main.{} ORDER BY {order}", quoted(&table)))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            for index in 0..width {
                match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => {
                        hash.update(&[0]);
                    }
                    rusqlite::types::ValueRef::Integer(value) => {
                        hash.update(&[1]);
                        hash.update(&value.to_be_bytes());
                    }
                    rusqlite::types::ValueRef::Real(value) => {
                        hash.update(&[2]);
                        hash.update(&value.to_bits().to_be_bytes());
                    }
                    rusqlite::types::ValueRef::Text(bytes) | rusqlite::types::ValueRef::Blob(bytes) => {
                        hash.update(&[3]);
                        hash.update(&(bytes.len() as u64).to_be_bytes());
                        hash.update(bytes);
                    }
                }
            }
        }
    }
    Ok(*hash.finalize().as_bytes())
}
