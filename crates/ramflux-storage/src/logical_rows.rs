// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only logical rows of the client tables a typing indicator must not enter.
//! The account writer lock stays with the daemon. This opens the index and the
//! account database query-only.

use crate::database::Connection;
use crate::encryption::{AccountDbKey, FileVaultSecretSource, WrappedAccountDbKey, apply_key};
use crate::{ACCOUNT_DB_FILE, ACCOUNT_INDEX_FILE, StorageError};
use rusqlite::{OpenFlags, params};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const ROW_CAP: usize = 10_000;

/// Reads the existing 32-byte file-vault secret. Does not create one.
///
/// # Errors
/// Returns an error when the account id is not a single path component, or the
/// secret file is missing or not 32 bytes.
pub fn read_existing_vault_secret(
    root: &Path,
    local_account_id: &str,
) -> Result<[u8; 32], StorageError> {
    single_component(local_account_id)?;
    let path = FileVaultSecretSource::new(root).vault_secret_path(local_account_id);
    let bytes = std::fs::read(&path)?;
    bytes.as_slice().try_into().map_err(|_| StorageError::Integrity("vault secret is not 32 bytes"))
}

/// Loads the account database path and key without taking the writer lock.
///
/// # Errors
/// Returns an error when the index row, wrapped key, or database path is missing
/// or the path escapes the data root.
pub fn load_account_db_key(
    data_root: &Path,
    local_account_id: &str,
    key_encryption_key: &[u8; 32],
) -> Result<(PathBuf, AccountDbKey), StorageError> {
    single_component(local_account_id)?;
    let index = Connection::open_with_flags(
        data_root.join(ACCOUNT_INDEX_FILE),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (relative, provider, wrapping_ref, wrapped, nonce) = index.query_row(
        "SELECT db_relative_path, key_wrapping_provider, key_wrapping_ref, wrapped_key, wrapped_key_nonce
           FROM local_account WHERE local_account_id = ?1",
        params![local_account_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
            ))
        },
    )?;
    let Some(wrapped_key) = wrapped else {
        return Err(StorageError::Integrity("account database key is not wrapped"));
    };
    let Some(nonce) = nonce else {
        return Err(StorageError::Integrity("account database key nonce is missing"));
    };
    let nonce: [u8; 12] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| StorageError::Integrity("wrapped account key nonce is not 12 bytes"))?;
    let key = crate::unwrap_with_vault_secret(
        key_encryption_key,
        &WrappedAccountDbKey {
            key_wrapping_provider: provider,
            key_wrapping_ref: wrapping_ref,
            nonce,
            wrapped_key,
        },
    )?;
    let path = rooted_database(data_root, &relative)?;
    if path.file_name().and_then(|name| name.to_str()) != Some(ACCOUNT_DB_FILE) {
        return Err(StorageError::Integrity(
            "account database file name is not ramflux_local.sqlite",
        ));
    }
    Ok((path, key))
}

/// Logical rows of the message, event, outbox, receipt and actor-state tables.
/// Includes committed WAL frames. Does not take the writer lock.
///
/// # Errors
/// Returns an error when the database cannot be opened or a present table cannot
/// be read within the row cap.
pub fn logical_table_rows(
    db_path: &Path,
    key: &AccountDbKey,
) -> Result<BTreeMap<String, Vec<String>>, StorageError> {
    let connection = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    apply_key(&connection, key)?;
    connection.execute_batch("PRAGMA query_only=ON;")?;
    let mut tables = BTreeMap::new();
    for (name, sql) in TABLES {
        tables.insert((*name).to_owned(), table_lines(&connection, name, sql)?);
    }
    Ok(tables)
}

const TABLES: &[(&str, &str)] = &[
    (
        "message_projection",
        "SELECT message_id || char(9) || conversation_id || char(9) || event_id || char(9) || CAST(edit_counter AS TEXT) || char(9) || CAST(IFNULL(deleted_at, 0) AS TEXT) || char(9) || hex(body_cipher) FROM message_projection ORDER BY message_id LIMIT 10001",
    ),
    (
        "direct_message_projection",
        "SELECT message_id || char(9) || conversation_id || char(9) || CAST(deleted AS TEXT) || char(9) || hex(encrypted_body) || char(9) || hex(metadata_json) FROM direct_message_projection ORDER BY message_id LIMIT 10001",
    ),
    (
        "local_event_log",
        "SELECT event_id || char(9) || event_type || char(9) || signature_status || char(9) || projection_status || char(9) || hex(event_body) FROM local_event_log ORDER BY event_id LIMIT 10001",
    ),
    (
        "outbox_queue",
        "SELECT outbox_id || char(9) || envelope_id || char(9) || delivery_class || char(9) || state || char(9) || hex(encrypted_envelope) FROM outbox_queue ORDER BY outbox_id LIMIT 10001",
    ),
    (
        "receipt_projection",
        "SELECT receipt_id || char(9) || conversation_id || char(9) || IFNULL(message_id, '') || char(9) || receipt_type || char(9) || actor_device_id FROM receipt_projection ORDER BY receipt_id LIMIT 10001",
    ),
    (
        "runtime_outbox",
        "SELECT table_name || char(9) || change_kind || char(9) || IFNULL(actor_state_kind, '') || char(9) || REPLACE(IFNULL(keys_json, ''), char(9), ' ') FROM runtime_outbox ORDER BY sequence LIMIT 10001",
    ),
    (
        "runtime_actor_state",
        "SELECT state_kind || char(9) || hex(state_json) FROM runtime_actor_state ORDER BY state_kind LIMIT 10001",
    ),
];

fn table_lines(
    connection: &Connection,
    table: &str,
    sql: &str,
) -> Result<Vec<String>, StorageError> {
    let present: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![table],
        |row| row.get(0),
    )?;
    if present == 0 {
        return Ok(Vec::new());
    }
    let rows = connection.rows(sql, params![])?;
    if rows.len() > ROW_CAP {
        return Err(StorageError::Integrity("logical table snapshot exceeded 10000 rows"));
    }
    let mut lines = Vec::with_capacity(rows.len());
    for row in &rows {
        lines.push(row.get(0)?);
    }
    Ok(lines)
}

fn single_component(local_account_id: &str) -> Result<(), StorageError> {
    if local_account_id.is_empty()
        || local_account_id.contains('/')
        || local_account_id.contains('\\')
        || local_account_id == "."
        || local_account_id == ".."
    {
        return Err(StorageError::Integrity("local account id is not a single path component"));
    }
    Ok(())
}

fn rooted_database(root: &Path, relative: &str) -> Result<PathBuf, StorageError> {
    let relative_path = Path::new(relative);
    if relative.is_empty()
        || relative_path.is_absolute()
        || relative_path.components().any(|component| {
            matches!(component, std::path::Component::ParentDir | std::path::Component::RootDir)
        })
    {
        return Err(StorageError::Integrity("account database path escapes the data root"));
    }
    let root = root.canonicalize()?;
    let file = root.join(relative_path).canonicalize()?;
    if !file.starts_with(&root) {
        return Err(StorageError::Integrity("account database path escapes the data root"));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::read_existing_vault_secret;

    #[test]
    fn missing_vault_secret_is_not_created() {
        let root = tempfile::tempdir().expect("temp dir");
        let error = read_existing_vault_secret(root.path(), "acct").expect_err("missing secret");
        assert!(
            !root.path().join("vault").join("acct.key").exists(),
            "test: reading a vault secret must not create one: {error}"
        );
        assert!(
            read_existing_vault_secret(root.path(), "../acct").is_err(),
            "test: an account id must be one path component"
        );
    }
}
