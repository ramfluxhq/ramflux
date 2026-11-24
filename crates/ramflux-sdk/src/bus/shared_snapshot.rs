// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Committed account snapshot for a second process, and one fenced direct-message commit.
//!
//! The snapshot takes neither the daemon lease nor the account writer lock. The commit
//! takes the account writer lock and returns [`SdkError`] `account_busy` when another
//! process already holds it, before any SQL write.

use crate::SdkError;
use crate::client::account::account_db_key_encryption_key;
use ramflux_storage::{
    AccountDb, AccountIndex, DirectMessageWrite, MessageMetadata, StorageError,
    load_account_db_key, logical_table_rows, read_existing_vault_secret,
};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Message ids from one committed snapshot. Bodies stay in the database.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[must_use]
pub struct CommittedSnapshot {
    /// Account whose database was read.
    pub account_id: String,
    /// `direct_message_projection.message_id`, ordered by id.
    pub direct_message_ids: Vec<String>,
    /// `message_projection.message_id`, ordered by id.
    pub message_ids: Vec<String>,
}

/// Fields of one direct-message projection row. The body is the caller-supplied bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectMessageCommit<'a> {
    /// Conversation the row belongs to.
    pub conversation_id: &'a str,
    /// Primary key. A second commit of the same id and body stays one row.
    pub message_id: &'a str,
    /// Sender stored on the row.
    pub sender_id: &'a str,
}

/// Reads one committed snapshot. Does not create the root and does not take a writer lease.
///
/// # Errors
/// Returns an error when the root is not a private absolute directory, the account
/// code cannot unwrap the database key, or the snapshot cannot be read.
#[must_use = "the snapshot is the only view of committed message ids"]
pub fn read_committed_snapshot(
    data_root: &Path,
    account_id: &str,
    account_code: &[u8],
) -> Result<CommittedSnapshot, SdkError> {
    let root = require_private_root(data_root)?;
    require_component("account id", account_id)?;
    require_code(account_code)?;
    let key = unwrap_account_key(&root, account_id, account_code)?;
    let tables = logical_table_rows(&key.0, &key.1)?;
    Ok(CommittedSnapshot {
        account_id: account_id.to_owned(),
        direct_message_ids: message_ids(tables.get("direct_message_projection").map(Vec::as_slice)),
        message_ids: message_ids(tables.get("message_projection").map(Vec::as_slice)),
    })
}

/// Inserts one direct-message projection in the existing immediate write transaction.
///
/// A process that already holds the account writer lock is refused before SQL. The same
/// id and body commit once. This does not send a wire acknowledgement.
///
/// # Errors
/// Returns [`SdkError::Storage`] wrapping [`StorageError::AccountWriterBusy`] when another
/// process holds the writer lock, or a storage error when the commit fails.
#[must_use = "a busy writer is a typed error and must not be ignored"]
pub fn commit_direct_message(
    data_root: &Path,
    account_id: &str,
    account_code: &[u8],
    message: DirectMessageCommit<'_>,
) -> Result<(), SdkError> {
    let root = require_private_root(data_root)?;
    require_component("account id", account_id)?;
    require_component("conversation id", message.conversation_id)?;
    require_component("message id", message.message_id)?;
    require_component("sender id", message.sender_id)?;
    require_code(account_code)?;
    let key = unwrap_account_key(&root, account_id, account_code)?;
    let index = AccountIndex::open(&root)?;
    let database = AccountDb::open(&index, account_id, &key.1)?;
    let metadata = MessageMetadata::default();
    let body = message.message_id.as_bytes();
    database.write_transaction(|| {
        database.import_direct_message_projection(DirectMessageWrite {
            conversation_id: message.conversation_id,
            message_id: message.message_id,
            sender_id: message.sender_id,
            encrypted_body: body,
            metadata: &metadata,
            created_at: unix_now()?,
        })
    })?;
    Ok(())
}

/// Stable refusal token for the shared-root reader and writer, when one applies.
#[must_use]
pub fn shared_root_refusal(error: &SdkError) -> Option<&'static str> {
    match error {
        SdkError::DataRootInUse => Some("DataRootInUse"),
        SdkError::Storage(error) if error.is_writer_busy() => Some("account_busy"),
        SdkError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Some("permission_denied")
        }
        SdkError::Io(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            Some("invalid_argument")
        }
        _ => None,
    }
}

fn unwrap_account_key(
    root: &Path,
    account_id: &str,
    account_code: &[u8],
) -> Result<(PathBuf, ramflux_storage::AccountDbKey), SdkError> {
    let secret = Zeroizing::new(read_existing_vault_secret(root, account_id)?);
    let kek = Zeroizing::new(account_db_key_encryption_key(&secret, account_code)?);
    Ok(load_account_db_key(root, account_id, &kek)?)
}

fn message_ids(rows: Option<&[String]>) -> Vec<String> {
    rows.into_iter()
        .flatten()
        .filter_map(|line| line.split('\t').next().filter(|id| !id.is_empty()))
        .map(str::to_owned)
        .collect()
}

fn require_code(account_code: &[u8]) -> Result<(), SdkError> {
    if account_code.is_empty() || account_code.len() > 1024 {
        return Err(invalid_input("account code length"));
    }
    Ok(())
}

fn require_component(label: &str, value: &str) -> Result<(), SdkError> {
    if value.is_empty()
        || value.len() > 256
        || value.contains(['/', '\\', '\t', '\n', '\r', '\0'])
        || value == "."
        || value == ".."
    {
        return Err(invalid_input(format!("{label} is not a single path component")));
    }
    Ok(())
}

fn require_private_root(root: &Path) -> Result<PathBuf, SdkError> {
    if !root.is_absolute() {
        return Err(invalid_input("data root must be absolute"));
    }
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_input("data root must be an existing directory"));
    }
    let canonical = std::fs::canonicalize(root)?;
    #[cfg(unix)]
    private_unix_root(&canonical)?;
    Ok(canonical)
}

#[cfg(unix)]
fn private_unix_root(root: &Path) -> Result<(), SdkError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(root)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700 {
        return Err(SdkError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "data root must be private to its owner",
        )));
    }
    Ok(())
}

fn invalid_input(message: impl Into<String>) -> SdkError {
    SdkError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into()))
}

fn unix_now() -> Result<i64, StorageError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StorageError::Integrity("system clock is before the unix epoch"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| StorageError::Integrity("system clock exceeds i64"))
}
