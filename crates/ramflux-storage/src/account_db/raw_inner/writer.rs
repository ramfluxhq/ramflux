// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Caller-transaction raw-copy writer and bounded handle reader.

use super::quota;
use crate::{StorageError, account_db::AccountDb};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

pub const MAX_INNER_BYTES: usize = 524_252;
pub const MAX_HISTORY_CONTAINER_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawInnerCopyKind {
    OuterInner,
    NestedGroup,
    HistoryContainer,
}

impl RawInnerCopyKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::OuterInner => "outer_inner",
            Self::NestedGroup => "nested_group",
            Self::HistoryContainer => "history_container",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawInnerCopy {
    pub copy_id: String,
    pub owner_id: String,
    pub kind: RawInnerCopyKind,
    pub digest: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct RawInnerCopyWrite<'a> {
    pub owner_id: &'a str,
    pub verified_source_anchor: &'a str,
    pub copy_id: &'a str,
    pub kind: RawInnerCopyKind,
    pub bytes: &'a [u8],
    pub bounded_metadata: &'a [u8],
}

pub(super) fn validate_id(value: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(())
}

pub(super) fn put(db: &Connection, write: RawInnerCopyWrite<'_>) -> Result<(), StorageError> {
    let RawInnerCopyWrite {
        owner_id,
        verified_source_anchor: source_anchor,
        copy_id,
        kind,
        bytes,
        bounded_metadata: metadata,
    } = write;
    if db.is_autocommit() {
        return Err(StorageError::AuthorizationRejected);
    }
    validate_id(owner_id)?;
    validate_id(source_anchor)?;
    validate_id(copy_id)?;
    let max_bytes = match kind {
        RawInnerCopyKind::HistoryContainer => MAX_HISTORY_CONTAINER_BYTES,
        RawInnerCopyKind::OuterInner | RawInnerCopyKind::NestedGroup => MAX_INNER_BYTES,
    };
    if bytes.is_empty() || bytes.len() > max_bytes || metadata.len() > 4096 {
        return Err(StorageError::AuthorizationRejected);
    }
    if message_deleted(db, owner_id)? || raw_copy_deleted(db, copy_id)? {
        return Err(StorageError::AuthorizationRejected);
    }
    let recorded_source: Option<String> = db
        .query_row(
            "SELECT source_anchor FROM raw_inner_owner WHERE owner_id=?1",
            [owner_id],
            |row| row.get(0),
        )
        .optional()?;
    if recorded_source.as_deref().is_some_and(|anchor| anchor != source_anchor) {
        return Err(StorageError::AuthorizationRejected);
    }
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let existing: Option<(String, String, Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT owner_id,copy_kind,raw_digest,raw_bytes FROM raw_inner_copy WHERE copy_id=?1",
            [copy_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if let Some((existing_owner, existing_kind, existing_digest, existing_bytes)) = existing {
        if existing_owner == owner_id
            && existing_kind == kind.as_sql()
            && existing_digest == digest
            && existing_bytes == bytes
        {
            let registered: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM message_footprint WHERE kind='raw_inner' AND locator=?1)",
                [copy_id],
                |row| row.get(0),
            )?;
            if !registered {
                db.execute(
                    "INSERT OR IGNORE INTO message_copy_binding(copy_id,message_id) VALUES(?1,?2)",
                    params![format!("raw:{copy_id}"), owner_id],
                )?;
                db.execute(
                    "INSERT OR IGNORE INTO message_footprint(message_id,kind,locator) VALUES(?1,'raw_inner',?2)",
                    params![owner_id, copy_id],
                )?;
            }
            return Ok(());
        }
        return Err(StorageError::AuthorizationRejected);
    }
    quota::reserve(db, owner_id, source_anchor, bytes.len() as u64)?;
    db.execute(
        "INSERT INTO raw_inner_owner(owner_id,source_anchor,metadata) VALUES(?1,?2,?3)
         ON CONFLICT(owner_id) DO NOTHING",
        params![owner_id, source_anchor, metadata],
    )?;
    db.execute(
        "INSERT INTO raw_inner_copy(copy_id,owner_id,copy_kind,raw_digest,raw_bytes)
         VALUES(?1,?2,?3,?4,?5)",
        params![copy_id, owner_id, kind.as_sql(), digest.as_slice(), bytes],
    )?;
    db.execute(
        "INSERT OR IGNORE INTO message_copy_binding(copy_id,message_id) VALUES(?1,?2)",
        params![format!("raw:{copy_id}"), owner_id],
    )?;
    db.execute(
        "INSERT OR IGNORE INTO message_footprint(message_id,kind,locator) VALUES(?1,'raw_inner',?2)",
        params![owner_id, copy_id],
    )?;
    #[cfg(test)]
    if fail_for_owner(owner_id) {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(())
}

pub(super) fn bind(db: &Connection, copy_id: &str, message_id: &str) -> Result<(), StorageError> {
    if db.is_autocommit() {
        return Err(StorageError::AuthorizationRejected);
    }
    validate_id(copy_id)?;
    validate_id(message_id)?;
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM raw_inner_copy WHERE copy_id=?1)",
        [copy_id],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(StorageError::AuthorizationRejected);
    }
    if message_deleted(db, message_id)? {
        return Err(StorageError::AuthorizationRejected);
    }
    let binding_id = format!("raw:{copy_id}");
    db.execute(
        "INSERT OR IGNORE INTO message_copy_binding(copy_id,message_id) VALUES(?1,?2)",
        params![binding_id, message_id],
    )?;
    db.execute(
        "INSERT OR IGNORE INTO message_footprint(message_id,kind,locator) VALUES(?1,'raw_inner',?2)",
        params![message_id, copy_id],
    )?;
    db.execute(
        "DELETE FROM message_footprint WHERE kind='raw_inner' AND locator=?1 AND message_id<>?2",
        params![copy_id, message_id],
    )?;
    db.execute(
        "DELETE FROM message_copy_binding WHERE copy_id=?1 AND message_id<>?2",
        params![binding_id, message_id],
    )?;
    Ok(())
}

pub(crate) fn message_deleted(db: &Connection, message_id: &str) -> Result<bool, StorageError> {
    super::super::deleted_messages::message_is_deleted_on(db, message_id)
}

pub(crate) fn raw_copy_deleted(db: &Connection, copy_id: &str) -> Result<bool, StorageError> {
    for mac in super::super::mac_subkeys::all_macs(
        db,
        super::super::mac_subkeys::RAW_COPY_MARKER_LABEL,
        copy_id.as_bytes(),
    )? {
        let found: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=?1)",
            [format!("message/deleted-raw-copy/{mac}")],
            |row| row.get(0),
        )?;
        if found {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
static FAIL_AFTER_OWNER: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) fn fail_after_last_write_once() {
    if let Ok(mut owner) = FAIL_AFTER_OWNER.lock() {
        *owner = Some("fault-owner".to_owned());
    }
}

#[cfg(test)]
fn fail_for_owner(owner_id: &str) -> bool {
    let Ok(mut configured) = FAIL_AFTER_OWNER.lock() else { return false };
    if configured.as_deref() != Some(owner_id) {
        return false;
    }
    *configured = None;
    true
}

impl AccountDb {
    /// Writes one exact Unsupported raw copy and its quota/erasure linkage.
    /// The caller must wrap this call in `write_transaction`; it never starts a transaction.
    ///
    /// # Errors
    /// Rejects invalid identifiers, copy conflicts, missing caller transactions, quota exhaustion,
    /// and SQL failures.
    pub fn put_unsupported_raw_copy(
        &self,
        write: RawInnerCopyWrite<'_>,
    ) -> Result<(), StorageError> {
        let owner_id = write.owner_id.to_owned();
        let source = write.verified_source_anchor.to_owned();
        let copy_id = write.copy_id.to_owned();
        let bytes = write.bytes.to_vec();
        let metadata = write.bounded_metadata.to_vec();
        let kind = write.kind;
        self.connection
            .call(move |db| {
                Ok(put(
                    db,
                    RawInnerCopyWrite {
                        owner_id: &owner_id,
                        verified_source_anchor: &source,
                        copy_id: &copy_id,
                        kind,
                        bytes: &bytes,
                        bounded_metadata: &metadata,
                    },
                ))
            })
            .map_err(StorageError::from)?
    }

    /// Reads exact raw bytes by an opaque bounded copy handle.
    ///
    /// # Errors
    /// Returns SQL errors or rejects invalid handles.
    pub fn raw_inner_copy(&self, copy_id: &str) -> Result<Option<RawInnerCopy>, StorageError> {
        validate_id(copy_id)?;
        let copy_id = copy_id.to_owned();
        self.connection.call(move |db| {
            db.query_row(
                "SELECT copy_id,owner_id,copy_kind,raw_digest,raw_bytes FROM raw_inner_copy WHERE copy_id=?1",
                [copy_id],
                |row| {
                    let kind: String = row.get(2)?;
                    let digest: Vec<u8> = row.get(3)?;
                    let digest: [u8; 32] = digest.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
                    let kind = match kind.as_str() {
                        "outer_inner" => RawInnerCopyKind::OuterInner,
                        "nested_group" => RawInnerCopyKind::NestedGroup,
                        "history_container" => RawInnerCopyKind::HistoryContainer,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    Ok(RawInnerCopy { copy_id: row.get(0)?, owner_id: row.get(1)?, kind, digest, bytes: row.get(4)? })
                },
            ).optional()
        }).map_err(StorageError::from)
    }

    /// Moves a provisional copy locator to its authenticated replay target atomically.
    /// The caller must include this call in the same transaction as the replay binding.
    ///
    /// # Errors
    /// Rejects unknown handles, invalid IDs, missing caller transactions, and SQL failures.
    pub fn bind_raw_inner_copy(
        &self,
        copy_id: &str,
        authenticated_message_id: &str,
    ) -> Result<(), StorageError> {
        let copy = copy_id.to_owned();
        let message = authenticated_message_id.to_owned();
        self.connection.call(move |db| Ok(bind(db, &copy, &message))).map_err(StorageError::from)?
    }
}
