// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Hard per-account and verified-source raw retention ceilings.

use crate::StorageError;
use rusqlite::{Connection, OptionalExtension, params};

pub const ACCOUNT_OWNER_LIMIT: u64 = 64;
pub const ACCOUNT_RAW_BYTE_LIMIT: u64 = 32 * 1024 * 1024;
pub const SOURCE_OWNER_LIMIT: u64 = 16;
pub const SOURCE_RAW_BYTE_LIMIT: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawInnerQuotaScope {
    Account,
    Source,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawInnerQuota {
    pub owners: u64,
    pub raw_bytes: u64,
}

pub(super) fn reserve(
    db: &Connection,
    owner_id: &str,
    source_anchor: &str,
    additional_bytes: u64,
) -> Result<(), StorageError> {
    let existing: Option<String> = db
        .query_row(
            "SELECT source_anchor FROM raw_inner_owner WHERE owner_id=?1",
            [owner_id],
            |row| row.get(0),
        )
        .optional()?;
    if existing.as_deref().is_some_and(|anchor| anchor != source_anchor) {
        return Err(StorageError::AuthorizationRejected);
    }
    let is_new = existing.is_none();
    let account = measure(db, None)?;
    if exceeds(account, is_new, additional_bytes, ACCOUNT_OWNER_LIMIT, ACCOUNT_RAW_BYTE_LIMIT) {
        return Err(StorageError::UnsupportedRawQuotaExceeded {
            source_anchor: source_anchor.to_owned(),
            scope: RawInnerQuotaScope::Account,
        });
    }
    let source = measure(db, Some(source_anchor))?;
    if exceeds(source, is_new, additional_bytes, SOURCE_OWNER_LIMIT, SOURCE_RAW_BYTE_LIMIT) {
        return Err(StorageError::UnsupportedRawQuotaExceeded {
            source_anchor: source_anchor.to_owned(),
            scope: RawInnerQuotaScope::Source,
        });
    }
    Ok(())
}

fn exceeds(current: RawInnerQuota, new_owner: bool, added: u64, owners: u64, bytes: u64) -> bool {
    current.owners.saturating_add(u64::from(new_owner)) > owners
        || current.raw_bytes.saturating_add(added) > bytes
}

fn measure(db: &Connection, source: Option<&str>) -> Result<RawInnerQuota, StorageError> {
    let (owners, raw_bytes): (i64, i64) = if let Some(source) = source {
        db.query_row(
            "SELECT count(DISTINCT o.owner_id),coalesce(sum(length(c.raw_bytes)),0)
             FROM raw_inner_owner o LEFT JOIN raw_inner_copy c USING(owner_id)
             WHERE o.source_anchor=?1",
            params![source],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?
    } else {
        db.query_row(
            "SELECT count(DISTINCT o.owner_id),coalesce(sum(length(c.raw_bytes)),0)
             FROM raw_inner_owner o LEFT JOIN raw_inner_copy c USING(owner_id)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?
    };
    Ok(RawInnerQuota {
        owners: u64::try_from(owners).map_err(|_| StorageError::AuthorizationRejected)?,
        raw_bytes: u64::try_from(raw_bytes).map_err(|_| StorageError::AuthorizationRejected)?,
    })
}

pub(in crate::account_db) fn validate_all(db: &Connection) -> Result<(), StorageError> {
    let account = measure(db, None)?;
    if exceeds(account, false, 0, ACCOUNT_OWNER_LIMIT, ACCOUNT_RAW_BYTE_LIMIT) {
        let source: String = db.query_row(
            "SELECT source_anchor FROM raw_inner_owner ORDER BY source_anchor LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        return Err(StorageError::UnsupportedRawQuotaExceeded {
            source_anchor: source,
            scope: RawInnerQuotaScope::Account,
        });
    }
    let mut sources = db.prepare(
        "SELECT source_anchor FROM raw_inner_owner GROUP BY source_anchor ORDER BY source_anchor",
    )?;
    let anchors = sources
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for anchor in anchors {
        let source = measure(db, Some(&anchor))?;
        if exceeds(source, false, 0, SOURCE_OWNER_LIMIT, SOURCE_RAW_BYTE_LIMIT) {
            return Err(StorageError::UnsupportedRawQuotaExceeded {
                source_anchor: anchor,
                scope: RawInnerQuotaScope::Source,
            });
        }
    }
    Ok(())
}

impl super::super::AccountDb {
    /// Returns current retained Unsupported-owner and exact-copy byte usage.
    ///
    /// # Errors
    /// Returns a storage error if the quota index cannot be read.
    pub fn unsupported_raw_quota(
        &self,
        source_anchor: Option<&str>,
    ) -> Result<RawInnerQuota, StorageError> {
        let source_anchor = source_anchor.map(str::to_owned);
        self.connection
            .call(move |db| Ok(measure(db, source_anchor.as_deref())))
            .map_err(StorageError::from)?
    }
}
