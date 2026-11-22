// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Hard per-account and verified-source raw retention ceilings.

use crate::StorageError;
use rusqlite::{Connection, OptionalExtension, params};

pub const ACCOUNT_OWNER_LIMIT: u64 = 64;
pub const ACCOUNT_RAW_BYTE_LIMIT: u64 = 32 * 1024 * 1024;
pub const SOURCE_OWNER_LIMIT: u64 = 16;
pub const SOURCE_RAW_BYTE_LIMIT: u64 = 8 * 1024 * 1024;
/// Own Message/Edit proofs. Separate from the 16-owner unsupported source cap.
pub const SUPPORTED_ACCOUNT_OWNER_LIMIT: u64 = 65_536;
pub const SUPPORTED_ACCOUNT_BYTE_LIMIT: u64 = 512 * 1024 * 1024;
pub const SUPPORTED_SOURCE_OWNER_LIMIT: u64 = 16_384;
pub const SUPPORTED_SOURCE_BYTE_LIMIT: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawInnerQuotaScope {
    Account,
    Source,
    /// Supported own-message attestation pool, not the Unsupported raw pool.
    SupportedAttestation,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawInnerQuota {
    pub owners: u64,
    /// All retained copy bytes, including each copy's immutable provenance.
    pub raw_bytes: u64,
}

#[derive(Clone, Copy)]
struct PoolLimits {
    account_owners: u64,
    account_bytes: u64,
    source_owners: u64,
    source_bytes: u64,
    account_scope: RawInnerQuotaScope,
    source_scope: RawInnerQuotaScope,
}

pub(super) fn reserve(
    db: &Connection,
    owner_id: &str,
    source_anchor: &str,
    additional_bytes: u64,
    supported_attestation: bool,
) -> Result<(), StorageError> {
    reject_foreign_source(db, owner_id, source_anchor)?;
    let is_new = !owner_in_pool(db, owner_id, supported_attestation)?;
    enforce(
        db,
        source_anchor,
        supported_attestation,
        is_new,
        additional_bytes,
        limits_for(supported_attestation),
    )
}

fn limits_for(supported: bool) -> PoolLimits {
    if supported {
        PoolLimits {
            account_owners: SUPPORTED_ACCOUNT_OWNER_LIMIT,
            account_bytes: SUPPORTED_ACCOUNT_BYTE_LIMIT,
            source_owners: SUPPORTED_SOURCE_OWNER_LIMIT,
            source_bytes: SUPPORTED_SOURCE_BYTE_LIMIT,
            account_scope: RawInnerQuotaScope::SupportedAttestation,
            source_scope: RawInnerQuotaScope::SupportedAttestation,
        }
    } else {
        PoolLimits {
            account_owners: ACCOUNT_OWNER_LIMIT,
            account_bytes: ACCOUNT_RAW_BYTE_LIMIT,
            source_owners: SOURCE_OWNER_LIMIT,
            source_bytes: SOURCE_RAW_BYTE_LIMIT,
            account_scope: RawInnerQuotaScope::Account,
            source_scope: RawInnerQuotaScope::Source,
        }
    }
}

fn exceeds(current: RawInnerQuota, new_owner: bool, added: u64, owners: u64, bytes: u64) -> bool {
    current.owners.saturating_add(u64::from(new_owner)) > owners
        || current.raw_bytes.saturating_add(added) > bytes
}

fn reject_foreign_source(
    db: &Connection,
    owner_id: &str,
    source_anchor: &str,
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
    Ok(())
}

fn owner_in_pool(db: &Connection, owner_id: &str, supported: bool) -> Result<bool, StorageError> {
    let kind = super::writer::SUPPORTED_OWN_ATTESTATION_KIND;
    let sql = if supported {
        "SELECT EXISTS(SELECT 1 FROM raw_inner_copy WHERE owner_id=?1 AND copy_kind=?2)"
    } else {
        "SELECT EXISTS(SELECT 1 FROM raw_inner_copy WHERE owner_id=?1 AND copy_kind<>?2)"
    };
    Ok(db.query_row(sql, params![owner_id, kind], |row| row.get(0))?)
}

fn enforce(
    db: &Connection,
    source_anchor: &str,
    supported: bool,
    is_new: bool,
    added: u64,
    limits: PoolLimits,
) -> Result<(), StorageError> {
    let account = measure(db, None, supported)?;
    if exceeds(account, is_new, added, limits.account_owners, limits.account_bytes) {
        return Err(quota_error(source_anchor, limits.account_scope));
    }
    let source = measure(db, Some(source_anchor), supported)?;
    if exceeds(source, is_new, added, limits.source_owners, limits.source_bytes) {
        return Err(quota_error(source_anchor, limits.source_scope));
    }
    Ok(())
}

fn quota_error(source_anchor: &str, scope: RawInnerQuotaScope) -> StorageError {
    StorageError::UnsupportedRawQuotaExceeded { source_anchor: source_anchor.to_owned(), scope }
}

fn measure(
    db: &Connection,
    source: Option<&str>,
    supported: bool,
) -> Result<RawInnerQuota, StorageError> {
    let (owners, raw_bytes) =
        if supported { supported_totals(db, source)? } else { unsupported_totals(db, source)? };
    Ok(RawInnerQuota {
        owners: u64::try_from(owners).map_err(|_| StorageError::AuthorizationRejected)?,
        raw_bytes: u64::try_from(raw_bytes).map_err(|_| StorageError::AuthorizationRejected)?,
    })
}

fn unsupported_totals(db: &Connection, source: Option<&str>) -> Result<(i64, i64), StorageError> {
    let kind = super::writer::SUPPORTED_OWN_ATTESTATION_KIND;
    // Owners with only supported proofs, and those proofs' bytes, stay out of this pool.
    let select = "SELECT count(DISTINCT CASE WHEN c.copy_id IS NULL OR c.copy_kind<>?1 THEN o.owner_id END), \
         coalesce(sum(CASE WHEN c.copy_kind IS NOT NULL AND c.copy_kind<>?1 THEN length(c.raw_bytes)+length(c.copy_metadata) ELSE 0 END),0) \
         FROM raw_inner_owner o LEFT JOIN raw_inner_copy c USING(owner_id)";
    if let Some(source) = source {
        Ok(db.query_row(
            &format!("{select} WHERE o.source_anchor=?2"),
            params![kind, source],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    } else {
        Ok(db.query_row(select, params![kind], |row| Ok((row.get(0)?, row.get(1)?)))?)
    }
}

fn supported_totals(db: &Connection, source: Option<&str>) -> Result<(i64, i64), StorageError> {
    let kind = super::writer::SUPPORTED_OWN_ATTESTATION_KIND;
    let select = "SELECT count(DISTINCT o.owner_id),coalesce(sum(length(c.raw_bytes)+length(c.copy_metadata)),0) \
         FROM raw_inner_owner o JOIN raw_inner_copy c USING(owner_id) WHERE c.copy_kind=?1";
    if let Some(source) = source {
        Ok(db.query_row(
            &format!("{select} AND o.source_anchor=?2"),
            params![kind, source],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    } else {
        Ok(db.query_row(select, params![kind], |row| Ok((row.get(0)?, row.get(1)?)))?)
    }
}

pub(in crate::account_db) fn validate_all(db: &Connection) -> Result<(), StorageError> {
    enforce_stored(db, false)?;
    enforce_stored(db, true)
}

fn enforce_stored(db: &Connection, supported: bool) -> Result<(), StorageError> {
    let limits = limits_for(supported);
    let account = measure(db, None, supported)?;
    if exceeds(account, false, 0, limits.account_owners, limits.account_bytes) {
        let source: String = db.query_row(
            "SELECT source_anchor FROM raw_inner_owner ORDER BY source_anchor LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        return Err(quota_error(&source, limits.account_scope));
    }
    let mut sources = db.prepare(
        "SELECT source_anchor FROM raw_inner_owner GROUP BY source_anchor ORDER BY source_anchor",
    )?;
    let anchors = sources
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for anchor in anchors {
        let source = measure(db, Some(&anchor), supported)?;
        if exceeds(source, false, 0, limits.source_owners, limits.source_bytes) {
            return Err(quota_error(&anchor, limits.source_scope));
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
        self.read_quota(source_anchor, false)
    }

    /// Returns retained supported own-message attestation owners and bytes.
    ///
    /// # Errors
    /// Returns a storage error if the attestation index cannot be read.
    pub fn supported_own_attestation_quota(
        &self,
        source_anchor: Option<&str>,
    ) -> Result<RawInnerQuota, StorageError> {
        self.read_quota(source_anchor, true)
    }

    fn read_quota(
        &self,
        source_anchor: Option<&str>,
        supported: bool,
    ) -> Result<RawInnerQuota, StorageError> {
        let source_anchor = source_anchor.map(str::to_owned);
        self.connection
            .call(move |db| Ok(measure(db, source_anchor.as_deref(), supported)))
            .map_err(StorageError::from)?
    }
}
