// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resident metadata limits and capacity/accounting errors.

use super::{NodeCoreError, ObjectRelayTombstone, env};

/// Single env override for the relay resident metadata budget (RELAY-MEM-01-A1). The value is the
/// maximum number of bytes the in-memory chunk-meta + tombstone index (including in-flight
/// reservations) may charge. Absent or unexpanded optional input uses the bounded
/// [`RELAY_METADATA_MAX_BYTES_DEFAULT`]; an explicit `0` remains a startup failure.
pub const RELAY_METADATA_MAX_BYTES_ENV: &str = "RAMFLUX_RELAY_METADATA_MAX_BYTES";
/// Default resident metadata budget: 64 MiB. Only the metadata index is resident; chunk ciphertext
/// lives in redb and is read through on demand, so this bounds RAM independent of stored object size.
pub const RELAY_METADATA_MAX_BYTES_DEFAULT: u64 = 64 * 1024 * 1024;
/// Conservative fixed per-chunk-meta overhead added to the serialized metadata length. This is a
/// deliberately safe over-estimate covering `BTreeMap` node/key allocation, the `String`/`BTreeSet`
/// heap headers, and reservation bookkeeping so the resident charge can never under-count RAM.
pub(super) const RELAY_CHUNK_META_CHARGE_OVERHEAD: u64 = 512;
/// Conservative fixed per-tombstone overhead added to the serialized tombstone length. Same safe
/// over-estimate rationale as [`RELAY_CHUNK_META_CHARGE_OVERHEAD`].
pub(super) const RELAY_TOMBSTONE_CHARGE_OVERHEAD: u64 = 256;

#[must_use]
pub(super) fn relay_default_max_bytes() -> u64 {
    RELAY_METADATA_MAX_BYTES_DEFAULT
}

/// Resolve an optional environment override without accepting an unexpanded expression.
///
/// # Errors
/// Returns an error for malformed or zero budgets; unresolved optional input selects 64 MiB.
pub fn relay_metadata_max_bytes_from_env() -> Result<u64, NodeCoreError> {
    match env::var(RELAY_METADATA_MAX_BYTES_ENV) {
        Ok(value) => configured_metadata_budget(Some(&value)),
        Err(std::env::VarError::NotPresent) => configured_metadata_budget(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(NodeCoreError::ItestHttp(format!(
            "{RELAY_METADATA_MAX_BYTES_ENV} must be a positive integer"
        ))),
    }
}

fn configured_metadata_budget(raw: Option<&str>) -> Result<u64, NodeCoreError> {
    let raw = env::configured_value(RELAY_METADATA_MAX_BYTES_ENV, raw).map(str::trim);
    parse_relay_metadata_max_bytes(raw)
}

/// Pure resident-budget resolver: `None` (unset) yields the 64 MiB default; a positive integer
/// overrides; `0` or a non-parseable value is a hard failure (never a silent default).
///
/// # Errors
/// Returns [`NodeCoreError::ItestHttp`] when the value is present but not a positive integer.
pub fn parse_relay_metadata_max_bytes(raw: Option<&str>) -> Result<u64, NodeCoreError> {
    match raw {
        None => Ok(RELAY_METADATA_MAX_BYTES_DEFAULT),
        Some(value) => {
            value.trim().parse::<u64>().ok().filter(|parsed| *parsed > 0).ok_or_else(|| {
                NodeCoreError::ItestHttp(format!(
                    "{RELAY_METADATA_MAX_BYTES_ENV} must be a positive integer"
                ))
            })
        }
    }
}

/// An internal reservation-accounting invariant violation. PRE-persist (reserve) these are surfaced as
/// a fail-closed [`RelayStoreOpError::Capacity`]; POST-persist (publish) they are a fail-stop, because
/// redb is already committed and silently continuing would split redb from the live index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RelayInternalInvariant(pub(super) &'static str);

impl std::fmt::Display for RelayInternalInvariant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "relay internal invariant violated: {}", self.0)
    }
}

impl std::error::Error for RelayInternalInvariant {}

/// Explicit capacity/backpressure signal: admitting a new chunk-meta or tombstone would push the
/// resident charge past the configured budget. The relay maps this to a `503` with zero redb and
/// zero memory mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayResidentBudgetExceeded {
    pub requested_charge: u64,
    pub resident_bytes: u64,
    pub max_bytes: u64,
}

impl std::fmt::Display for RelayResidentBudgetExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "relay resident metadata budget exceeded: requested {} + resident {} > max {}",
            self.requested_charge, self.resident_bytes, self.max_bytes
        )
    }
}

impl std::error::Error for RelayResidentBudgetExceeded {}

#[must_use]
pub(super) fn tombstone_resident_charge(tombstone: &ObjectRelayTombstone) -> Option<u64> {
    let body = serde_json::to_vec(tombstone).map_or(usize::MAX, |bytes| bytes.len());
    u64::try_from(body).ok()?.checked_add(RELAY_TOMBSTONE_CHARGE_OVERHEAD)
}

/// Typed outcome of a store-backed relay operation (read-through / persist-before-publish). The relay
/// HTTP/QUIC layer maps each variant to a status code; the v2 path folds it back into a
/// [`NodeCoreError`] to preserve the existing coarse mesh error taxonomy.
#[derive(Debug)]
pub enum RelayStoreOpError {
    /// Chunk not present / not available (`404`).
    NotAvailable,
    /// Object is tombstoned: `410` on get, `409` on put.
    Tombstoned,
    /// Owner / object / content / authorization rejection (`403`).
    Unauthorized(String),
    /// A conflicting mutation is in flight on the same chunk/object — retryable (`409`). Zero
    /// mutation: nothing was reserved, persisted, or published.
    Conflict(String),
    /// Resident metadata budget exceeded — backpressure (`503`).
    Capacity(String),
    /// redb persistence failed (`500`); nothing was published.
    Persist(String),
    /// The redb payload was missing/corrupt/mismatched on a read-through (`500`, fail-closed).
    PayloadUnavailable(String),
    /// Validation or internal error carried from [`NodeCoreError`].
    Validation(Box<NodeCoreError>),
}

impl From<NodeCoreError> for RelayStoreOpError {
    fn from(error: NodeCoreError) -> Self {
        // Preserve the status taxonomy when a validation/plan error crosses into the store layer:
        // owner/authorization and TTL rejections are `403`, a missing chunk is `404`; anything else
        // is an opaque internal (`500`) `Validation`.
        match error {
            NodeCoreError::Unauthorized(reason) => Self::Unauthorized(reason),
            NodeCoreError::EnvelopeNotFound(_) => Self::NotAvailable,
            NodeCoreError::TtlExpired { envelope_id } => {
                Self::Unauthorized(format!("object relay ttl rejected: {envelope_id}"))
            }
            other => Self::Validation(Box::new(other)),
        }
    }
}

impl From<RelayResidentBudgetExceeded> for RelayStoreOpError {
    fn from(error: RelayResidentBudgetExceeded) -> Self {
        Self::Capacity(error.to_string())
    }
}

impl std::fmt::Display for RelayStoreOpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable => write!(formatter, "relay chunk not available"),
            Self::Tombstoned => write!(formatter, "relay object tombstoned"),
            Self::Unauthorized(reason) => write!(formatter, "relay unauthorized: {reason}"),
            Self::Conflict(reason) => write!(formatter, "relay conflict: {reason}"),
            Self::Capacity(reason) => write!(formatter, "relay capacity: {reason}"),
            Self::Persist(reason) => write!(formatter, "relay persist failed: {reason}"),
            Self::PayloadUnavailable(reason) => {
                write!(formatter, "relay payload unavailable: {reason}")
            }
            Self::Validation(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for RelayStoreOpError {}

impl RelayStoreOpError {
    /// Folds the typed store error back into a [`NodeCoreError`] for the v2 mesh path and the pure
    /// state methods, preserving the pre-existing error taxonomy (tombstone/get-miss → `ItestHttp`
    /// / `EnvelopeNotFound`, owner rejections → `Unauthorized`).
    #[must_use]
    pub fn into_node_core(self) -> NodeCoreError {
        match self {
            Self::NotAvailable => NodeCoreError::EnvelopeNotFound("relay chunk".to_owned()),
            Self::Tombstoned => {
                NodeCoreError::ItestHttp("object relay tombstone blocks chunk".to_owned())
            }
            Self::Unauthorized(reason) => NodeCoreError::Unauthorized(reason),
            Self::Conflict(reason) | Self::Capacity(reason) => NodeCoreError::ItestHttp(reason),
            Self::Persist(reason) | Self::PayloadUnavailable(reason) => NodeCoreError::Redb(reason),
            Self::Validation(error) => *error,
        }
    }

    /// The HTTP/QUIC status code the relay returns for this outcome.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            Self::NotAvailable => 404,
            Self::Tombstoned => 410,
            Self::Unauthorized(_) => 403,
            Self::Conflict(_) => 409,
            Self::Capacity(_) => 503,
            Self::Persist(_) | Self::PayloadUnavailable(_) | Self::Validation(_) => 500,
        }
    }
}

#[cfg(test)]
mod environment_tests {
    use super::*;
    #[test]
    fn malformed_budget_is_fatal_while_unexpanded_optional_budget_uses_default()
    -> Result<(), NodeCoreError> {
        for value in [None, Some("${RAMFLUX_RELAY_METADATA_MAX_BYTES:-0}")] {
            assert_eq!(configured_metadata_budget(value)?, RELAY_METADATA_MAX_BYTES_DEFAULT);
        }
        assert_eq!(configured_metadata_budget(Some(" 1048576 "))?, 1_048_576);
        for value in ["", "invalid", "18446744073709551616", "0"] {
            let error = configured_metadata_budget(Some(value));
            assert!(error.is_err());
            assert_eq!(
                error.err().map(|error| error.to_string()),
                parse_relay_metadata_max_bytes(Some(value)).err().map(|error| error.to_string())
            );
        }
        Ok(())
    }
}
