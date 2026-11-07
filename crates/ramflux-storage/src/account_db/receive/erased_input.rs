// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Tombstones of deleted authenticated inputs. A row holds only MAC selectors, the bundle that
//! produced each, and an expiry; it never holds an id, ciphertext or message link.
// Dormant: the first producers and the W0 reader land in later P03a parts.
#![allow(dead_code)]
use crate::{AccountDb, StorageError};
use rusqlite::params;

const LABEL: &[u8] = b"ramflux/deleted-envelope/v1";
/// Router clock skew and envelope TTL caps (`ramflux-node-core` replay guard), plus slack.
const MAX_CLOCK_SKEW: i64 = 120;
const MAX_ENVELOPE_TTL: i64 = 604_800;
const SLACK: i64 = 300;
/// Expired rows removed by each write.
const SWEEP: i64 = 64;

/// The exact authenticated tuple that identifies one admitted envelope.
pub(crate) struct ErasedTuple<'a> {
    pub principal: &'a str,
    pub device: &'a str,
    pub signing_key_id: &'a str,
    pub payload_hash: &'a str,
}

impl<'a> ErasedTuple<'a> {
    pub(crate) fn from_envelope(envelope: &'a ramflux_protocol::Envelope) -> Self {
        Self {
            principal: &envelope.source_principal_id,
            device: &envelope.source_device_id,
            signing_key_id: &envelope.signed.signing_key_id,
            payload_hash: &envelope.payload_hash,
        }
    }

    fn canonical(&self) -> Result<Vec<u8>, StorageError> {
        Ok(ramflux_protocol::canonical_json_bytes(&[
            "erased-input/v1",
            self.principal,
            self.device,
            self.signing_key_id,
            self.payload_hash,
        ])?)
    }
}

impl AccountDb {
    fn erased_input_selectors(
        &self,
        tuple: &ErasedTuple<'_>,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let value = tuple.canonical()?;
        self.connection
            .call(move |raw| Ok(super::super::mac_subkeys::bundle_macs(raw, LABEL, &value)))?
    }

    /// Records one tombstone per retained MAC bundle. An already-expired input writes nothing.
    /// Each write sweeps up to 64 expired rows through the expiry index.
    ///
    /// # Errors
    /// Returns storage or canonicalization errors.
    pub(crate) fn record_erased_input(
        &self,
        tuple: &ErasedTuple<'_>,
        created_at: i64,
        ttl: u64,
    ) -> Result<(), StorageError> {
        let now = crate::unix_now();
        let ttl = i64::try_from(ttl).unwrap_or(i64::MAX).min(MAX_ENVELOPE_TTL);
        let expires_at = created_at.min(now.saturating_add(MAX_CLOCK_SKEW)) + ttl + SLACK;
        if expires_at <= now {
            return Ok(());
        }
        let selectors = self.erased_input_selectors(tuple)?;
        self.write_transaction(|| {
            for (bundle, selector) in &selectors {
                self.connection.execute(
                    "INSERT INTO receive_erased_input VALUES(?1,?2,?3) \
                     ON CONFLICT(selector) DO UPDATE SET expires_at=max(expires_at,excluded.expires_at)",
                    params![selector, bundle, expires_at],
                )?;
            }
            self.connection.execute(
                "DELETE FROM receive_erased_input WHERE selector IN \
                 (SELECT selector FROM receive_erased_input WHERE expires_at<=?1 \
                  ORDER BY expires_at LIMIT ?2)",
                params![now, SWEEP],
            )?;
            Ok(())
        })
    }

    /// True when a live tombstone matches the envelope's exact authenticated tuple under any
    /// retained bundle.
    ///
    /// # Errors
    /// Returns storage or canonicalization errors.
    pub(crate) fn erased_input_matches(
        &self,
        envelope: &ramflux_protocol::Envelope,
    ) -> Result<bool, StorageError> {
        let now = crate::unix_now();
        for (_, selector) in self.erased_input_selectors(&ErasedTuple::from_envelope(envelope))? {
            let live: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM receive_erased_input WHERE selector=?1 AND expires_at>?2)",
                params![selector, now],
                |row| row.get(0),
            )?;
            if live {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
