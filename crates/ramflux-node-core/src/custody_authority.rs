// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 publication and durable mode fencing, separate from legacy enrollment.
use crate::{IdentityRegistry, NodeCoreError, RouterCore, RouterRedbStore};
use ramflux_crypto::custody::{
    AuthorityPins, CustodyConflictEvidence, PinOutcome, VerifiedRecord, verify_record,
};
use ramflux_protocol::custody::{DeviceSet, Envelope};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyRegistry {
    pins: AuthorityPins,
    records: BTreeMap<String, CustodyPublication>,
}
impl CustodyRegistry {
    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub(crate) fn permits_legacy(&self, anchor: &str) -> bool {
        self.pins.permits_legacy(anchor)
    }
    fn conflict_evidence(&self, anchor: &str, range: u64) -> Option<&CustodyConflictEvidence> {
        self.pins.conflict_evidence(anchor, range)
    }
}
/// Full signed authority plus the bounded cumulative membership evidence, when present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyPublication {
    pub record: Envelope<DeviceSet>,
    pub compacted_ids: Option<Vec<String>>,
}
impl CustodyPublication {
    /// Decode original I-JSON bytes, preserving mandatory null and duplicate-key checks.
    /// # Errors
    /// Rejects oversized, ambiguous or noncanonical typed input.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        ramflux_protocol::custody::decode(
            bytes,
            ramflux_protocol::custody::MAX_RECORD_BYTES
                + ramflux_protocol::custody::MAX_REVOKED_LIST_BYTES,
        )
        .map_err(|e| reject(&e.to_string()))
    }
}
fn reject(message: &str) -> NodeCoreError {
    NodeCoreError::ItestHttp(message.into())
}
fn crypto(error: &ramflux_crypto::CryptoError) -> NodeCoreError {
    reject(&error.to_string())
}
impl IdentityRegistry {
    fn verify_custody(
        &self,
        publication: &CustodyPublication,
        now: u64,
    ) -> Result<VerifiedRecord, NodeCoreError> {
        let certificate = &publication.record.body.master_certificate.body;
        let human =
            if certificate.custody_kind == ramflux_protocol::custody::CustodyKind::ExternalHuman {
                let custodian = self
                    .custody
                    .records
                    .get(&certificate.primary_device_ref.account_anchor)
                    .ok_or_else(|| reject("current human custodian authority unavailable"))?;
                let verified =
                    verify_record(&custodian.record, now, custodian.compacted_ids.as_deref(), None)
                        .map_err(|error| crypto(&error))?;
                self.custody.pins.require_current(&verified).map_err(|error| crypto(&error))?;
                Some(verified)
            } else {
                None
            };
        verify_record(
            &publication.record,
            now,
            publication.compacted_ids.as_deref(),
            human.as_ref(),
        )
        .map_err(|error| crypto(&error))
    }
    pub(crate) fn observe_custody(
        &mut self,
        publication: &CustodyPublication,
        now: u64,
    ) -> Result<PinOutcome, NodeCoreError> {
        let anchor = &publication.record.body.account_anchor;
        if self.signed_device_sets.contains_key(anchor)
            || self.root_public_keys_by_commitment.contains_key(anchor)
        {
            return Err(reject("legacy-to-custody migration is not enabled"));
        }
        let verified = self.verify_custody(publication, now)?;
        let previous = self.custody.records.get(anchor).map(|entry| entry.record.clone());
        let pruned_before = self.custody.pins.pruned_evidence(anchor);
        let outcome = self
            .custody
            .pins
            .observe_with_previous(&verified, previous.as_ref())
            .map_err(|error| crypto(&error))?;
        let pruned_after = self.custody.pins.pruned_evidence(anchor);
        if pruned_after > pruned_before {
            tracing::warn!(
                account_anchor = %anchor,
                dropped = pruned_after - pruned_before,
                "dropped older custody conflict evidence to enforce retention bounds"
            );
        }
        if outcome == PinOutcome::Advanced {
            if verified.capacity_pressure().any() {
                tracing::warn!(account_anchor = %anchor, "custody authority reached eighty percent capacity; prioritize revocations");
            }
            self.custody.records.insert(anchor.clone(), publication.clone());
        }
        if let PinOutcome::Fenced(alert) = &outcome {
            tracing::error!(
                account_anchor = %alert.account_anchor,
                range_index = alert.range_index,
                conflict_kind = ?alert.kind,
                accepted_record_hash = %alert.accepted_record_hash,
                conflicting_record_hash = %alert.conflicting_record_hash,
                "custody authority conflict requires operator review and a new master certificate"
            );
        }
        Ok(outcome)
    }
}
impl RouterCore {
    /// Return the first complete authenticated conflict pair retained for a fenced range.
    #[must_use]
    pub fn custody_conflict_evidence(
        &self,
        anchor: &str,
        range: u64,
    ) -> Option<CustodyConflictEvidence> {
        let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        control.mvp1_identities.custody.conflict_evidence(anchor, range).cloned()
    }
    /// Verify and persist head/mode pins atomically, including valid equivocation fences.
    /// # Errors
    /// Rejects invalid/stale/migrated authority or durable write failures.
    pub fn publish_custody_record(
        &self,
        publication: &CustodyPublication,
        now: u64,
        store: &RouterRedbStore,
    ) -> Result<Envelope<DeviceSet>, NodeCoreError> {
        let mut control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut candidate = control.mvp1_identities.clone();
        let outcome = candidate.observe_custody(publication, now)?;
        store.record_identity_registry(&candidate)?;
        control.mvp1_identities = candidate;
        self.refresh_migration_read_snapshot_from_control(&control);
        if let PinOutcome::Fenced(alert) = outcome {
            return Err(NodeCoreError::CustodyConflict { alert: Box::new(alert) });
        }
        Ok(publication.record.clone())
    }
    /// Return only the current unfenced head, rechecking signatures and leases at use time.
    /// # Errors
    /// Rejects fenced or malformed persisted authority.
    pub fn custody_record(
        &self,
        anchor: &str,
        now: u64,
    ) -> Result<Option<CustodyPublication>, NodeCoreError> {
        let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let registry = &control.mvp1_identities;
        let Some(publication) = registry.custody.records.get(anchor) else {
            return Ok(None);
        };
        let verified = registry.verify_custody(publication, now)?;
        registry.custody.pins.require_current(&verified).map_err(|error| crypto(&error))?;
        Ok(Some(publication.clone()))
    }
}
