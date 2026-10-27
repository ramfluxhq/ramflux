// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 publication and durable mode fencing, separate from legacy enrollment.
use crate::{IdentityRegistry, NodeCoreError, RouterCore, RouterRedbStore};
use ramflux_crypto::custody::{AuthorityPins, PinOutcome, VerifiedRecord, verify_record};
use ramflux_protocol::custody::{DeviceSet, Envelope};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyRegistry {
    pins: AuthorityPins,
    records: BTreeMap<String, CustodyPublication>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    account_pins: BTreeMap<String, AuthorityPins>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) principals: BTreeMap<String, String>,
}
impl CustodyRegistry {
    fn pins_for(&self, anchor: &str) -> AuthorityPins {
        self.account_pins.get(anchor).cloned().unwrap_or_else(|| self.pins.for_account(anchor))
    }
    fn require_current(&self, record: &VerifiedRecord) -> Result<(), ramflux_crypto::CryptoError> {
        self.account_pins
            .get(&record.envelope().body.account_anchor)
            .unwrap_or(&self.pins)
            .require_current(record)
    }
    pub(crate) fn permits_legacy(&self, anchor: &str) -> bool {
        !self.account_pins.contains_key(anchor) && self.pins.permits_legacy(anchor)
    }
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty() && self.principals.is_empty()
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
                self.custody.require_current(&verified).map_err(|error| crypto(&error))?;
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
    #[cfg(test)]
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
        let body = &publication.record.body;
        let master = &body.master_certificate.body.master_public_key;
        self.check_principal_root_ownership(&body.principal_id, master)?;
        let mut pins = self.custody.pins_for(anchor);
        let outcome = pins.observe(&verified).map_err(|error| crypto(&error))?;
        let custody = Arc::make_mut(&mut self.custody);
        custody.account_pins.insert(anchor.clone(), pins);
        custody.principals.entry(body.principal_id.clone()).or_insert_with(|| master.clone());
        if outcome == PinOutcome::Advanced {
            if verified.capacity_pressure().any() {
                tracing::warn!(account_anchor = %anchor, "custody authority reached eighty percent capacity; prioritize revocations");
            }
            custody.records.insert(anchor.clone(), publication.clone());
        }
        Ok(outcome)
    }
}
impl RouterCore {
    pub(crate) fn custody_anchor_known(&self, anchor: &str) -> bool {
        self.control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .mvp1_identities
            .custody
            .records
            .contains_key(anchor)
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
        self.publish_custody_record_from(
            publication,
            now,
            store,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        )
    }
    /// Publish with durable network-prefix and node-wide new-principal admission.
    /// # Errors
    /// Rejects bad authority, ownership conflicts, exhausted budgets and durable failures.
    pub fn publish_custody_record_from(
        &self,
        publication: &CustodyPublication,
        now: u64,
        store: &RouterRedbStore,
        source: std::net::IpAddr,
    ) -> Result<Envelope<DeviceSet>, NodeCoreError> {
        let mut control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let registry = &mut control.mvp1_identities;
        let anchor = &publication.record.body.account_anchor;
        if registry.signed_device_sets.contains_key(anchor)
            || registry.root_public_keys_by_commitment.contains_key(anchor)
        {
            return Err(reject("legacy-to-custody migration is not enabled"));
        }
        let verified = registry.verify_custody(publication, now)?;
        let body = &publication.record.body;
        registry.check_principal_root_ownership(
            &body.principal_id,
            &body.master_certificate.body.master_public_key,
        )?;
        let mut pins = registry.custody.pins_for(anchor);
        let outcome = pins.observe(&verified).map_err(|error| crypto(&error))?;
        if outcome == PinOutcome::Unchanged {
            return Ok(publication.record.clone());
        }
        let accepted = if outcome == PinOutcome::Fenced {
            registry
                .custody
                .records
                .get(anchor)
                .cloned()
                .ok_or_else(|| reject("fenced head unavailable"))?
        } else {
            publication.clone()
        };
        let state = CustodyAccountState { publication: accepted, pins };
        let is_new = !registry.custody.records.contains_key(anchor);
        if is_new && registry.custody.records.len() >= 65_536 {
            return Err(crate::NodeCoreError::Capacity { resource: "custody account count" });
        }
        if verified.capacity_pressure().any() {
            tracing::warn!(account_anchor=%anchor,"custody authority reached eighty percent capacity; prioritize revocations");
        }
        store.record_custody_account(anchor, &state, is_new, source, now)?;
        registry.apply_custody_account(anchor.clone(), state)?;
        // Native custody does not change the legacy delivery-key migration read snapshot.
        if outcome == PinOutcome::Fenced {
            return Err(reject("custody authority equivocation fenced"));
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
        registry.custody.require_current(&verified).map_err(|error| crypto(&error))?;
        Ok(Some(publication.clone()))
    }
}

impl RouterCore {
    pub(crate) fn verify_custody_possession_authority(
        &self,
        publication: &CustodyPublication,
        now: u64,
        require_current: bool,
    ) -> Result<VerifiedRecord, NodeCoreError> {
        let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let registry = &control.mvp1_identities;
        let verified = registry.verify_custody(publication, now)?;
        if require_current {
            registry.custody.require_current(&verified).map_err(|error| crypto(&error))?;
        }
        Ok(verified)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyAccountState {
    pub publication: CustodyPublication,
    pub pins: AuthorityPins,
}
impl IdentityRegistry {
    pub(crate) fn apply_custody_account(
        &mut self,
        anchor: String,
        state: CustodyAccountState,
    ) -> Result<(), NodeCoreError> {
        let body = &state.publication.record.body;
        if anchor != body.account_anchor {
            return Err(reject("custody durable account key mismatch"));
        }
        self.check_principal_root_ownership(
            &body.principal_id,
            &body.master_certificate.body.master_public_key,
        )?;
        let custody = Arc::make_mut(&mut self.custody);
        custody
            .principals
            .entry(body.principal_id.clone())
            .or_insert_with(|| body.master_certificate.body.master_public_key.clone());
        custody.account_pins.insert(anchor.clone(), state.pins);
        custody.records.insert(anchor, state.publication);
        Ok(())
    }
}
