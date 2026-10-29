// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable authenticated mode, certificate, head and denial floors.
use super::{VerifiedRecord, validate::reject};
use crate::CryptoError;
use ramflux_protocol::custody::{DeviceSet, Envelope, decode_epoch, object_hash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CONFLICT_RANGES: usize = 8;
const MAX_CONFLICT_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;

/// Persist atomically with the accepted head before exposing new authority.
/// Deserialization is only for trusted local storage, never a network capability.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPins {
    accounts: BTreeMap<String, AccountPin>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountPin {
    principal_id: String,
    principal_kind: ramflux_protocol::PrincipalKind,
    certificates: BTreeMap<u64, String>,
    fenced_ranges: BTreeSet<u64>,
    epoch: u64,
    hash: String,
    revoked_ids: BTreeSet<String>,
    devices: BTreeMap<String, (u64, String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_record: Option<Envelope<DeviceSet>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    range_records: BTreeMap<u64, Envelope<DeviceSet>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    conflicts: BTreeMap<u64, CustodyConflictEvidence>,
    #[serde(default, skip_serializing_if = "is_default")]
    pruned_evidence: u64,
}
fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
}
/// Authenticated conflict class surfaced to callers as a blocking security alert.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyConflictKind {
    MasterCertificate,
    RecordHead,
}
/// Typed blocking alert. Hashes identify both complete envelopes retained in evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyConflictAlert {
    pub account_anchor: String,
    pub range_index: u64,
    pub kind: CustodyConflictKind,
    pub accepted_record_hash: String,
    pub conflicting_record_hash: String,
}
/// The first complete authenticated conflict pair retained for one fenced range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyConflictEvidence {
    pub alert: CustodyConflictAlert,
    pub accepted: Envelope<DeviceSet>,
    pub conflicting: Envelope<DeviceSet>,
}
/// A valid conflict must be durably recorded even though it grants no authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinOutcome {
    Advanced,
    Unchanged,
    Fenced(CustodyConflictAlert),
}
impl AuthorityPins {
    /// Once observed, a born-v3 anchor can never authorize a legacy record.
    #[must_use]
    pub fn permits_legacy(&self, anchor: &str) -> bool {
        !self.accounts.contains_key(anchor)
    }
    /// Require the exact accepted, unfenced head immediately before authorization.
    /// # Errors
    /// Rejects absent, stale, conflicting or fenced authority.
    pub fn require_current(&self, record: &VerifiedRecord) -> Result<(), CryptoError> {
        let body = &record.envelope().body;
        let pin = self
            .accounts
            .get(&body.account_anchor)
            .ok_or_else(|| reject("custody mode unpinned"))?;
        let range = decode_epoch(body.device_set_epoch)?.0;
        if pin.fenced_ranges.contains(&range)
            || pin.epoch != body.device_set_epoch
            || pin.hash != object_hash(record.envelope())?
        {
            return Err(reject("custody head is stale or fenced"));
        }
        Ok(())
    }
    /// Observe only completely verified evidence. Invalid signatures cannot poison pins.
    /// Persist the resulting state for every successful outcome, including `Fenced`.
    /// # Errors
    /// Rejects rollback, immutable identity changes, erased denials or branch-key regression.
    pub fn observe(&mut self, record: &VerifiedRecord) -> Result<PinOutcome, CryptoError> {
        self.observe_with_previous(record, None)
    }
    /// Observe with a separately stored current envelope, used to upgrade old pin snapshots that
    /// predate embedded evidence retention.
    /// # Errors
    /// Rejects rollback, immutable identity changes, erased denials or unavailable conflict proof.
    pub fn observe_with_previous(
        &mut self,
        record: &VerifiedRecord,
        previous: Option<&Envelope<DeviceSet>>,
    ) -> Result<PinOutcome, CryptoError> {
        let body = &record.envelope().body;
        let range = decode_epoch(body.device_set_epoch)?.0;
        let certificate = object_hash(&body.master_certificate)?;
        let hash = object_hash(record.envelope())?;
        let devices = indexed_devices(record)?;
        if let Some(pin) = self.accounts.get_mut(&body.account_anchor) {
            return observe_existing(pin, record, previous, certificate, hash, devices);
        }
        self.accounts.insert(
            body.account_anchor.clone(),
            AccountPin {
                principal_id: body.principal_id.clone(),
                principal_kind: body.principal_kind,
                certificates: BTreeMap::from([(range, certificate)]),
                fenced_ranges: BTreeSet::new(),
                epoch: body.device_set_epoch,
                hash,
                revoked_ids: record.revoked_ids().clone(),
                devices,
                current_record: Some(record.envelope().clone()),
                range_records: BTreeMap::from([(range, record.envelope().clone())]),
                conflicts: BTreeMap::new(),
                pruned_evidence: 0,
            },
        );
        Ok(PinOutcome::Advanced)
    }
    /// Return the durable first authenticated conflict pair for operator review.
    #[must_use]
    pub fn conflict_evidence(&self, anchor: &str, range: u64) -> Option<&CustodyConflictEvidence> {
        self.accounts.get(anchor)?.conflicts.get(&range)
    }
    /// Number of full conflict pairs discarded to enforce evidence retention bounds.
    #[must_use]
    pub fn pruned_evidence(&self, anchor: &str) -> u64 {
        self.accounts.get(anchor).map_or(0, |pin| pin.pruned_evidence)
    }
    /// Remove full record copies when only current hashes and certificate pins are needed locally.
    /// Subsequent observations must pass the separately stored head to `observe_with_previous`.
    pub fn discard_retained_records(&mut self) {
        for pin in self.accounts.values_mut() {
            pin.current_record = None;
            pin.range_records.clear();
            pin.conflicts.clear();
        }
    }
}

fn observe_existing(
    pin: &mut AccountPin,
    record: &VerifiedRecord,
    previous: Option<&Envelope<DeviceSet>>,
    certificate: String,
    hash: String,
    devices: BTreeMap<String, (u64, String, String)>,
) -> Result<PinOutcome, CryptoError> {
    let body = &record.envelope().body;
    let range = decode_epoch(body.device_set_epoch)?.0;
    if pin.principal_id != body.principal_id || pin.principal_kind != body.principal_kind {
        return Err(reject("custody immutable identity changed"));
    }
    if range < decode_epoch(pin.epoch)?.0 {
        return Err(reject("custody epoch rollback"));
    }
    if pin.certificates.get(&range).is_some_and(|old| old != &certificate) {
        return fence(
            pin,
            record.envelope(),
            previous,
            range,
            CustodyConflictKind::MasterCertificate,
        );
    }
    if body.device_set_epoch < pin.epoch {
        return Err(reject("custody epoch rollback"));
    }
    if body.device_set_epoch == pin.epoch {
        if pin.hash != hash {
            return fence(pin, record.envelope(), previous, range, CustodyConflictKind::RecordHead);
        }
        if pin.fenced_ranges.contains(&range) {
            let alert = pin
                .conflicts
                .get(&range)
                .ok_or_else(|| reject("custody conflict evidence unavailable"))?
                .alert
                .clone();
            return Ok(PinOutcome::Fenced(alert));
        }
        if pin.current_record.is_none() {
            pin.current_record = Some(record.envelope().clone());
        }
        return Ok(PinOutcome::Unchanged);
    }
    if pin.fenced_ranges.contains(&range) {
        return fence(pin, record.envelope(), previous, range, CustodyConflictKind::RecordHead);
    }
    validate_transition(pin, record)?;
    pin.certificates.insert(range, certificate);
    pin.epoch = body.device_set_epoch;
    pin.hash = hash;
    pin.current_record = Some(record.envelope().clone());
    pin.range_records.insert(range, record.envelope().clone());
    prune_evidence(pin, None)?;
    pin.revoked_ids.extend(record.revoked_ids().iter().cloned());
    pin.devices.extend(devices);
    Ok(PinOutcome::Advanced)
}

fn fence(
    pin: &mut AccountPin,
    conflicting: &Envelope<DeviceSet>,
    previous: Option<&Envelope<DeviceSet>>,
    range: u64,
    kind: CustodyConflictKind,
) -> Result<PinOutcome, CryptoError> {
    if let Some(evidence) = pin.conflicts.get(&range) {
        return Ok(PinOutcome::Fenced(evidence.alert.clone()));
    }
    let accepted = same_range_record(pin, previous, range)?.clone();
    let alert = CustodyConflictAlert {
        account_anchor: conflicting.body.account_anchor.clone(),
        range_index: range,
        kind,
        accepted_record_hash: object_hash(&accepted)?,
        conflicting_record_hash: object_hash(conflicting)?,
    };
    let evidence = CustodyConflictEvidence {
        alert: alert.clone(),
        accepted,
        conflicting: conflicting.clone(),
    };
    let singleton = BTreeMap::from([(range, &evidence)]);
    if ramflux_protocol::canonical_json_bytes(&(
        BTreeMap::<u64, Envelope<DeviceSet>>::new(),
        singleton,
    ))?
    .len()
        > MAX_CONFLICT_EVIDENCE_BYTES
    {
        return Err(reject("custody conflict evidence exceeds retention budget"));
    }
    pin.fenced_ranges.insert(range);
    pin.range_records.remove(&range);
    pin.conflicts.insert(range, evidence);
    prune_evidence(pin, Some(range))?;
    Ok(PinOutcome::Fenced(alert))
}

fn same_range_record<'a>(
    pin: &'a AccountPin,
    previous: Option<&'a Envelope<DeviceSet>>,
    range: u64,
) -> Result<&'a Envelope<DeviceSet>, CryptoError> {
    if let Some(record) = pin.range_records.get(&range) {
        return Ok(record);
    }
    for record in [pin.current_record.as_ref(), previous].into_iter().flatten() {
        if decode_epoch(record.body.device_set_epoch)?.0 == range
            && object_hash(record)? == pin.hash
        {
            return Ok(record);
        }
    }
    Err(reject("custody conflict evidence unavailable"))
}

fn prune_evidence(pin: &mut AccountPin, retained_conflict: Option<u64>) -> Result<(), CryptoError> {
    // current_record already retains the accepted head for same-range conflict pairing.
    // Superseded accepted copies must never displace evidence of a fenced range.
    pin.range_records.clear();
    let mut bytes = ramflux_protocol::canonical_json_bytes(&pin.conflicts)?.len();
    while pin.conflicts.len() > MAX_CONFLICT_RANGES || bytes + 5 > MAX_CONFLICT_EVIDENCE_BYTES {
        let oldest = pin
            .conflicts
            .keys()
            .copied()
            .find(|range| Some(*range) != retained_conflict)
            .ok_or_else(|| reject("custody conflict evidence exceeds retention budget"))?;
        let entry_bytes = ramflux_protocol::canonical_json_bytes(&BTreeMap::from([(
            oldest,
            &pin.conflicts[&oldest],
        )]))?
        .len();
        let separator = usize::from(pin.conflicts.len() > 1);
        bytes = bytes.saturating_sub(entry_bytes - 2 + separator);
        pin.conflicts.remove(&oldest);
        pin.pruned_evidence = pin.pruned_evidence.saturating_add(1);
    }
    Ok(())
}

fn validate_transition(pin: &AccountPin, record: &VerifiedRecord) -> Result<(), CryptoError> {
    let body = &record.envelope().body;
    if body.devices.len() > ramflux_protocol::custody::MAX_ENROLLMENT_ROSTER {
        for device in body
            .devices
            .iter()
            .filter(|device| device.status == ramflux_protocol::DeviceSetStatus::Active)
        {
            let reference =
                crate::RootQualifiedDeviceRef::from_custody_record(record, &device.device_id)?;
            if !pin.devices.contains_key(reference.storage_key()) {
                return Err(reject("custody enrollment reserve exhausted; prioritize revocation"));
            }
        }
    }
    if !pin.revoked_ids.is_subset(record.revoked_ids()) {
        return Err(reject("custody revocation rollback"));
    }
    for device in &body.devices {
        let reference =
            crate::RootQualifiedDeviceRef::from_custody_record(record, &device.device_id)?;
        if let Some((epoch, signing, agreement)) = pin.devices.get(reference.storage_key())
            && (device.device_epoch < *epoch
                || (device.device_epoch == *epoch
                    && (device.signing_key_commitment != *signing
                        || device.agreement_key_commitment != *agreement)))
        {
            return Err(reject("custody branch epoch or key rollback"));
        }
    }
    for key in pin.devices.keys() {
        let Some((root, device_id)) = ramflux_protocol::parse_qualified_device_id(key)? else {
            return Err(reject("custody pin device reference is not root qualified"));
        };
        if root != body.account_anchor
            || (!body.devices.iter().any(|device| device.device_id == device_id)
                && !record.revoked_ids().iter().any(|revoked| revoked == &device_id))
        {
            return Err(reject("custody roster entry disappeared without revocation"));
        }
    }
    Ok(())
}

fn indexed_devices(
    record: &VerifiedRecord,
) -> Result<BTreeMap<String, (u64, String, String)>, CryptoError> {
    record
        .envelope()
        .body
        .devices
        .iter()
        .map(|device| {
            let reference =
                crate::RootQualifiedDeviceRef::from_custody_record(record, &device.device_id)?;
            Ok((
                reference.storage_key().to_owned(),
                (
                    device.device_epoch,
                    device.signing_key_commitment.clone(),
                    device.agreement_key_commitment.clone(),
                ),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::verify_record;

    #[test]
    fn conflict_evidence_is_bounded_by_range_count_and_serialized_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/custody_v3.json"))?;
        let record: Envelope<DeviceSet> = serde_json::from_value(vector["record"].clone())?;
        let anchor = record.body.account_anchor.clone();
        let verified = verify_record(&record, record.body.issued_at, None, None)?;
        let mut pins = AuthorityPins::default();
        pins.observe(&verified)?;
        let pin = pins.accounts.get_mut(&anchor).ok_or("account pin")?;
        for range in 0..10 {
            let mut conflicting = record.clone();
            conflicting.body.profile.display_name = format!("{range}-{}", "x".repeat(600_000));
            let alert = CustodyConflictAlert {
                account_anchor: anchor.clone(),
                range_index: range,
                kind: CustodyConflictKind::RecordHead,
                accepted_record_hash: object_hash(&record)?,
                conflicting_record_hash: object_hash(&conflicting)?,
            };
            pin.conflicts.insert(
                range,
                CustodyConflictEvidence { alert, accepted: record.clone(), conflicting },
            );
        }
        prune_evidence(pin, Some(9))?;
        assert!(pin.conflicts.len() <= MAX_CONFLICT_RANGES);
        assert!(
            ramflux_protocol::canonical_json_bytes(&(&pin.range_records, &pin.conflicts))?.len()
                <= MAX_CONFLICT_EVIDENCE_BYTES
        );
        assert!(pin.pruned_evidence > 0);
        Ok(())
    }
}

#[cfg(test)]
mod regression_tests;
