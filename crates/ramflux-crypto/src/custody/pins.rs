// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable authenticated mode, certificate, head and denial floors.
use super::{VerifiedRecord, validate::reject};
use crate::CryptoError;
use ramflux_protocol::custody::{DeviceSet, Envelope, decode_epoch, object_hash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    conflicts: BTreeMap<u64, CustodyConflictEvidence>,
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
            return observe_existing(pin, record, previous, range, certificate, hash, devices);
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
                conflicts: BTreeMap::new(),
            },
        );
        Ok(PinOutcome::Advanced)
    }
    /// Return the durable first authenticated conflict pair for operator review.
    #[must_use]
    pub fn conflict_evidence(&self, anchor: &str, range: u64) -> Option<&CustodyConflictEvidence> {
        self.accounts.get(anchor)?.conflicts.get(&range)
    }
}

fn observe_existing(
    pin: &mut AccountPin,
    record: &VerifiedRecord,
    previous: Option<&Envelope<DeviceSet>>,
    range: u64,
    certificate: String,
    hash: String,
    devices: BTreeMap<String, (u64, String, String)>,
) -> Result<PinOutcome, CryptoError> {
    let body = &record.envelope().body;
    if pin.principal_id != body.principal_id || pin.principal_kind != body.principal_kind {
        return Err(reject("custody immutable identity changed"));
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
    pin.fenced_ranges.insert(range);
    if let Some(evidence) = pin.conflicts.get(&range) {
        return Ok(PinOutcome::Fenced(evidence.alert.clone()));
    }
    let accepted = pin
        .current_record
        .as_ref()
        .or(previous)
        .ok_or_else(|| reject("custody conflict evidence unavailable"))?
        .clone();
    let alert = CustodyConflictAlert {
        account_anchor: conflicting.body.account_anchor.clone(),
        range_index: range,
        kind,
        accepted_record_hash: object_hash(&accepted)?,
        conflicting_record_hash: object_hash(conflicting)?,
    };
    pin.conflicts.insert(
        range,
        CustodyConflictEvidence {
            alert: alert.clone(),
            accepted,
            conflicting: conflicting.clone(),
        },
    );
    Ok(PinOutcome::Fenced(alert))
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
