// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable authenticated mode, certificate, head and denial floors.
use super::{VerifiedRecord, validate::reject};
use crate::CryptoError;
use ramflux_protocol::custody::{decode_epoch, object_hash};
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
}
/// A valid conflict must be durably recorded even though it grants no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinOutcome {
    Advanced,
    Unchanged,
    Fenced,
}
impl AuthorityPins {
    /// Copy one account's retained floor/evidence for an incremental durable update.
    #[must_use]
    pub fn for_account(&self, anchor: &str) -> Self {
        Self {
            accounts: self
                .accounts
                .get(anchor)
                .map(|pin| (anchor.into(), pin.clone()))
                .into_iter()
                .collect(),
        }
    }

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
        let body = &record.envelope().body;
        let range = decode_epoch(body.device_set_epoch)?.0;
        let certificate = object_hash(&body.master_certificate)?;
        let hash = object_hash(record.envelope())?;
        if let Some(pin) = self.accounts.get_mut(&body.account_anchor) {
            if pin.principal_id != body.principal_id || pin.principal_kind != body.principal_kind {
                return Err(reject("custody immutable identity changed"));
            }
            if pin.certificates.get(&range).is_some_and(|old| old != &certificate) {
                pin.fenced_ranges.insert(range);
                return Ok(PinOutcome::Fenced);
            }
            if body.device_set_epoch < pin.epoch {
                return Err(reject("custody epoch rollback"));
            }
            if body.device_set_epoch == pin.epoch {
                if pin.hash != hash {
                    pin.fenced_ranges.insert(range);
                    return Ok(PinOutcome::Fenced);
                }
                return Ok(if pin.fenced_ranges.contains(&range) {
                    PinOutcome::Fenced
                } else {
                    PinOutcome::Unchanged
                });
            }
            if pin.fenced_ranges.contains(&range) {
                return Ok(PinOutcome::Fenced);
            }
            validate_transition(pin, record)?;
            pin.certificates.insert(range, certificate);
            pin.epoch = body.device_set_epoch;
            pin.hash = hash;
            pin.revoked_ids.extend(record.revoked_ids().iter().cloned());
            for device in &body.devices {
                pin.devices.insert(
                    device.device_id.clone(),
                    (
                        device.device_epoch,
                        device.signing_key_commitment.clone(),
                        device.agreement_key_commitment.clone(),
                    ),
                );
            }
        } else {
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
                    devices: body
                        .devices
                        .iter()
                        .map(|d| {
                            (
                                d.device_id.clone(),
                                (
                                    d.device_epoch,
                                    d.signing_key_commitment.clone(),
                                    d.agreement_key_commitment.clone(),
                                ),
                            )
                        })
                        .collect(),
                },
            );
        }
        Ok(PinOutcome::Advanced)
    }
}

fn validate_transition(pin: &AccountPin, record: &VerifiedRecord) -> Result<(), CryptoError> {
    let body = &record.envelope().body;
    if body.devices.len() > ramflux_protocol::custody::MAX_ENROLLMENT_ROSTER
        && body.devices.iter().any(|device| {
            device.status == ramflux_protocol::DeviceSetStatus::Active
                && !pin.devices.contains_key(&device.device_id)
        })
    {
        return Err(reject("custody enrollment reserve exhausted; prioritize revocation"));
    }
    if !pin.revoked_ids.is_subset(record.revoked_ids()) {
        return Err(reject("custody revocation rollback"));
    }
    for device in &body.devices {
        if let Some((epoch, signing, agreement)) = pin.devices.get(&device.device_id)
            && (device.device_epoch < *epoch
                || (device.device_epoch == *epoch
                    && (device.signing_key_commitment != *signing
                        || device.agreement_key_commitment != *agreement)))
        {
            return Err(reject("custody branch epoch or key rollback"));
        }
    }
    for id in pin.devices.keys() {
        if !body.devices.iter().any(|d| &d.device_id == id) && !record.revoked_ids().contains(id) {
            return Err(reject("custody roster entry disappeared without revocation"));
        }
    }
    Ok(())
}
