// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Highest accepted device-set record per account anchor (revocation authority).
//!
//! `verify_record` only proves a record is authentic; it says nothing about rollback. Per
//! account anchor we keep the highest custody record accepted so far (row
//! `rf/device_set/<anchor>`, canonical I-JSON of the `Envelope<DeviceSet>`):
//!
//! * newer epoch: the custody authority pins (`AuthorityPins`, seeded with the stored record)
//!   must accept the presented record as an advance (no rollback, no fork, no key regression, no
//!   revocation rollback), then it replaces the stored one (in the same flush);
//! * equal epoch: the canonical bytes must be identical;
//! * lower epoch: allowed only when the device is present, active and has the same signing
//!   commitment in the stored record.

use ramflux_crypto::custody::{AuthorityPins, PinOutcome, VerifiedRecord, verify_record};
use ramflux_protocol::DeviceSetStatus;
use ramflux_protocol::custody::{DeviceSet, Envelope};

use crate::group::unix_now;
use crate::storage::MlsStorage;
use crate::storage::kv::MlsKv;
use crate::{MlsError, RF_LABEL_DEVICE_SET};

fn reject(what: &str) -> MlsError {
    MlsError::CredentialRejected(what.to_owned())
}

/// The stored record and its canonical bytes.
type Stored = (Envelope<DeviceSet>, Vec<u8>);

fn load<K: MlsKv>(storage: &MlsStorage<'_, K>, anchor: &str) -> Result<Option<Stored>, MlsError> {
    let Some(raw) = storage.rf_get(RF_LABEL_DEVICE_SET, anchor.as_bytes())? else {
        return Ok(None);
    };
    let record = Envelope::<DeviceSet>::from_wire_bytes(&raw)
        .map_err(|error| MlsError::Internal(format!("stored device set: {error}")))?;
    Ok(Some((record, raw.to_vec())))
}

fn canonical(record: &Envelope<DeviceSet>) -> Result<Vec<u8>, MlsError> {
    ramflux_protocol::canonical_json_bytes(record)
        .map_err(|error| MlsError::Internal(format!("device set encoding: {error}")))
}

/// Apply the authority rules to a presented, already verified record.
///
/// # Errors
/// [`MlsError::CredentialRejected`] on rollback, equivocation, a revoked device or a changed key.
pub(crate) fn authorize<K: MlsKv>(
    storage: &MlsStorage<'_, K>,
    presented: &VerifiedRecord,
    device_id: &str,
    signing_key_commitment: &str,
) -> Result<(), MlsError> {
    let record = presented.envelope();
    let anchor = record.body.account_anchor.as_str();
    let presented_bytes = canonical(record)?;
    let Some((stored, stored_bytes)) = load(storage, anchor)? else {
        storage.rf_put(RF_LABEL_DEVICE_SET, anchor.as_bytes(), &presented_bytes)?;
        return Ok(());
    };
    if record.body.device_set_epoch > stored.body.device_set_epoch {
        let stored_verified = verify_record(&stored, unix_now()?, None, None)
            .map_err(|error| MlsError::Internal(format!("stored device set: {error}")))?;
        let mut pins = AuthorityPins::default();
        pins.observe(&stored_verified)
            .map_err(|error| MlsError::Internal(format!("stored device set pin: {error}")))?;
        match pins.observe(presented) {
            Ok(PinOutcome::Advanced) => {}
            Ok(_) => return Err(reject("device set transition is a fork")),
            Err(error) => return Err(reject(&format!("device set transition: {error}"))),
        }
        storage.rf_put(RF_LABEL_DEVICE_SET, anchor.as_bytes(), &presented_bytes)?;
        return Ok(());
    }
    if record.body.device_set_epoch == stored.body.device_set_epoch {
        if stored_bytes == presented_bytes {
            return Ok(());
        }
        return Err(reject("device set equivocation at the same epoch"));
    }
    let entry = stored
        .body
        .devices
        .iter()
        .find(|entry| entry.device_id == device_id)
        .ok_or_else(|| reject("device is absent from the highest accepted device set"))?;
    if entry.status != DeviceSetStatus::Active
        || entry.signing_key_commitment != signing_key_commitment
    {
        return Err(reject("device is revoked or re-keyed in the highest accepted device set"));
    }
    Ok(())
}

/// Seed the own record at credential issuance. A stale own record never lowers the stored one.
///
/// # Errors
/// The record does not decode or storage fails.
pub(crate) fn seed_own<K: MlsKv>(
    storage: &MlsStorage<'_, K>,
    record_bytes: &[u8],
) -> Result<(), MlsError> {
    let record = Envelope::<DeviceSet>::from_wire_bytes(record_bytes)
        .map_err(|error| reject(&format!("own device set record: {error}")))?;
    let anchor = record.body.account_anchor.as_str();
    match load(storage, anchor)? {
        Some((stored, _)) if stored.body.device_set_epoch >= record.body.device_set_epoch => Ok(()),
        _ => Ok(storage.rf_put(RF_LABEL_DEVICE_SET, anchor.as_bytes(), &canonical(&record)?)?),
    }
}

/// True when the highest accepted record lists the device as revoked.
///
/// # Errors
/// Storage failure.
pub(crate) fn is_revoked<K: MlsKv>(
    storage: &MlsStorage<'_, K>,
    anchor: &str,
    device_id: &str,
) -> Result<bool, MlsError> {
    Ok(load(storage, anchor)?.is_some_and(|(record, _)| {
        record
            .body
            .devices
            .iter()
            .any(|entry| entry.device_id == device_id && entry.status == DeviceSetStatus::Revoked)
    }))
}
