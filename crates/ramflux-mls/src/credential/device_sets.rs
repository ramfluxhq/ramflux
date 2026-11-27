// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Highest accepted device-set record per root commitment (revocation authority).
//!
//! `verify_signed_device_set` only proves a record is root-signed; it says nothing about
//! rollback. Per root we keep the highest record accepted so far (row `rf/device_set/<root>`):
//!
//! * newer epoch: `validate_device_set_transition(stored, presented)` must pass, then the
//!   presented record replaces the stored one (in the same flush);
//! * equal epoch: the bytes must be identical;
//! * lower epoch: allowed only when the device is present, active and has the same signing
//!   commitment in the stored record.

use ramflux_protocol::{DeviceSetStatus, SignedDeviceSetRecord};

use crate::storage::MlsStorage;
use crate::storage::kv::MlsKv;
use crate::{MlsError, RF_LABEL_DEVICE_SET};

fn reject(what: &str) -> MlsError {
    MlsError::CredentialRejected(what.to_owned())
}

fn load<K: MlsKv>(
    storage: &MlsStorage<'_, K>,
    root_commitment: &str,
) -> Result<Option<(SignedDeviceSetRecord, Vec<u8>)>, MlsError> {
    let Some(raw) = storage.rf_get(RF_LABEL_DEVICE_SET, root_commitment.as_bytes())? else {
        return Ok(None);
    };
    let record = SignedDeviceSetRecord::from_wire_bytes(&raw)
        .map_err(|error| MlsError::Internal(format!("stored device set: {error}")))?;
    Ok(Some((record, raw.to_vec())))
}

/// Apply the authority rules to a presented, already root-verified record.
///
/// # Errors
/// [`MlsError::CredentialRejected`] on rollback, equivocation, a revoked device or a changed key.
pub(crate) fn authorize<K: MlsKv>(
    storage: &MlsStorage<'_, K>,
    root_commitment: &str,
    presented: &SignedDeviceSetRecord,
    presented_bytes: &[u8],
    device_id: &str,
    signing_key_commitment: &str,
) -> Result<(), MlsError> {
    let Some((stored, stored_bytes)) = load(storage, root_commitment)? else {
        storage.rf_put(RF_LABEL_DEVICE_SET, root_commitment.as_bytes(), presented_bytes)?;
        return Ok(());
    };
    if presented.device_set_epoch > stored.device_set_epoch {
        ramflux_crypto::validate_device_set_transition(&stored, presented)
            .map_err(|error| reject(&format!("device set transition: {error}")))?;
        storage.rf_put(RF_LABEL_DEVICE_SET, root_commitment.as_bytes(), presented_bytes)?;
        return Ok(());
    }
    if presented.device_set_epoch == stored.device_set_epoch {
        if stored_bytes == presented_bytes {
            return Ok(());
        }
        return Err(reject("device set equivocation at the same epoch"));
    }
    let entry = stored
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
    let record = SignedDeviceSetRecord::from_wire_bytes(record_bytes)
        .map_err(|error| reject(&format!("own device set record: {error}")))?;
    match load(storage, &record.principal_commitment)? {
        Some((stored, _)) if stored.device_set_epoch >= record.device_set_epoch => Ok(()),
        _ => Ok(storage.rf_put(
            RF_LABEL_DEVICE_SET,
            record.principal_commitment.as_bytes(),
            record_bytes,
        )?),
    }
}

/// True when the highest accepted record lists the device as revoked.
///
/// # Errors
/// Storage failure.
pub(crate) fn is_revoked<K: MlsKv>(
    storage: &MlsStorage<'_, K>,
    root_commitment: &str,
    device_id: &str,
) -> Result<bool, MlsError> {
    Ok(load(storage, root_commitment)?.is_some_and(|(record, _)| {
        record
            .devices
            .iter()
            .any(|entry| entry.device_id == device_id && entry.status == DeviceSetStatus::Revoked)
    }))
}
