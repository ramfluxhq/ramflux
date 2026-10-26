// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-signed complete device sets with immutable kind and monotonic revocation evidence.
use crate::{
    CryptoError, IdentityRoot,
    identity_binding::{identifier, invalid, validate_public_keys},
};
use ed25519_dalek::{Signer, VerifyingKey};
use ramflux_protocol::{
    DeviceSetStatus, PrincipalKind, SignedDeviceSetEntry, SignedDeviceSetRecord, decode_base64url,
    encode_base64url,
};
/// Bounded local root-owned input; entries are sorted before signing.
pub struct DeviceSetSigningInput {
    pub principal_kind: PrincipalKind,
    pub device_set_epoch: u64,
    pub devices: Vec<SignedDeviceSetEntry>,
}
/// The same identity commitment used by the established node registry.
#[must_use]
pub fn identity_root_commitment(root: &VerifyingKey) -> String {
    crate::blake3_256_base64url("ramflux.identity.root_public_key.commitment.v1", &root.to_bytes())
}
/// Commit to canonical, valid device signing/agreement keys using separate domains.
/// # Errors
/// Rejects malformed or weak public keys.
pub fn device_key_commitments(
    signing: &str,
    agreement: &str,
) -> Result<(String, String), CryptoError> {
    let (signing, agreement) = validate_public_keys(signing, agreement)?;
    Ok((
        crate::blake3_256_base64url(
            ramflux_protocol::domain::DEVICE_SIGNING_KEY_COMMITMENT,
            &signing,
        ),
        crate::blake3_256_base64url(
            ramflux_protocol::domain::DEVICE_AGREEMENT_KEY_COMMITMENT,
            &agreement,
        ),
    ))
}
/// Sign a complete device set with the principal's root. Root ownership is not inferred from a node.
/// # Errors
/// Rejects invalid/duplicate entries, unsafe integers, or canonical serialization errors.
pub fn sign_device_set(
    root: &IdentityRoot,
    input: DeviceSetSigningInput,
) -> Result<SignedDeviceSetRecord, CryptoError> {
    sign_device_set_with_profile(root, input, None)
}
/// Signs v2 when a root-signed public profile is present; legacy v1 stays byte-compatible.
/// # Errors
/// Rejects invalid profiles, mismatched authority or invalid device entries.
pub fn sign_device_set_with_profile(
    root: &IdentityRoot,
    mut input: DeviceSetSigningInput,
    profile: Option<ramflux_protocol::SignedIdentityProfile>,
) -> Result<SignedDeviceSetRecord, CryptoError> {
    if let Some(profile) = &profile {
        crate::verify_identity_profile(&root.signing_key.verifying_key(), profile)?;
    }
    let domain = if profile.is_some() {
        ramflux_protocol::domain::SIGNED_DEVICE_SET_V2
    } else {
        ramflux_protocol::domain::SIGNED_DEVICE_SET
    };
    input.devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let mut record = SignedDeviceSetRecord {
        schema: domain.into(),
        version: if profile.is_some() { 2 } else { 1 },
        domain: domain.into(),
        principal_id: root.principal_id.clone(),
        principal_commitment: identity_root_commitment(&root.signing_key.verifying_key()),
        principal_kind: input.principal_kind,
        device_set_epoch: input.device_set_epoch,
        devices: input.devices,
        profile: profile.map(Box::new),
        signature: String::new(),
    };
    validate(&record)?;
    record.signature = encode_base64url(
        root.signing_key
            .sign(&ramflux_protocol::signed_device_set_signing_bytes(&record)?)
            .to_bytes(),
    );
    Ok(record)
}
/// Validate the exact root-signed record, including root commitment, ordering, kind and tombstones.
/// Callers must additionally compare it with the highest previously accepted record.
/// # Errors
/// Rejects unsigned/forged records and malformed or oversized records.
pub fn verify_signed_device_set(
    root: &VerifyingKey,
    record: &SignedDeviceSetRecord,
) -> Result<(), CryptoError> {
    validate(record)?;
    if root.is_weak() || identity_root_commitment(root) != record.principal_commitment {
        return Err(invalid("device set root mismatch"));
    }
    if let Some(profile) = &record.profile {
        crate::verify_identity_profile(root, profile)?;
    }
    crate::verify_canonical_signature(
        &ramflux_protocol::signed_device_set_signing_bytes(record)?,
        &record.signature,
        &encode_base64url(root.to_bytes()),
    )
}
/// Compare two already root-authenticated complete records. Exact retransmission is idempotent.
/// # Errors
/// Rejects epoch rollback/equivocation, kind changes, omissions, resurrection or unversioned keys.
pub fn validate_device_set_transition(
    previous: &SignedDeviceSetRecord,
    next: &SignedDeviceSetRecord,
) -> Result<(), CryptoError> {
    validate(previous)?;
    validate(next)?;
    if previous == next {
        return Ok(());
    }
    if previous.principal_id != next.principal_id
        || previous.principal_commitment != next.principal_commitment
        || previous.principal_kind != next.principal_kind
    {
        return Err(invalid("immutable principal identity or kind changed"));
    }
    if next.device_set_epoch <= previous.device_set_epoch {
        return Err(invalid("device set epoch rollback or equivocation"));
    }
    crate::identity_profile::validate_transition(
        previous.profile.as_deref(),
        next.profile.as_deref(),
    )?;
    for old in &previous.devices {
        let new = next
            .devices
            .iter()
            .find(|new| new.device_id == old.device_id)
            .ok_or_else(|| invalid("complete device set omitted a known device"))?;
        if old.status == DeviceSetStatus::Revoked && old != new {
            return Err(invalid("revoked device tombstone changed"));
        }
        let changed = old.signing_key_commitment != new.signing_key_commitment
            || old.agreement_key_commitment != new.agreement_key_commitment;
        if new.device_epoch < old.device_epoch || changed && new.device_epoch <= old.device_epoch {
            return Err(invalid("device key change requires a newer device epoch"));
        }
    }
    Ok(())
}
fn validate(record: &SignedDeviceSetRecord) -> Result<(), CryptoError> {
    let domain = match (record.version, record.profile.as_ref()) {
        (1, None) => ramflux_protocol::domain::SIGNED_DEVICE_SET,
        (2, Some(profile)) => {
            ramflux_protocol::identity_profile_signing_bytes(profile)?;
            if profile.principal_id != record.principal_id
                || profile.principal_commitment != record.principal_commitment
                || profile.kind != record.principal_kind
            {
                return Err(invalid("profile and device-set owner or kind mismatch"));
            }
            ramflux_protocol::domain::SIGNED_DEVICE_SET_V2
        }
        _ => return Err(invalid("device-set profile version mismatch")),
    };
    if record.schema != domain
        || record.domain != domain
        || record.device_set_epoch == 0
        || record.device_set_epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || record.devices.is_empty()
        || record.devices.len() > 1024
    {
        return Err(invalid("invalid device set header or count"));
    }
    identifier(&record.principal_id)?;
    digest(&record.principal_commitment)?;
    if record.devices.windows(2).any(|w| w[0].device_id >= w[1].device_id) {
        return Err(invalid("device set must be sorted and unique"));
    }
    for entry in &record.devices {
        ramflux_protocol::validate_device_name(&entry.device_id)?;
        digest(&entry.signing_key_commitment)?;
        digest(&entry.agreement_key_commitment)?;
        if entry.device_epoch == 0 || entry.device_epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
            return Err(invalid("invalid device epoch"));
        }
        match (entry.status, entry.revoked_at) {
            (DeviceSetStatus::Active, None) => {}
            (DeviceSetStatus::Revoked, Some(at))
                if at >= 0
                    && at
                        <= i64::try_from(ramflux_protocol::MAX_SAFE_JSON_INTEGER)
                            .map_err(|_| invalid("time bound"))? => {}
            _ => return Err(invalid("invalid revocation evidence")),
        }
    }
    if ramflux_protocol::signed_device_set_signing_bytes(record)?.len() > 512 * 1024 {
        return Err(invalid("device set byte budget exceeded"));
    }
    Ok(())
}
fn digest(value: &str) -> Result<(), CryptoError> {
    let bytes = decode_base64url(value)?;
    if bytes.len() != 32 || encode_base64url(bytes) != value {
        return Err(invalid("invalid key commitment"));
    }
    Ok(())
}
