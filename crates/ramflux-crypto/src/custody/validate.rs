// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Schema, key, lease and complete-record validation before authority is pinned.
use crate::CryptoError;
use ed25519_dalek::{Signature, VerifyingKey};
use ramflux_protocol::{
    MAX_SAFE_JSON_INTEGER, PrincipalKind,
    custody::{
        BranchCertificate, CustodyKind, DeviceRef, DeviceSet, Envelope, MASTER_SCOPES,
        MAX_BRANCH_LEASE_SECONDS, MAX_RECORD_BYTES, MAX_ROSTER, MasterCertificate, MigrationState,
        decode_epoch, encode_epoch, object_hash, section_hashes, signing_bytes,
    },
    domain,
};
use serde::Serialize;

pub(super) fn reject(reason: &'static str) -> CryptoError {
    CryptoError::IdentityAuthority(reason)
}
pub(super) fn bytes(value: &str, count: usize) -> Result<Vec<u8>, CryptoError> {
    if value.len() != (count * 8).div_ceil(6) {
        return Err(reject("noncanonical custody binary length"));
    }
    let raw = ramflux_protocol::decode_base64url(value)?;
    if raw.len() != count || ramflux_protocol::encode_base64url(&raw) != value {
        return Err(reject("noncanonical custody binary encoding"));
    }
    Ok(raw)
}
pub(super) fn key(value: &str) -> Result<VerifyingKey, CryptoError> {
    let raw: [u8; 32] = bytes(value, 32)?.try_into().map_err(|_| reject("invalid custody key"))?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| reject("invalid custody key"))?;
    if key.is_weak() {
        return Err(reject("weak custody signing key"));
    }
    Ok(key)
}
pub(super) fn id(value: &str) -> Result<(), CryptoError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(reject("invalid custody identifier"));
    }
    Ok(())
}
pub(super) fn time(value: u64) -> Result<(), CryptoError> {
    if value > MAX_SAFE_JSON_INTEGER {
        return Err(reject("unsafe custody integer"));
    }
    Ok(())
}
pub(super) fn positive(value: u64) -> Result<(), CryptoError> {
    time(value)?;
    if value == 0 {
        return Err(reject("zero custody counter"));
    }
    Ok(())
}
pub(super) fn reference(value: &DeviceRef) -> Result<(), CryptoError> {
    bytes(&value.account_anchor, 32)?;
    id(&value.device_id)?;
    positive(value.device_epoch)
}
fn optional_hash(value: Option<&str>) -> Result<(), CryptoError> {
    if let Some(value) = value {
        bytes(value, 32)?;
    }
    Ok(())
}
pub(super) fn signature<T: Serialize>(
    key: &VerifyingKey,
    tag: &str,
    envelope: &Envelope<T>,
) -> Result<(), CryptoError> {
    let signature = Signature::from_slice(&bytes(&envelope.signature, 64)?)
        .map_err(|_| reject("invalid custody signature"))?;
    key.verify_strict(&signing_bytes(tag, &envelope.body)?, &signature)
        .map_err(|_| CryptoError::VerifyFailed)
}
pub(super) fn master_body(body: &MasterCertificate) -> Result<(), CryptoError> {
    if body.schema != domain::CUSTODY_MASTER_CERTIFICATE || body.version != 1 {
        return Err(reject("unsupported master certificate"));
    }
    id(&body.principal_id)?;
    bytes(&body.account_anchor, 32)?;
    bytes(&body.cert_id, 32)?;
    let master = key(&body.master_public_key)?;
    key(&body.self_signing_public_key)?;
    if body.master_public_key == body.self_signing_public_key
        || crate::identity_root_commitment(&master) != body.account_anchor
    {
        return Err(reject("custody master anchor or independent-key mismatch"));
    }
    reference(&body.primary_device_ref)?;
    time(body.issued_at)?;
    encode_epoch(body.range_index, 1)?;
    if body.scopes.iter().map(String::as_str).ne(MASTER_SCOPES)
        || body.legacy_binding_hash.is_some()
    {
        return Err(reject("born-v3 certificate requires exact scopes and no legacy binding"));
    }
    optional_hash(body.previous_certificate_hash.as_deref())?;
    match (body.principal_kind, body.custody_kind) {
        (PrincipalKind::Human, CustodyKind::LocalHuman)
            if body.primary_device_ref.account_anchor == body.account_anchor => {}
        (kind, CustodyKind::ExternalHuman)
            if kind != PrincipalKind::Human
                && body.primary_device_ref.account_anchor != body.account_anchor => {}
        _ => return Err(reject("custodian kind or primary reference mismatch")),
    }
    Ok(())
}
pub(super) fn branch_body(body: &BranchCertificate) -> Result<(), CryptoError> {
    if body.schema != domain::CUSTODY_BRANCH_CERTIFICATE || body.version != 1 {
        return Err(reject("unsupported custody branch certificate"));
    }
    bytes(&body.account_anchor, 32)?;
    bytes(&body.master_certificate_hash, 32)?;
    bytes(&body.cert_id, 32)?;
    id(&body.device_id)?;
    positive(body.device_epoch)?;
    crate::device_key_commitments(
        &body.branch_signing_public_key,
        &body.agreement_identity_public_key,
    )?;
    time(body.not_before)?;
    time(body.expires_at)?;
    let duration = body
        .expires_at
        .checked_sub(body.not_before)
        .ok_or_else(|| reject("invalid branch lease"))?;
    if duration == 0 || duration > MAX_BRANCH_LEASE_SECONDS {
        return Err(reject("branch lease exceeds 30 days"));
    }
    if body.capabilities.is_empty()
        || body.capabilities.len() > 5
        || !body.capabilities.windows(2).all(|pair| pair[0] < pair[1])
        || body
            .capabilities
            .iter()
            .any(|cap| !["call", "group", "message", "register", "sync"].contains(&cap.as_str()))
    {
        return Err(reject("invalid custody branch capabilities"));
    }
    Ok(())
}
pub(super) fn record_structure(body: &DeviceSet) -> Result<(), CryptoError> {
    if body.schema != domain::SIGNED_DEVICE_SET_V3
        || body.version != 3
        || body.origin != "new"
        || body.custody_mode != "v3"
    {
        return Err(reject("only born-v3 custody records are supported"));
    }
    if body.legacy_binding.is_some()
        || body.migration.is_some()
        || !body.delegations.is_empty()
        || !body.revoked_delegation_ids.is_empty()
    {
        return Err(reject("migration and delegation support require a later custody stage"));
    }
    let cert = &body.master_certificate.body;
    master_body(cert)?;
    signature(
        &key(&cert.master_public_key)?,
        domain::CUSTODY_MASTER_CERTIFICATE,
        &body.master_certificate,
    )?;
    let (range, _) = decode_epoch(body.device_set_epoch)?;
    if body.principal_id != cert.principal_id
        || body.account_anchor != cert.account_anchor
        || body.principal_kind != cert.principal_kind
        || range != cert.range_index
    {
        return Err(reject("custody record differs from certified authority"));
    }
    time(body.issued_at)?;
    optional_hash(body.previous_record_hash.as_deref())?;
    if body.profile.kind != body.principal_kind
        || ramflux_protocol::normalize_profile_display_name(&body.profile.display_name)?
            != body.profile.display_name
    {
        return Err(reject("invalid custody profile"));
    }
    match body.principal_kind {
        PrincipalKind::Human if body.profile.custodian.is_none() => {}
        kind if kind != PrincipalKind::Human
            && body.profile.custodian.as_ref() == Some(&cert.primary_device_ref) => {}
        _ => return Err(reject("custody profile reference mismatch")),
    }
    if body.devices.is_empty() || body.devices.len() > MAX_ROSTER {
        return Err(reject("custody roster capacity exceeded"));
    }
    roster(body)?;
    if body.section_hashes != section_hashes(body)? {
        return Err(reject("custody section hash mismatch"));
    }
    if ramflux_protocol::canonical_json_bytes(body)?.len() > MAX_RECORD_BYTES {
        return Err(reject("custody record byte budget exceeded"));
    }
    Ok(())
}

fn roster(body: &DeviceSet) -> Result<(), CryptoError> {
    let cert = &body.master_certificate.body;
    let cert_hash = object_hash(&body.master_certificate)?;
    let signer = key(&cert.self_signing_public_key)?;
    let mut previous: Option<&str> = None;
    for device in &body.devices {
        id(&device.device_id)?;
        positive(device.device_epoch)?;
        bytes(&device.signing_key_commitment, 32)?;
        bytes(&device.agreement_key_commitment, 32)?;
        if previous.is_some_and(|old| old >= device.device_id.as_str()) {
            return Err(reject("custody roster must be sorted and unique"));
        }
        previous = Some(&device.device_id);
        match (device.status, device.migration_state, device.revoked_at, &device.branch_certificate)
        {
            (
                ramflux_protocol::DeviceSetStatus::Active,
                MigrationState::Native,
                None,
                Some(branch),
            ) => {
                let b = &branch.body;
                branch_body(b)?;
                if b.account_anchor != body.account_anchor
                    || b.master_certificate_hash != cert_hash
                    || b.principal_kind != body.principal_kind
                    || b.device_id != device.device_id
                    || b.device_epoch != device.device_epoch
                    || b.branch_signing_public_key == cert.master_public_key
                    || b.branch_signing_public_key == cert.self_signing_public_key
                {
                    return Err(reject("custody branch binding mismatch"));
                }
                signature(&signer, domain::CUSTODY_BRANCH_CERTIFICATE, branch)?;
                let (signing, agreement) = crate::device_key_commitments(
                    &b.branch_signing_public_key,
                    &b.agreement_identity_public_key,
                )?;
                if signing != device.signing_key_commitment
                    || agreement != device.agreement_key_commitment
                {
                    return Err(reject("custody key commitment mismatch"));
                }
            }
            (
                ramflux_protocol::DeviceSetStatus::Revoked,
                MigrationState::Revoked,
                Some(at),
                None,
            ) => time(at)?,
            _ => return Err(reject("invalid native custody device state")),
        }
    }
    if body.principal_kind == PrincipalKind::Human
        && !body.devices.iter().any(|d| {
            d.device_id == cert.primary_device_ref.device_id
                && d.device_epoch == cert.primary_device_ref.device_epoch
        })
    {
        return Err(reject("local primary must remain represented in its roster"));
    }
    Ok(())
}
