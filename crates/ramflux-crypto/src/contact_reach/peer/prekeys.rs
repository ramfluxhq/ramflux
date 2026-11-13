// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public native routing and prekeys remain independently bound to current branch authority.
use super::{CryptoError, VerifiedRecord, custody, reject, wire};
use ramflux_protocol::custody::{CustodyManifest, DeviceRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) fn verify_manifest(
    payload: &wire::SnapshotPayload,
    query: &wire::Query,
    manifest: &CustodyManifest,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    let object =
        payload.manifest.as_object().ok_or_else(|| reject("peer manifest object required"))?;
    if object.keys().any(|key| {
        ![
            "custody",
            "signed_device_set",
            "principal_id",
            "principal_commitment",
            "root_public_key",
            "devices",
        ]
        .contains(&key.as_str())
    }) || object.get("signed_device_set").is_some_and(|v| !v.is_null())
        || object.get("devices").and_then(serde_json::Value::as_array).is_none_or(|v| !v.is_empty())
        || object.get("principal_id").and_then(serde_json::Value::as_str)
            != Some(authority.envelope().body.principal_id.as_str())
        || object.get("principal_commitment").and_then(serde_json::Value::as_str)
            != Some(query.account_anchor.as_str())
        || object.get("root_public_key").and_then(serde_json::Value::as_str)
            != Some(authority.envelope().body.master_certificate.body.master_public_key.as_str())
        || manifest.devices.len() > 32
    {
        return Err(reject("peer native manifest binding mismatch"));
    }
    let mut devices = BTreeSet::new();
    for device in &manifest.devices {
        let target = ramflux_protocol::qualified_device_id(
            &query.account_anchor,
            &device.device_ref.device_id,
        )?;
        if device.device_ref.account_anchor != query.account_anchor
            || device.target_delivery_id != target
            || !devices
                .insert((device.device_ref.device_id.clone(), device.device_ref.device_epoch))
        {
            return Err(reject("peer manifest target/duplicate mismatch"));
        }
        let entry = authority
            .envelope()
            .body
            .devices
            .iter()
            .find(|entry| entry.device_id == device.device_ref.device_id)
            .ok_or_else(|| reject("peer manifest branch missing"))?;
        if device.message_layer != entry.message_layer {
            return Err(reject("peer manifest layer substitution"));
        }
        verify_bundle(authority, &device.device_ref, &device.prekey_bundle, now)?;
    }
    match (&query.device_ref, &payload.prekey) {
        (None, None) => Ok(()),
        (Some(device), Some(value)) => verify_prekey_response(authority, device, value, now),
        _ => Err(reject("peer prekey request mismatch")),
    }
}
fn verify_prekey_response(
    authority: &VerifiedRecord,
    device: &DeviceRef,
    value: &serde_json::Value,
    now: u64,
) -> Result<(), CryptoError> {
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Response {
        device_id: String,
        bundle: Option<crate::PrekeyBundle>,
        principal_commitment: String,
        target_delivery_id: Option<String>,
    }
    let response: Response =
        custody::decode(&ramflux_protocol::canonical_json_bytes(value)?, 64 * 1024)?;
    let target = ramflux_protocol::qualified_device_id(&device.account_anchor, &device.device_id)?;
    if response.device_id != device.device_id
        || response.principal_commitment != device.account_anchor
        || response.target_delivery_id.as_deref() != Some(target.as_str())
    {
        return Err(reject("peer prekey response target mismatch"));
    }
    let bundle = response.bundle.ok_or_else(|| reject("peer prekey unavailable"))?;
    verify_prekey(authority, device, &bundle, now)
}
fn verify_bundle(
    authority: &VerifiedRecord,
    device: &DeviceRef,
    value: &serde_json::Value,
    now: u64,
) -> Result<(), CryptoError> {
    let bundle: crate::PrekeyBundle =
        custody::decode(&ramflux_protocol::canonical_json_bytes(value)?, 64 * 1024)?;
    verify_prekey(authority, device, &bundle, now)
}
fn verify_prekey(
    authority: &VerifiedRecord,
    device: &DeviceRef,
    bundle: &crate::PrekeyBundle,
    now: u64,
) -> Result<(), CryptoError> {
    let cert = authority.authorize(device, "message", now)?;
    if bundle.device_id != device.device_id
        || bundle.device_epoch != device.device_epoch
        || bundle.identity_commitment != authority.envelope().body.principal_id
        || bundle.device_identity_ed25519_public != cert.branch_signing_public_key
        || bundle.identity_key != bundle.device_agreement_x25519_public
        || ramflux_protocol::encode_base64url(bundle.identity_key)
            != cert.agreement_identity_public_key
        || !u64::try_from(bundle.signed_prekey_expires_at).is_ok_and(|until| until > now)
    {
        return Err(reject("peer native prekey binding mismatch"));
    }
    let key = crate::verifying_key_from_base64url(&cert.branch_signing_public_key)?;
    crate::verify_prekey_bundle(&key, bundle)
}
