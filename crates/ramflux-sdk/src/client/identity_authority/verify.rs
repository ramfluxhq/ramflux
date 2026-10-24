// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact bundle-to-branch-to-root and signed active-set verification.
use super::invalid;
use crate::{SdkError, prekey::SdkDeviceManifestResponse};
use ramflux_protocol::{DeviceKeyBinding, DeviceSetStatus};
pub(crate) fn verify_manifest(
    manifest: &SdkDeviceManifestResponse,
    expected: &str,
) -> Result<(), SdkError> {
    if manifest.devices.len() > 1024 || serde_json::to_vec(manifest)?.len() > 8 * 1024 * 1024 {
        return Err(invalid("manifest budget exceeded"));
    }
    let root = ramflux_crypto::verifying_key_from_base64url(&manifest.root_public_key)?;
    if manifest.principal_commitment != expected
        || ramflux_crypto::identity_root_commitment(&root) != expected
        || ramflux_protocol::encode_base64url(root.to_bytes()) != manifest.root_public_key
    {
        return Err(invalid("root commitment mismatch"));
    }
    let record = manifest
        .signed_device_set
        .as_ref()
        .ok_or_else(|| invalid("legacy manifest is read-only; signed device set required"))?;
    ramflux_crypto::verify_signed_device_set(&root, record)?;
    if record.principal_id != manifest.principal_id || record.principal_commitment != expected {
        return Err(invalid("principal or signed-set binding mismatch"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for device in &manifest.devices {
        if !seen.insert(&device.device_id) {
            return Err(invalid("duplicate manifest device"));
        }
        let bundle = &device.prekey_bundle;
        if device.principal_id != manifest.principal_id
            || device.principal_commitment != expected
            || device.branch_proof.principal_id != manifest.principal_id
            || device.branch_proof.device_id != device.device_id
            || device.branch_proof.device_epoch != device.device_epoch
            || bundle.identity_commitment != manifest.principal_id
            || bundle.device_id != device.device_id
            || bundle.device_epoch != device.device_epoch
            || bundle.device_identity_ed25519_public != device.branch_public_key
            || bundle.device_agreement_x25519_public != bundle.identity_key
        {
            return Err(invalid("device or bundle binding mismatch"));
        }
        let binding = DeviceKeyBinding {
            version: 2,
            principal_kind: record.principal_kind,
            branch_signing_public_key: device.branch_public_key.clone(),
            agreement_identity_public_key: ramflux_protocol::encode_base64url(bundle.identity_key),
        };
        ramflux_crypto::verify_root_bound_branch_proof(
            &root,
            &device.branch_proof,
            &binding,
            "ramflux-node",
            "device.delivery.bind",
            crate::prelude::now_unix_timestamp(),
        )?;
        let keys = ramflux_crypto::device_key_commitments(
            &binding.branch_signing_public_key,
            &binding.agreement_identity_public_key,
        )?;
        if !record.devices.iter().any(|entry| {
            entry.device_id == device.device_id
                && entry.status == DeviceSetStatus::Active
                && entry.device_epoch == device.device_epoch
                && entry.signing_key_commitment == keys.0
                && entry.agreement_key_commitment == keys.1
        }) {
            return Err(invalid("device absent from active signed set"));
        }
        let key = ramflux_crypto::verifying_key_from_base64url(&device.branch_public_key)?;
        ramflux_crypto::verify_prekey_bundle(&key, bundle)?;
    }
    // An empty ready-device array is valid, including a fully revoked root. Omission alone
    // never means revocation: only the complete signed record can authorize retirement.
    Ok(())
}
