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
    verify_manifest_authority(manifest, expected)?;
    let root = ramflux_crypto::verifying_key_from_base64url(&manifest.root_public_key)?;
    let record =
        manifest.signed_device_set.as_ref().ok_or_else(|| invalid("missing signed set"))?;
    let mut seen = std::collections::BTreeSet::new();
    for device in &manifest.devices {
        // Authority above authenticates this complete immutable set once. Keep root-scoped
        // duplicate detection here; active membership and exact keys are still checked below.
        if !record.devices.iter().any(|entry| entry.device_id == device.device_id) {
            return Err(ramflux_crypto::CryptoError::IdentityAuthority(
                "device absent from signed set",
            )
            .into());
        }
        let address = ramflux_protocol::qualified_device_id(expected, &device.device_id)
            .map_err(ramflux_crypto::CryptoError::from)?;
        if !seen.insert(address) {
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
        ramflux_crypto::verify_root_bound_key_authorization(
            &root,
            &device.branch_proof,
            &binding,
            "ramflux-node",
            "device.delivery.bind",
            // The current signed set grants durable authority; authenticate this historical
            // registration artifact at issuance rather than using its clock as a lookup lease.
            device.branch_proof.issued_at,
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

pub(crate) fn ready_manifest(
    mut manifest: SdkDeviceManifestResponse,
    now: i64,
) -> SdkDeviceManifestResponse {
    manifest.devices.retain(|device| {
        ramflux_crypto::branch_proof_material_is_ready(device.branch_proof.issued_at, now)
    });
    manifest
}

pub(crate) fn verify_manifest_authority(
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
    Ok(())
}

impl crate::RamfluxClient {
    pub(crate) fn require_current_device_authorization(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        // Registration-proof expiry cannot retire a device authorized by the latest signed set.
        self.require_cached_root_authority(identity)
    }
    pub(crate) fn verify_root_bound_prekey(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
        bundle: &ramflux_crypto::PrekeyBundle,
    ) -> Result<(), SdkError> {
        let remote = identity.storage_key();
        let record = {
            self.require_cached_root_authority(identity)?;
            self.account_db()?
                .client_record("device", remote)?
                .ok_or_else(|| invalid("recipient missing"))?
        };
        self.require_current_device_authorization(identity)?;
        let identity: [u8; 32] = serde_json::from_value(
            record
                .get("x25519_identity_public")
                .cloned()
                .ok_or_else(|| invalid("recipient identity missing"))?,
        )?;
        if bundle.device_id != super::device_namespace::wire_device_id(remote)?
            || bundle.identity_key != identity
            || bundle.device_agreement_x25519_public != identity
            || record["device_epoch"] != bundle.device_epoch
            || record["principal_id"] != bundle.identity_commitment
            || record["signing_public_key"] != bundle.device_identity_ed25519_public
        {
            return Err(invalid("recipient prekey differs from verified device identity"));
        }
        let key = record
            .get("signing_public_key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("recipient signing key missing"))?;
        ramflux_crypto::verify_prekey_bundle(
            &ramflux_crypto::verifying_key_from_base64url(key)?,
            bundle,
        )?;
        if bundle.signed_prekey_expires_at > 0
            && bundle.signed_prekey_expires_at <= crate::time::now_unix_timestamp()
        {
            return Err(invalid("recipient signed prekey expired"));
        }
        Ok(())
    }
}
