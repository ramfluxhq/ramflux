// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only root-owned fixture authorizations; never a production migration shortcut.
use crate::{RamfluxClient, SdkError, prekey::SdkDeviceManifestResponse};
use ramflux_protocol::{DeviceKeyBinding, DeviceSetStatus, PrincipalKind, SignedDeviceSetEntry};
pub(crate) fn sign_manifest(
    root: &ramflux_crypto::IdentityRoot,
    manifest: &mut SdkDeviceManifestResponse,
    epoch: u64,
) -> Result<(), SdkError> {
    let kind = manifest
        .devices
        .first()
        .and_then(|d| d.branch_proof.key_binding.as_ref())
        .map_or(PrincipalKind::Human, |b| b.principal_kind);
    let mut entries = Vec::new();
    for device in &mut manifest.devices {
        device.branch_proof.key_binding = Some(DeviceKeyBinding {
            version: 2,
            principal_kind: kind,
            branch_signing_public_key: device.branch_public_key.clone(),
            agreement_identity_public_key: ramflux_protocol::encode_base64url(
                device.prekey_bundle.identity_key,
            ),
        });
        device.branch_proof.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_crypto::branch_proof_signing_bytes(&device.branch_proof)?,
            root.signing_key.to_bytes(),
        );
        let keys = ramflux_crypto::device_key_commitments(
            &device.branch_public_key,
            &ramflux_protocol::encode_base64url(device.prekey_bundle.identity_key),
        )?;
        entries.push(SignedDeviceSetEntry {
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
            signing_key_commitment: keys.0,
            agreement_key_commitment: keys.1,
            status: DeviceSetStatus::Active,
            revoked_at: None,
        });
    }
    manifest.signed_device_set = Some(ramflux_crypto::sign_device_set(
        root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: kind,
            device_set_epoch: epoch,
            devices: entries,
        },
    )?);
    Ok(())
}
pub(crate) fn manifest(client: &RamfluxClient) -> Result<SdkDeviceManifestResponse, SdkError> {
    let root = client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let device = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let commitment = ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
    let now = crate::prelude::now_unix_timestamp();
    let mut manifest = SdkDeviceManifestResponse {
        signed_device_set: None,
        principal_id: device.principal_id.clone(),
        principal_commitment: commitment.clone(),
        root_public_key: ramflux_protocol::encode_base64url(
            root.signing_key.verifying_key().to_bytes(),
        ),
        devices: vec![crate::prekey::SdkDeviceManifestEntry {
            principal_id: device.principal_id.clone(),
            principal_commitment: commitment,
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
            branch_public_key: ramflux_protocol::encode_base64url(
                device.signing_key.verifying_key().to_bytes(),
            ),
            target_delivery_id: device.device_id.clone(),
            branch_proof: client.authorize_current_device(
                "ramflux-node",
                vec!["device.delivery.bind".into()],
                now,
                now.saturating_add(3600),
            )?,
            prekey_bundle: client
                .load_x3dh_private_state(&client.local_device_identity(&device.device_id)?)?
                .bundle,
            branch_authorized_event_id: format!(
                "device.branch_authorized:{}:{}",
                device.device_id, device.device_epoch
            ),
        }],
    };
    sign_manifest(root, &mut manifest, 1)?;
    Ok(manifest)
}
