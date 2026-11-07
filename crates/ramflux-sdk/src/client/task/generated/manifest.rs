// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native directory documents retain canonical bytes and their native authority checks.
use super::{g, invalid};
use crate::{
    RamfluxClient, SdkError,
    prekey::{SdkDeviceManifestEntry, SdkDeviceManifestResponse},
};
use prost::Message as _;
use serde::{Serialize, de::DeserializeOwned};

impl RamfluxClient {
    /// Map all native manifest fields, retaining canonical signed native documents.
    /// Verifies against existing trusted account material without importing keys.
    /// # Errors
    /// Rejects invalid native authority, inconsistent projections or delivery caps.
    pub fn encode_generated_task_manifest(
        &self,
        native: &SdkDeviceManifestResponse,
    ) -> Result<Vec<u8>, SdkError> {
        if native.custody.is_none()
            && native.devices.iter().any(|device| device.message_layer.is_some())
        {
            return Err(invalid("message-layer declaration requires native custody evidence"));
        }
        let generated = g::NativeDeviceManifest {
            custody: native
                .custody
                .as_ref()
                .map(|value| {
                    Ok::<_, SdkError>(g::NativeCustodyManifest {
                        canonical: ramflux_protocol::canonical_json_bytes(value)?,
                    })
                })
                .transpose()?,
            signed_device_set: native
                .signed_device_set
                .as_ref()
                .map(|value| {
                    Ok::<_, SdkError>(g::NativeSignedDeviceSet {
                        canonical: ramflux_protocol::canonical_json_bytes(value)?,
                    })
                })
                .transpose()?,
            principal_id: native.principal_id.clone(),
            principal_commitment: native.principal_commitment.clone(),
            root_public_key: native.root_public_key.clone(),
            devices: native
                .devices
                .iter()
                .map(|device| {
                    Ok(g::ManifestDevice {
                        principal_id: device.principal_id.clone(),
                        principal_commitment: device.principal_commitment.clone(),
                        device_id: device.device_id.clone(),
                        device_epoch: device.device_epoch,
                        branch_public_key: device.branch_public_key.clone(),
                        target_delivery_id: device.target_delivery_id.clone(),
                        branch_proof: device
                            .branch_proof
                            .as_ref()
                            .map(|value| {
                                Ok::<_, SdkError>(g::NativeBranchProof {
                                    canonical: ramflux_protocol::canonical_json_bytes(value)?,
                                })
                            })
                            .transpose()?,
                        prekey_bundle: Some(g::NativePrekeyBundle {
                            canonical: ramflux_protocol::canonical_json_bytes(
                                &device.prekey_bundle,
                            )?,
                        }),
                        branch_authorized_event_id: device.branch_authorized_event_id.clone(),
                    })
                })
                .collect::<Result<Vec<_>, SdkError>>()?,
        };
        let bytes = generated.encode_to_vec();
        self.decode_generated_task_manifest(&bytes, &native.principal_id)?;
        Ok(bytes)
    }

    /// Decode canonical generated directory fields and verify unchanged native
    /// evidence against the existing trusted root. Never installs supplied keys.
    /// # Errors
    /// Rejects noncanonical/unsupported bytes, wrong principal/root, invalid native
    /// signatures, mixed custody projections, missing bundles or delivery caps.
    pub fn decode_generated_task_manifest(
        &self,
        bytes: &[u8],
        expected_principal: &str,
    ) -> Result<SdkDeviceManifestResponse, SdkError> {
        super::super::check_delivery_size(bytes.len())?;
        if g::validation::scan_message("NativeDeviceManifest", bytes, g::registry::COMPILED_LAYER)
            .map_err(|_| invalid("noncanonical generated task manifest"))?
            != g::validation::ScanOutcome::Supported
        {
            return Err(invalid("unsupported generated task manifest"));
        }
        let generated = g::NativeDeviceManifest::decode(bytes)
            .map_err(|_| invalid("invalid generated task manifest"))?;
        self.check_generated_task_manifest(&generated, expected_principal)
    }

    pub(super) fn check_generated_task_manifest(
        &self,
        manifest: &g::NativeDeviceManifest,
        expected_principal: &str,
    ) -> Result<SdkDeviceManifestResponse, SdkError> {
        if manifest.principal_id != expected_principal {
            return Err(invalid("task manifest principal mismatch"));
        }
        let native_custody = manifest
            .custody
            .as_ref()
            .map(|value| canonical::<ramflux_protocol::custody::CustodyManifest>(&value.canonical))
            .transpose()?;
        let native = SdkDeviceManifestResponse {
            custody: manifest
                .custody
                .as_ref()
                .map(|value| canonical(&value.canonical).map(Box::new))
                .transpose()?,
            signed_device_set: manifest
                .signed_device_set
                .as_ref()
                .map(|value| canonical(&value.canonical))
                .transpose()?,
            principal_id: manifest.principal_id.clone(),
            principal_commitment: manifest.principal_commitment.clone(),
            root_public_key: manifest.root_public_key.clone(),
            devices: manifest
                .devices
                .iter()
                .map(|device| {
                    Ok(SdkDeviceManifestEntry {
                        principal_id: device.principal_id.clone(),
                        principal_commitment: device.principal_commitment.clone(),
                        device_id: device.device_id.clone(),
                        device_epoch: device.device_epoch,
                        branch_public_key: device.branch_public_key.clone(),
                        target_delivery_id: device.target_delivery_id.clone(),
                        message_layer: native_custody.as_ref().and_then(|custody| {
                            custody
                                .publication
                                .record
                                .body
                                .devices
                                .iter()
                                .find(|native| native.device_id == device.device_id)
                                .and_then(|native| native.message_layer.clone())
                        }),
                        branch_proof: device
                            .branch_proof
                            .as_ref()
                            .map(|value| canonical(&value.canonical))
                            .transpose()?,
                        prekey_bundle: canonical(
                            &device
                                .prekey_bundle
                                .as_ref()
                                .ok_or_else(|| invalid("task manifest prekey bundle missing"))?
                                .canonical,
                        )?,
                        branch_authorized_event_id: device.branch_authorized_event_id.clone(),
                    })
                })
                .collect::<Result<Vec<_>, SdkError>>()?,
        };
        // The native deserializer owns mixed custody/legacy projection consistency.
        let native: SdkDeviceManifestResponse =
            serde_json::from_value(serde_json::to_value(native)?)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let commitment = if native.principal_id == local.principal_id {
            self.surface_local_root_commitment()?
        } else {
            self.account_db()?
                .client_record("identity", &native.principal_id)?
                .and_then(|value| value["contact_identity_commitment"].as_str().map(str::to_owned))
                .ok_or_else(|| invalid("task manifest has no trusted principal commitment"))?
        };
        crate::client::contact::verify_device_manifest(&native, &commitment)?;
        Ok(native)
    }
}

fn canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, SdkError> {
    let value: T = ramflux_protocol::parse_i_json(bytes)?;
    if ramflux_protocol::canonical_json_bytes(&value)? != bytes {
        return Err(invalid("noncanonical native task manifest document"));
    }
    Ok(value)
}
