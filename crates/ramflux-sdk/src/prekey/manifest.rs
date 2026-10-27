// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Directory material view retaining the complete native signed authority.
use crate::SdkError;
use ramflux_crypto::BranchProofDocument;
use ramflux_protocol::custody::{CustodyManifest, decode, object_hash};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkDeviceManifestEntry {
    pub(crate) principal_id: String,
    pub(crate) principal_commitment: String,
    pub(crate) device_id: String,
    pub(crate) device_epoch: u64,
    pub(crate) branch_public_key: String,
    pub(crate) target_delivery_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) branch_proof: Option<BranchProofDocument>,
    pub(crate) prekey_bundle: ramflux_crypto::PrekeyBundle,
    pub(crate) branch_authorized_event_id: String,
}
impl SdkDeviceManifestEntry {
    #[cfg(test)]
    pub(crate) fn legacy_proof_mut(&mut self) -> Result<&mut BranchProofDocument, SdkError> {
        self.branch_proof
            .as_mut()
            .ok_or_else(|| SdkError::LocalBus("legacy fixture proof missing".into()))
    }
    pub(crate) fn legacy_proof(&self) -> Result<&BranchProofDocument, SdkError> {
        self.branch_proof.as_ref().ok_or_else(|| {
            SdkError::LocalBus("legacy branch proof unavailable for native device".into())
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SdkDeviceManifestResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) custody: Option<Box<CustodyManifest>>,
    #[serde(default)]
    pub(crate) signed_device_set: Option<ramflux_protocol::SignedDeviceSetRecord>,
    pub(crate) principal_id: String,
    pub(crate) principal_commitment: String,
    pub(crate) root_public_key: String,
    pub(crate) devices: Vec<SdkDeviceManifestEntry>,
}
#[derive(Deserialize)]
struct Wire {
    #[serde(default)]
    custody: Option<Value>,
    #[serde(default)]
    signed_device_set: Option<ramflux_protocol::SignedDeviceSetRecord>,
    principal_id: String,
    principal_commitment: String,
    root_public_key: String,
    devices: Vec<SdkDeviceManifestEntry>,
}
impl SdkDeviceManifestResponse {
    pub(crate) fn from_native(native: CustodyManifest) -> Result<Self, SdkError> {
        let body = &native.publication.record.body;
        let mut devices = Vec::with_capacity(native.devices.len());
        for device in &native.devices {
            let certificate = body
                .devices
                .iter()
                .find(|entry| entry.device_id == device.device_ref.device_id)
                .and_then(|entry| entry.branch_certificate.as_ref())
                .ok_or_else(|| {
                    SdkError::LocalBus("native directory branch certificate missing".into())
                })?;
            let bundle =
                decode(&ramflux_protocol::canonical_json_bytes(&device.prekey_bundle)?, 64 * 1024)?;
            devices.push(SdkDeviceManifestEntry {
                principal_id: body.principal_id.clone(),
                principal_commitment: body.account_anchor.clone(),
                device_id: device.device_ref.device_id.clone(),
                device_epoch: device.device_ref.device_epoch,
                branch_public_key: certificate.body.branch_signing_public_key.clone(),
                target_delivery_id: device.target_delivery_id.clone(),
                branch_proof: None,
                prekey_bundle: bundle,
                branch_authorized_event_id: object_hash(certificate)?,
            });
        }
        Ok(Self {
            principal_id: body.principal_id.clone(),
            principal_commitment: body.account_anchor.clone(),
            root_public_key: body.master_certificate.body.master_public_key.clone(),
            signed_device_set: None,
            custody: Some(Box::new(native)),
            devices,
        })
    }
}
impl<'de> Deserialize<'de> for SdkDeviceManifestResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let raw = Value::deserialize(deserializer)?;
        if raw.get("publication").is_some() {
            let bytes = ramflux_protocol::canonical_json_bytes(&raw).map_err(D::Error::custom)?;
            let native = decode(&bytes, ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES)
                .map_err(D::Error::custom)?;
            return Self::from_native(native).map_err(D::Error::custom);
        }
        let wire: Wire = serde_json::from_value(raw).map_err(D::Error::custom)?;
        if let Some(native) = wire.custody {
            let bytes =
                ramflux_protocol::canonical_json_bytes(&native).map_err(D::Error::custom)?;
            let native = decode(&bytes, ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES)
                .map_err(D::Error::custom)?;
            let projected = Self::from_native(native).map_err(D::Error::custom)?;
            if wire.signed_device_set.is_some()
                || wire.principal_id != projected.principal_id
                || wire.principal_commitment != projected.principal_commitment
                || wire.root_public_key != projected.root_public_key
                || (!wire.devices.is_empty() && wire.devices != projected.devices)
            {
                return Err(D::Error::custom("mixed or inconsistent native directory evidence"));
            }
            return Ok(projected);
        }
        Ok(Self {
            custody: None,
            signed_device_set: wire.signed_device_set,
            principal_id: wire.principal_id,
            principal_commitment: wire.principal_commitment,
            root_public_key: wire.root_public_key,
            devices: wire.devices,
        })
    }
}
