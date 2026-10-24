// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device storage and routing are indexed by root commitment plus local device identifier.
use crate::{IdentityRegistry, mvp1_registry::IdentityDeviceRecord};
impl IdentityRegistry {
    pub(crate) fn device_storage_key(commitment: &str, device: &str) -> String {
        format!("{commitment}:{device}")
    }
    pub(crate) fn principal_device_lookup(principal: &str, device: &str) -> String {
        format!(
            "principal~{}",
            ramflux_protocol::encode_base64url(
                serde_json::to_vec(&(principal, device)).unwrap_or_default()
            )
        )
    }
    pub(crate) fn storage_key_for_record(&self, device: &IdentityDeviceRecord) -> String {
        let commitment = if device.principal_commitment.is_empty() {
            self.root_public_keys
                .get(&device.principal_id)
                .and_then(|k| ramflux_crypto::verifying_key_from_base64url(k).ok())
                .map(|k| ramflux_crypto::identity_root_commitment(&k))
                .unwrap_or_default()
        } else {
            device.principal_commitment.clone()
        };
        Self::device_storage_key(&commitment, &device.device_id)
    }
    pub(crate) fn device_record_for_principal(
        &self,
        principal: &str,
        device: &str,
    ) -> Option<&IdentityDeviceRecord> {
        let root = self.root_public_keys.get(principal)?;
        let key = ramflux_crypto::verifying_key_from_base64url(root).ok()?;
        let commitment = ramflux_crypto::identity_root_commitment(&key);
        self.devices
            .get(&Self::device_storage_key(&commitment, device))
            .or_else(|| self.devices.get(device).filter(|old| old.principal_id == principal))
    }
    pub(crate) fn device_record(&self, lookup: &str) -> Option<&IdentityDeviceRecord> {
        if let Some(encoded) = lookup.strip_prefix("principal~") {
            let bytes = ramflux_protocol::decode_base64url(encoded).ok()?;
            let (principal, device): (String, String) = serde_json::from_slice(&bytes).ok()?;
            return self.device_record_for_principal(&principal, &device);
        }
        if let Some(encoded) = lookup.strip_prefix("root~") {
            let bytes = ramflux_protocol::decode_base64url(encoded).ok()?;
            let (commitment, device): (String, String) = serde_json::from_slice(&bytes).ok()?;
            return self.devices.get(&Self::device_storage_key(&commitment, &device)).or_else(
                || self.devices.get(&device).filter(|d| d.principal_commitment == commitment),
            );
        }
        let mut candidates = self.devices.values().filter(|d| d.device_id == lookup);
        let only = candidates.next()?;
        (candidates.next().is_none() && only.branch_proof.key_binding.is_none()).then_some(only)
    }
    pub(crate) fn check_device_lookup(&self, lookup: &str) -> Result<(), crate::NodeCoreError> {
        if lookup.starts_with("root~") || lookup.starts_with("principal~") {
            return self.device_record(lookup).map(|_| ()).ok_or_else(|| {
                crate::NodeCoreError::ItestHttp("qualified device not found".into())
            });
        }
        let mut matches = self.devices.values().filter(|d| d.device_id == lookup);
        let Some(device) = matches.next() else {
            return Err(crate::NodeCoreError::ItestHttp("device not found".into()));
        };
        if matches.next().is_some() {
            return Err(crate::NodeCoreError::ItestHttp(
                "ambiguous device ID: root-qualified lookup required".into(),
            ));
        }
        if device.branch_proof.key_binding.is_some() {
            return Err(crate::NodeCoreError::ItestHttp(
                "root-bound device requires root-qualified lookup".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn record_is_revoked(&self, device: &IdentityDeviceRecord) -> bool {
        self.revoked_devices.contains(&self.storage_key_for_record(device))
            || self.revoked_devices.contains(&device.device_id)
                && self
                    .devices
                    .get(&device.device_id)
                    .is_some_and(|old| old.principal_id == device.principal_id)
    }
}
