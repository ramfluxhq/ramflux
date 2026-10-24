// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated device references at the registry's wire and persistence boundaries.
use crate::{IdentityRegistry, mvp1_registry::IdentityDeviceRecord};
use ramflux_crypto::RootQualifiedDeviceRef;
impl IdentityRegistry {
    pub(crate) fn device_storage_key(device: &RootQualifiedDeviceRef) -> String {
        format!("{}:{}", device.root_commitment(), device.device_id())
    }
    pub(crate) fn principal_device_lookup(principal: &str, device: &str) -> String {
        format!(
            "principal~{}",
            ramflux_protocol::encode_base64url(
                serde_json::to_vec(&(principal, device)).unwrap_or_default()
            )
        )
    }
    pub(crate) fn device_identity_for_root(
        &self,
        root: &str,
        name: &str,
    ) -> Option<RootQualifiedDeviceRef> {
        let public = ramflux_crypto::verifying_key_from_base64url(
            self.root_public_keys_by_commitment.get(root)?,
        )
        .ok()?;
        let record = self.signed_device_sets.get(root)?;
        RootQualifiedDeviceRef::from_signed_device_set(&public, record, name).ok()
    }
    pub(crate) fn device_identity_for_principal(
        &self,
        principal: &str,
        name: &str,
    ) -> Option<RootQualifiedDeviceRef> {
        let public =
            ramflux_crypto::verifying_key_from_base64url(self.root_public_keys.get(principal)?)
                .ok()?;
        let root = ramflux_crypto::identity_root_commitment(&public);
        let device = self.device_identity_for_root(&root, name)?;
        (self.signed_device_sets.get(&root)?.principal_id == principal).then_some(device)
    }
    pub(crate) fn device_identity_for_session(
        &self,
        session: &crate::SessionDescriptor,
    ) -> Option<RootQualifiedDeviceRef> {
        let mut records = self.devices.values().filter(|record| {
            record.target_delivery_id == session.target_delivery_id
                && record.device_id == session.device_id
                && record.device_epoch == session.device_epoch
        });
        let record = records.next()?;
        if records.next().is_some() {
            return None;
        }
        self.device_identity_for_root(&record.principal_commitment, &record.device_id)
    }
    /// Parse an external selector; an unqualified name never selects authenticated authority.
    pub(crate) fn resolve_device_selector(&self, selector: &str) -> Option<RootQualifiedDeviceRef> {
        if let Some(encoded) = selector.strip_prefix("principal~") {
            let bytes = ramflux_protocol::decode_base64url(encoded).ok()?;
            let (principal, name): (String, String) = serde_json::from_slice(&bytes).ok()?;
            return self.device_identity_for_principal(&principal, &name);
        }
        let (root, name) = ramflux_protocol::parse_qualified_device_id(selector).ok()??;
        self.device_identity_for_root(&root, &name)
    }
    pub(crate) fn storage_key_for_record(&self, record: &IdentityDeviceRecord) -> Option<String> {
        Some(Self::device_storage_key(
            &self.device_identity_for_root(&record.principal_commitment, &record.device_id)?,
        ))
    }
    pub(crate) fn device_record_for_principal(
        &self,
        principal: &str,
        name: &str,
    ) -> Option<&IdentityDeviceRecord> {
        self.device_record(&self.device_identity_for_principal(principal, name)?)
    }
    pub(crate) fn device_record(
        &self,
        device: &RootQualifiedDeviceRef,
    ) -> Option<&IdentityDeviceRecord> {
        self.devices
            .get(&Self::device_storage_key(device))
            .filter(|r| {
                r.principal_commitment == device.root_commitment()
                    && r.device_id == device.device_id()
            })
            .or_else(|| self.legacy_device_record(device))
    }
    pub(crate) fn legacy_device_record(
        &self,
        device: &RootQualifiedDeviceRef,
    ) -> Option<&IdentityDeviceRecord> {
        self.devices.get(device.device_id()).filter(|old| {
            old.principal_commitment == device.root_commitment()
                && old.device_id == device.device_id()
        })
    }
    pub(crate) fn legacy_remove_device_metadata(&mut self, identity: &RootQualifiedDeviceRef) {
        if self.legacy_device_record(identity).is_some() {
            self.devices.remove(identity.device_id());
            self.prekey_bundles.remove(identity.device_id());
        }
    }
    pub(crate) fn legacy_prekey_bundle(
        &self,
        identity: &RootQualifiedDeviceRef,
    ) -> Option<&ramflux_crypto::PrekeyBundle> {
        self.legacy_device_record(identity)?;
        self.prekey_bundles.get(identity.device_id())
    }
    pub(crate) fn record_is_revoked(&self, device: &IdentityDeviceRecord) -> bool {
        self.storage_key_for_record(device).is_none_or(|key| self.revoked_devices.contains(&key))
            || self.legacy_record_is_revoked(device)
    }
    fn legacy_record_is_revoked(&self, device: &IdentityDeviceRecord) -> bool {
        self.revoked_devices.contains(&device.device_id)
            && self.devices.get(&device.device_id).is_some_and(|old| {
                old.principal_commitment == device.principal_commitment
                    && !old.principal_commitment.is_empty()
            })
    }
}
