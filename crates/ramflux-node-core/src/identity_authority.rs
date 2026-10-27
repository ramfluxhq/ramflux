// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-authorized registry transitions and exact key-chain validation; no SDK policy here.
use crate::mvp1_registry::IdentityDeviceRecord;
use crate::{IdentityRegisterRequest, IdentityRegistry, NodeCoreError};
use ramflux_protocol::{DeviceKeyBinding, DeviceSetStatus, SignedDeviceSetRecord};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSetPublishRequest {
    pub root_public_key: String,
    pub record: SignedDeviceSetRecord,
}
impl DeviceSetPublishRequest {
    /// Verify signature and root commitment without accessing registry state.
    /// # Errors
    /// Rejects malformed, forged or oversized signed records.
    pub fn verify_signature(&self) -> Result<(), NodeCoreError> {
        let root = ramflux_crypto::verifying_key_from_base64url(&self.root_public_key)
            .map_err(|e| crypto(&e))?;
        ramflux_crypto::verify_signed_device_set(&root, &self.record).map_err(|e| crypto(&e))
    }
}
fn reject(reason: &str) -> NodeCoreError {
    NodeCoreError::ItestHttp(reason.into())
}
fn crypto(error: &ramflux_crypto::CryptoError) -> NodeCoreError {
    reject(&error.to_string())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IdentityAuthorityFence {
    pub(crate) principal_kind: ramflux_protocol::PrincipalKind,
    pub(crate) deleted: bool,
}
impl IdentityRegistry {
    pub(crate) fn exact_signed_device_set(
        &self,
        request: &DeviceSetPublishRequest,
    ) -> Option<&SignedDeviceSetRecord> {
        let stored = self.signed_device_sets.get(&request.record.principal_commitment)?;
        (self.root_public_keys_by_commitment.get(&request.record.principal_commitment)
            == Some(&request.root_public_key)
            && *stored == request.record)
            .then_some(stored)
    }
    pub(crate) fn require_pinned_publication_root(
        &self,
        request: &DeviceSetPublishRequest,
    ) -> Result<(), NodeCoreError> {
        if !self.custody.permits_legacy(&request.record.principal_commitment) {
            return Err(reject("custody anchor cannot use legacy publication"));
        }
        if self.root_public_keys_by_commitment.get(&request.record.principal_commitment)
            != Some(&request.root_public_key)
        {
            return Err(reject("publication root is not enrolled"));
        }
        Ok(())
    }
    pub(crate) fn validate_publication_revision(
        &self,
        request: &DeviceSetPublishRequest,
    ) -> Result<(), NodeCoreError> {
        if let Some(old) = self.signed_device_sets.get(&request.record.principal_commitment) {
            ramflux_crypto::validate_device_set_transition(old, &request.record)
                .map_err(|e| crypto(&e))?;
        }
        Ok(())
    }
    /// Publish a verified full record as-is; identical retransmission is idempotent.
    /// # Errors
    /// Rejects unsigned, regressed, conflicting or unauthorized identity/device changes.
    pub fn publish_signed_device_set(
        &mut self,
        request: &DeviceSetPublishRequest,
    ) -> Result<(), NodeCoreError> {
        if !self.custody.permits_legacy(&request.record.principal_commitment) {
            return Err(reject("custody anchor cannot use legacy publication"));
        }
        if self.exact_signed_device_set(request).is_some() {
            return Ok(());
        }
        if !self.root_public_keys_by_commitment.contains_key(&request.record.principal_commitment) {
            return Err(reject("initial signed device set requires identity enrollment"));
        }
        self.apply_signed_device_set(request)
    }
    fn apply_signed_device_set(
        &mut self,
        request: &DeviceSetPublishRequest,
    ) -> Result<(), NodeCoreError> {
        let root = ramflux_crypto::verifying_key_from_base64url(&request.root_public_key)
            .map_err(|error| crypto(&error))?;
        ramflux_crypto::verify_signed_device_set(&root, &request.record)
            .map_err(|error| crypto(&error))?;
        let next = &request.record;
        if self
            .identity_authority_fences
            .get(&next.principal_commitment)
            .is_some_and(|fence| fence.deleted || fence.principal_kind != next.principal_kind)
        {
            return Err(reject("identity was deleted or its immutable kind changed"));
        }
        if self
            .root_public_keys_by_commitment
            .get(&next.principal_commitment)
            .is_some_and(|old| old != &request.root_public_key)
        {
            return Err(reject("root commitment is already bound to another key"));
        }
        if let Some(previous) = self.signed_device_sets.get(&next.principal_commitment) {
            ramflux_crypto::validate_device_set_transition(previous, next)
                .map_err(|error| crypto(&error))?;
        }
        self.validate_set_ownership(next, &request.root_public_key)?;
        let public = ramflux_crypto::verifying_key_from_base64url(&request.root_public_key)
            .map_err(|e| crypto(&e))?;
        for entry in &next.devices {
            let identity = ramflux_crypto::RootQualifiedDeviceRef::from_signed_device_set(
                &public,
                next,
                &entry.device_id,
            )
            .map_err(|e| crypto(&e))?;
            let changed = self
                .device_record(&identity)
                .is_some_and(|device| !Self::device_matches_entry(device, entry));
            if entry.status == DeviceSetStatus::Revoked {
                self.revoked_devices.insert(Self::device_storage_key(&identity));
            }
            if changed || entry.status == DeviceSetStatus::Revoked {
                self.prekey_bundles.remove(&Self::device_storage_key(&identity));
                self.legacy_remove_device_metadata(&identity);
            }
        }
        self.root_public_keys
            .entry(next.principal_id.clone())
            .or_insert_with(|| request.root_public_key.clone());
        self.root_public_keys_by_commitment
            .insert(next.principal_commitment.clone(), request.root_public_key.clone());
        self.identity_authority_fences.insert(
            next.principal_commitment.clone(),
            IdentityAuthorityFence { principal_kind: next.principal_kind, deleted: false },
        );
        self.signed_device_sets.insert(next.principal_commitment.clone(), next.clone());
        Ok(())
    }
    fn validate_set_ownership(
        &self,
        next: &SignedDeviceSetRecord,
        public: &str,
    ) -> Result<(), NodeCoreError> {
        let public =
            ramflux_crypto::verifying_key_from_base64url(public).map_err(|e| crypto(&e))?;
        for entry in &next.devices {
            let identity = ramflux_crypto::RootQualifiedDeviceRef::from_signed_device_set(
                &public,
                next,
                &entry.device_id,
            )
            .map_err(|e| crypto(&e))?;
            if let Some(device) = self.device_record(&identity) {
                if device.principal_id != next.principal_id
                    || (!device.principal_commitment.is_empty()
                        && device.principal_commitment != next.principal_commitment)
                {
                    return Err(reject("device is already owned by another principal"));
                }
                let old_signing =
                    ramflux_crypto::verifying_key_from_base64url(&device.branch_public_key)
                        .map_err(|error| crypto(&error))?;
                let signing_changed = ramflux_crypto::blake3_256_base64url(
                    ramflux_protocol::domain::DEVICE_SIGNING_KEY_COMMITMENT,
                    &old_signing.to_bytes(),
                ) != entry.signing_key_commitment;
                let agreement = device
                    .branch_proof
                    .key_binding
                    .as_ref()
                    .map(|binding| binding.agreement_identity_public_key.clone())
                    .or_else(|| {
                        self.legacy_prekey_bundle(&identity)
                            .map(|bundle| ramflux_protocol::encode_base64url(bundle.identity_key))
                    });
                let agreement_changed = agreement
                    .map(|agreement| {
                        ramflux_crypto::device_key_commitments(
                            &device.branch_public_key,
                            &agreement,
                        )
                    })
                    .transpose()
                    .map_err(|error| crypto(&error))?
                    .is_some_and(|(_, commitment)| commitment != entry.agreement_key_commitment);
                if entry.device_epoch < device.device_epoch
                    || (signing_changed || agreement_changed)
                        && entry.device_epoch <= device.device_epoch
                {
                    return Err(reject("device key rotation requires a newer device epoch"));
                }
            }
            if self.revoked_devices.contains(&Self::device_storage_key(&identity))
                && entry.status != DeviceSetStatus::Revoked
            {
                return Err(reject("revoked device cannot be resurrected"));
            }
        }
        for device in self
            .devices
            .values()
            .filter(|device| device.principal_commitment == next.principal_commitment)
        {
            if device.principal_id != next.principal_id
                || !next.devices.iter().any(|entry| entry.device_id == device.device_id)
            {
                return Err(reject("device-set migration omitted an existing device"));
            }
        }
        Ok(())
    }
    pub(crate) fn authorize_root_bound_registration(
        &mut self,
        request: &IdentityRegisterRequest,
    ) -> Result<(), NodeCoreError> {
        if !self.custody.permits_legacy(&request.principal_commitment) {
            return Err(reject("custody anchor cannot use legacy registration"));
        }
        let binding = request.proof.key_binding.as_ref().ok_or_else(|| {
            reject("legacy branch proof is read-only; root-bound authorization required")
        })?;
        let root = ramflux_crypto::verifying_key_from_base64url(&request.root_public_key).map_err(
            |error| NodeCoreError::ItestHttp(format!("registration branch authorization: {error}")),
        )?;
        let expected = DeviceKeyBinding {
            version: 2,
            principal_kind: binding.principal_kind,
            branch_signing_public_key: request.branch_public_key.clone(),
            agreement_identity_public_key: binding.agreement_identity_public_key.clone(),
        };
        ramflux_crypto::verify_root_bound_branch_proof(
            &root,
            &request.proof,
            &expected,
            crate::IDENTITY_BIND_AUDIENCE,
            crate::IDENTITY_BIND_CAPABILITY,
            request.now,
        )
        .map_err(|error| crypto(&error))?;
        if request.principal_commitment != ramflux_crypto::identity_root_commitment(&root) {
            return Err(reject("root-bound registration commitment mismatch"));
        }
        self.check_registration_root_ownership(request)?;
        if let Some(record) = &request.device_set {
            self.apply_signed_device_set(&DeviceSetPublishRequest {
                root_public_key: request.root_public_key.clone(),
                record: record.clone(),
            })
            .map_err(|error| {
                NodeCoreError::ItestHttp(format!("registration device set: {error}"))
            })?;
        }
        let set = self
            .signed_device_sets
            .get(&request.principal_commitment)
            .ok_or_else(|| reject("root-signed device set required"))?;
        let keys = ramflux_crypto::device_key_commitments(
            &request.branch_public_key,
            &binding.agreement_identity_public_key,
        )
        .map_err(|error| crypto(&error))?;
        if set.principal_id != request.proof.principal_id
            || set.principal_kind != binding.principal_kind
            || !set.devices.iter().any(|entry| {
                entry.device_id == request.proof.device_id
                    && entry.device_epoch == request.proof.device_epoch
                    && entry.status == DeviceSetStatus::Active
                    && entry.signing_key_commitment == keys.0
                    && entry.agreement_key_commitment == keys.1
            })
        {
            return Err(reject(
                "registration keys or kind differ from the active signed device set",
            ));
        }
        Ok(())
    }
    pub(crate) fn authorize_bound_prekey(
        &self,
        device: &IdentityDeviceRecord,
        bundle: &ramflux_crypto::PrekeyBundle,
    ) -> Result<(), NodeCoreError> {
        let binding = device.branch_proof.key_binding.as_ref().ok_or_else(|| {
            reject("legacy registration is read-only; upgrade before publishing keys")
        })?;
        let agreement = ramflux_protocol::decode_base64url(&binding.agreement_identity_public_key)
            .map_err(|_| reject("invalid root-bound agreement key"))?;
        if !self.device_record_is_usable(device)
            || bundle.device_id != device.device_id
            || bundle.device_epoch != device.device_epoch
            || bundle.device_identity_ed25519_public != device.branch_public_key
            || bundle.device_agreement_x25519_public.as_slice() != agreement
            || bundle.identity_key.as_slice() != agreement
            || bundle.identity_commitment != device.principal_id
        {
            return Err(reject("prekey bundle differs from root-bound device keys"));
        }
        Ok(())
    }
    pub(crate) fn device_is_usable(
        &self,
        identity: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> bool {
        let Some(device) = self.device_record(identity) else {
            return false;
        };
        self.device_record_is_usable(device)
    }
    pub(crate) fn device_record_is_usable(&self, device: &IdentityDeviceRecord) -> bool {
        if self.record_is_revoked(device) {
            return false;
        }
        let Some(identity) =
            self.device_identity_for_root(&device.principal_commitment, &device.device_id)
        else {
            return false;
        };
        let Some(set) = self.signed_device_sets.get(identity.root_commitment()) else {
            return false;
        };
        set.devices.iter().any(|entry| {
            entry.device_id == device.device_id
                && entry.status == DeviceSetStatus::Active
                && Self::device_matches_entry(device, entry)
        })
    }
    fn device_matches_entry(
        device: &IdentityDeviceRecord,
        entry: &ramflux_protocol::SignedDeviceSetEntry,
    ) -> bool {
        let Some(binding) = &device.branch_proof.key_binding else {
            return false;
        };
        device.device_epoch == entry.device_epoch
            && ramflux_crypto::device_key_commitments(
                &device.branch_public_key,
                &binding.agreement_identity_public_key,
            )
            .is_ok_and(|keys| {
                keys.0 == entry.signing_key_commitment && keys.1 == entry.agreement_key_commitment
            })
    }
    /// Highest accepted full record, including revoked devices and its original root signature.
    #[must_use]
    pub fn signed_device_set(&self, commitment: &str) -> Option<&SignedDeviceSetRecord> {
        self.signed_device_sets.get(commitment)
    }
}
