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
    /// Publish a verified full record as-is; identical retransmission is idempotent.
    /// # Errors
    /// Rejects unsigned, regressed, conflicting or unauthorized identity/device changes.
    pub fn publish_signed_device_set(
        &mut self,
        request: &DeviceSetPublishRequest,
    ) -> Result<(), NodeCoreError> {
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
            .root_public_keys
            .get(&next.principal_id)
            .is_some_and(|old| old != &request.root_public_key)
            || self
                .root_public_keys_by_commitment
                .get(&next.principal_commitment)
                .is_some_and(|old| old != &request.root_public_key)
        {
            return Err(reject("principal is already bound to a different root"));
        }
        if let Some(previous) = self.signed_device_sets.get(&next.principal_commitment) {
            ramflux_crypto::validate_device_set_transition(previous, next)
                .map_err(|error| crypto(&error))?;
        }
        self.validate_set_ownership(next)?;
        for entry in &next.devices {
            if entry.status == DeviceSetStatus::Revoked {
                self.revoked_devices.insert(entry.device_id.clone());
            }
            if self
                .devices
                .get(&entry.device_id)
                .is_some_and(|device| !Self::device_matches_entry(device, entry))
                || entry.status == DeviceSetStatus::Revoked
            {
                self.prekey_bundles.remove(&entry.device_id);
            }
        }
        self.root_public_keys.insert(next.principal_id.clone(), request.root_public_key.clone());
        self.root_public_keys_by_commitment
            .insert(next.principal_commitment.clone(), request.root_public_key.clone());
        self.identity_authority_fences.insert(
            next.principal_commitment.clone(),
            IdentityAuthorityFence { principal_kind: next.principal_kind, deleted: false },
        );
        self.signed_device_sets.insert(next.principal_commitment.clone(), next.clone());
        Ok(())
    }
    fn validate_set_ownership(&self, next: &SignedDeviceSetRecord) -> Result<(), NodeCoreError> {
        for entry in &next.devices {
            if let Some(device) = self.devices.get(&entry.device_id) {
                if device.principal_id != next.principal_id
                    || device.principal_commitment != next.principal_commitment
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
                        self.prekey_bundles
                            .get(&device.device_id)
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
            if self.signed_device_sets.values().any(|set| {
                set.principal_commitment != next.principal_commitment
                    && set.devices.iter().any(|known| known.device_id == entry.device_id)
            }) {
                return Err(reject("device set ID already belongs to another root"));
            }
            if self.revoked_devices.contains(&entry.device_id)
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
        let binding = request.proof.key_binding.as_ref().ok_or_else(|| {
            reject("legacy branch proof is read-only; root-bound authorization required")
        })?;
        let root = ramflux_crypto::verifying_key_from_base64url(&request.root_public_key)
            .map_err(|error| crypto(&error))?;
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
        if let Some(record) = &request.device_set {
            self.apply_signed_device_set(&DeviceSetPublishRequest {
                root_public_key: request.root_public_key.clone(),
                record: record.clone(),
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
        if !self.device_is_usable(&device.device_id)
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
    pub(crate) fn device_is_usable(&self, id: &str) -> bool {
        if self.revoked_devices.contains(id) {
            return false;
        }
        let Some(device) = self.devices.get(id) else {
            return false;
        };
        let Some(set) = self.signed_device_sets.get(&device.principal_commitment) else {
            return device.branch_proof.key_binding.is_none();
        };
        set.devices.iter().any(|entry| {
            entry.device_id == id
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
