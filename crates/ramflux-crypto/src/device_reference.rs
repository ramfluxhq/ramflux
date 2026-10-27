// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opaque device identity references created from root ownership or verified root-signed evidence.
use crate::{CryptoError, DeviceBranch, IdentityRoot};
use ed25519_dalek::VerifyingKey;
use ramflux_protocol::SignedDeviceSetRecord;

/// A root commitment and one literal device name, suitable for identity keys and lookups.
/// This names an authenticated root's device; it does not grant an active-device permission.
/// Callers still enforce the highest accepted device-set epoch, revocation and operation policy.
/// There is deliberately no string constructor, deserializer, or implicit string conversion.
///
/// ```compile_fail
/// use ramflux_crypto::RootQualifiedDeviceRef;
/// let device = RootQualifiedDeviceRef::from("bob");
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RootQualifiedDeviceRef {
    root_commitment: String,
    device_id: String,
    storage_key: String,
}
impl RootQualifiedDeviceRef {
    /// Name a branch under an account whose root signing key the caller owns.
    /// # Errors
    /// Rejects a root/branch principal mismatch or an invalid live device name.
    pub fn for_owned_device(
        root: &IdentityRoot,
        branch: &DeviceBranch,
    ) -> Result<Self, CryptoError> {
        if root.principal_id != branch.principal_id {
            return Err(CryptoError::IdentityAuthority("root principal mismatch"));
        }
        Self::authenticated(
            crate::identity_root_commitment(&root.signing_key.verifying_key()),
            &branch.device_id,
        )
    }
    /// Name a device under an account whose private root the caller owns.
    /// This permits root-scoped revocation cleanup even if the old device is no longer active.
    /// # Errors
    /// Rejects invalid live device names.
    pub fn for_owned_account_device(
        root: &IdentityRoot,
        device: &str,
    ) -> Result<Self, CryptoError> {
        Self::authenticated(
            crate::identity_root_commitment(&root.signing_key.verifying_key()),
            device,
        )
    }
    /// Name an entry only after verifying its complete root-signed device set.
    /// Revoked entries remain nameable for cleanup and revocation bookkeeping, never authorization.
    /// # Errors
    /// Rejects invalid root signatures, malformed sets, or an absent device entry.
    pub fn from_signed_device_set(
        root: &VerifyingKey,
        record: &SignedDeviceSetRecord,
        device: &str,
    ) -> Result<Self, CryptoError> {
        crate::verify_signed_device_set(root, record)?;
        if !record.devices.iter().any(|entry| entry.device_id == device) {
            return Err(CryptoError::IdentityAuthority("device absent from signed set"));
        }
        Self::authenticated(record.principal_commitment.clone(), device)
    }
    /// Name a branch only from fully verified born-v3 authority.
    /// The caller must enforce durable head pins before granting operations.
    /// # Errors
    /// Rejects a device absent from both the authenticated roster and revocation membership.
    /// Compacted revoked identities remain nameable solely for history and denial cleanup.
    pub fn from_custody_record(
        record: &crate::custody::VerifiedRecord,
        device: &str,
    ) -> Result<Self, CryptoError> {
        let body = &record.envelope().body;
        if !body.devices.iter().any(|entry| entry.device_id == device)
            && !record.revoked_ids().contains(device)
        {
            return Err(CryptoError::IdentityAuthority("device absent from custody set"));
        }
        Self::authenticated(body.account_anchor.clone(), device)
    }
    /// Name a device in the account scope authenticated by a verified custody record.
    /// This is used for retained revocation indexes where the device may no longer be rostered.
    pub(crate) fn from_verified_custody_account(
        record: &crate::custody::VerifiedRecord,
        device: &str,
    ) -> Result<Self, CryptoError> {
        Self::authenticated(record.envelope().body.account_anchor.clone(), device)
    }
    fn authenticated(root: String, device: &str) -> Result<Self, CryptoError> {
        ramflux_protocol::validate_device_name(device)?;
        let storage_key = ramflux_protocol::qualified_device_id(&root, device)?;
        Ok(Self { root_commitment: root, device_id: device.into(), storage_key })
    }
    #[must_use]
    pub fn root_commitment(&self) -> &str {
        &self.root_commitment
    }
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    #[must_use]
    pub fn storage_key(&self) -> &str {
        &self.storage_key
    }
    /// Root-bound recipient identifier used by v3 object grants and gateway-issued tokens.
    #[must_use]
    pub fn object_relay_grantee_hash(&self) -> String {
        crate::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v2",
            self.storage_key().as_bytes(),
        )
    }
}

impl ramflux_protocol::RootQualifiedDeviceIdentity for RootQualifiedDeviceRef {
    fn root_commitment(&self) -> &str {
        self.root_commitment()
    }
    fn device_id(&self) -> &str {
        self.device_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_root_scoped_and_encoded_only_after_authentication() -> Result<(), CryptoError> {
        let a = crate::create_identity_root("alice", [1; 32]);
        let b = crate::create_identity_root("bob", [2; 32]);
        let branch = crate::create_device_branch("alice", "phone", 1, [3; 32]);
        let alice = RootQualifiedDeviceRef::for_owned_device(&a, &branch)?;
        assert!(RootQualifiedDeviceRef::for_owned_device(&b, &branch).is_err());
        let bob = RootQualifiedDeviceRef::for_owned_device(
            &b,
            &crate::create_device_branch("bob", "phone", 1, [4; 32]),
        )?;
        assert_ne!(alice, bob);
        assert_eq!(alice.device_id(), bob.device_id());
        assert_eq!(
            ramflux_protocol::parse_qualified_device_id(alice.storage_key())?,
            Some((alice.root_commitment().into(), "phone".into()))
        );
        Ok(())
    }
    #[test]
    fn signed_set_factory_checks_the_root_signature_and_entry_name() -> Result<(), CryptoError> {
        let root = crate::create_identity_root("alice", [1; 32]);
        let entry = ramflux_protocol::SignedDeviceSetEntry {
            device_id: "phone".into(),
            device_epoch: 1,
            signing_key_commitment: ramflux_protocol::encode_base64url([3; 32]),
            agreement_key_commitment: ramflux_protocol::encode_base64url([4; 32]),
            status: ramflux_protocol::DeviceSetStatus::Active,
            revoked_at: None,
        };
        let mut record = crate::sign_device_set(
            &root,
            crate::DeviceSetSigningInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                device_set_epoch: 1,
                devices: vec![entry.clone()],
            },
        )?;
        let public = root.signing_key.verifying_key();
        assert_eq!(
            RootQualifiedDeviceRef::from_signed_device_set(&public, &record, "phone")?
                .root_commitment(),
            crate::identity_root_commitment(&public)
        );
        assert!(RootQualifiedDeviceRef::from_signed_device_set(&public, &record, "other").is_err());
        record.devices[0].device_epoch = 2;
        assert!(RootQualifiedDeviceRef::from_signed_device_set(&public, &record, "phone").is_err());
        for bad in [" ", "a\u{202e}b", "a\u{200b}b", "root~nested", "legacy~name"] {
            for status in [
                ramflux_protocol::DeviceSetStatus::Active,
                ramflux_protocol::DeviceSetStatus::Revoked,
            ] {
                let mut bad_entry = entry.clone();
                bad_entry.device_id = bad.into();
                bad_entry.status = status;
                bad_entry.revoked_at =
                    (status == ramflux_protocol::DeviceSetStatus::Revoked).then_some(100);
                assert!(
                    crate::sign_device_set(
                        &root,
                        crate::DeviceSetSigningInput {
                            principal_kind: ramflux_protocol::PrincipalKind::Human,
                            device_set_epoch: 1,
                            devices: vec![bad_entry]
                        }
                    )
                    .is_err()
                );
            }
        }
        Ok(())
    }
}
