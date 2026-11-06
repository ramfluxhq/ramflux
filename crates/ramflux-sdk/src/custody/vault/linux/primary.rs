// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit dormant typed adapters. `NativePrimaryVault` selection is unchanged.
use super::{
    LinuxVaultConfig, LinuxVaultRole, cleanup::Secret, codec, files, init, writer::Operation,
};
use crate::{
    SdkError,
    custody::{BranchCredentials, PrimaryVault},
};
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::custody::DeviceRef;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub(super) fn unavailable<T>(_: T) -> SdkError {
    SdkError::CustodyVaultUnavailable
}
pub(super) struct Realm {
    store: files::Store,
    key: Secret<32>,
}
impl Realm {
    pub(super) fn read(&self, reference: &str, kind: u8) -> Result<codec::Plaintext, SdkError> {
        let _slot = init::Slot::acquire().map_err(unavailable)?;
        let record = self
            .store
            .apply(Operation::Read { reference: reference.into(), kind, generation: 1 }, |_| {})
            .map_err(unavailable)?;
        codec::open(self.store.binding(kind, reference, 1), &self.key, &record).map_err(unavailable)
    }
    pub(super) fn insert(&self, reference: &str, kind: u8, secret: &[u8]) -> Result<(), SdkError> {
        let _slot = init::Slot::acquire().map_err(unavailable)?;
        let input = codec::Plaintext::new(secret).map_err(unavailable)?;
        let record = codec::seal(self.store.binding(kind, reference, 1), &self.key, &input)
            .map_err(unavailable)?;
        self.store
            .apply(Operation::Insert { reference: reference.into(), kind, record }, |_| {})
            .map(drop)
            .map_err(unavailable)
    }
    pub(super) fn delete(&self, reference: &str, kind: u8) -> Result<(), SdkError> {
        let _slot = init::Slot::acquire().map_err(unavailable)?;
        match self
            .store
            .apply(Operation::Delete { reference: reference.into(), kind, generation: 1 }, |_| {})
        {
            Ok(_) | Err(files::Error::Missing) => Ok(()),
            Err(e) => Err(unavailable(e)),
        }
    }
}

/// Explicit per-account candidate provider. No production selector calls this factory.
/// Keys are dropped with the last provider handle; no portable authority export exists.
pub struct LinuxPrimaryVault {
    pub(super) realms: [Option<Realm>; 3],
    reference: String,
    class: &'static str,
    role: LinuxVaultRole,
}
impl LinuxPrimaryVault {
    /// Open a committed installation for exactly one account and canonical authority reference.
    /// Current record/device authorization remains the existing custody caller's responsibility.
    /// # Errors
    /// Refuses pending initialization, unsafe files, unavailable scoped KEKs or invalid bindings.
    pub async fn open(
        root: PathBuf,
        account: String,
        reference: String,
        config: LinuxVaultConfig,
    ) -> Result<Self, SdkError> {
        crate::custody::valid_id(&account)?;
        codec::Binding {
            realm: 1,
            kind: 1,
            vault_id: [0; 16],
            generation: 1,
            key_id: [0; 16],
            account: &account,
            reference: &reference,
        }
        .validate_name()
        .map_err(unavailable)?;
        let mut material =
            init::material(root.clone(), config.clone()).await.map_err(unavailable)?;
        let mut realms = std::array::from_fn(|_| None);
        for (i, slot) in realms.iter_mut().enumerate() {
            if let Some(key) = material.keys[i].take() {
                *slot = Some(Realm {
                    store: files::Store::open(
                        &root,
                        &account,
                        u8::try_from(i + 1).map_err(unavailable)?,
                        material.vault_id,
                        material.key_ids[i],
                    )
                    .map_err(unavailable)?,
                    key,
                });
            }
        }
        Ok(Self { realms, reference, class: config.mode().strength_class(), role: config.role() })
    }
    fn realm(&self, i: usize) -> Result<&Realm, SdkError> {
        self.realms[i].as_ref().ok_or(SdkError::CustodyVaultUnavailable)
    }
    fn bound(&self, reference: &str, prefix: &str) -> Result<(), SdkError> {
        if self.role == LinuxVaultRole::DataOnly
            || reference.strip_prefix(prefix) != Some(self.reference.as_str())
        {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        Ok(())
    }
    pub(super) fn take_data(mut self) -> Result<Realm, SdkError> {
        self.realms[2].take().ok_or(SdkError::CustodyVaultUnavailable)
    }
}
impl PrimaryVault for LinuxPrimaryVault {
    fn vault_class(&self) -> &'static str {
        self.class
    }
    fn preflight(&self) -> Result<(), SdkError> {
        // Ceremony preflight requires primary capacity, not a branch-only service handle.
        self.realm(0).map(|_| ())
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        self.bound(reference, "")?;
        self.realm(0)?.insert(reference, 1, &*key.vault_seed())
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        self.bound(reference, "")?;
        let bytes = self.realm(0)?.read(reference, 1)?;
        let mut seed = Secret::<32>::new("p06-primary-seed");
        seed.bytes_mut().copy_from_slice(bytes.bytes());
        Ok(SelfSigningKey::from_vault_seed(&Zeroizing::new(
            *<&[u8; 32]>::try_from(seed.bytes()).map_err(unavailable)?,
        )))
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.bound(reference, "branch:")?;
        self.realm(1)?.insert(reference, 2, seeds.as_slice())
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        self.bound(reference, "branch:")?;
        let bytes = self.realm(1)?.read(reference, 2)?;
        let mut seed = Secret::<64>::new("p06-branch-seed");
        seed.bytes_mut().copy_from_slice(bytes.bytes());
        BranchCredentials::from_vault_seeds(
            principal,
            device,
            &Zeroizing::new(*<&[u8; 64]>::try_from(seed.bytes()).map_err(unavailable)?),
        )
    }
    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        self.bound(reference, "agent-provisioning:")?;
        self.realm(2)?.insert(reference, 3, secret)
    }
    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.bound(reference, "agent-provisioning:")?;
        Ok(Zeroizing::new(self.realm(2)?.read(reference, 3)?.bytes().to_vec()))
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        let (i, kind, prefix) = if reference.starts_with("branch:") {
            (1, 2, "branch:")
        } else if reference.starts_with("agent-provisioning:") {
            (2, 3, "agent-provisioning:")
        } else {
            (0, 1, "")
        };
        self.bound(reference, prefix)?;
        self.realm(i)?.delete(reference, kind)
    }
}

#[cfg(test)]
mod tests;
