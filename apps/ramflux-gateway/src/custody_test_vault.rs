// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-local fixture credentials for real SDK clients in gateway tests.
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_sdk::{
    SdkError,
    custody::{BranchCredentials, PrimaryVault},
};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::Zeroizing;
#[derive(Default)]
pub(super) struct Vault(Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>);
impl Vault {
    fn put(&self, reference: &str, bytes: &[u8]) -> Result<(), SdkError> {
        let mut entries = self.0.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if entries.contains_key(reference) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        entries.insert(reference.into(), Zeroizing::new(bytes.to_vec()));
        Ok(())
    }
    fn get<const N: usize>(&self, reference: &str) -> Result<Zeroizing<[u8; N]>, SdkError> {
        let entries = self.0.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let bytes = entries.get(reference).ok_or(SdkError::CustodyVaultUnavailable)?;
        if bytes.len() != N {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut seed = Zeroizing::new([0; N]);
        seed.copy_from_slice(bytes);
        Ok(seed)
    }
}
impl PrimaryVault for Vault {
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        self.0.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.remove(reference);
        Ok(())
    }
    fn preflight(&self) -> Result<(), SdkError> {
        Ok(())
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        self.put(reference, &*key.vault_seed())
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        Ok(SelfSigningKey::from_vault_seed(&self.get(reference)?))
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.put(reference, &**seeds)
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        BranchCredentials::from_vault_seeds(principal, device, &self.get(reference)?)
    }
}
