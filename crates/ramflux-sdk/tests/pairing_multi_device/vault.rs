// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-device, bounded test vault; never shared between SDK accounts.
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::custody::DeviceRef;
use ramflux_sdk::{
    SdkError,
    custody::{BranchCredentials, PrimaryVault},
};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::Zeroizing;
#[derive(Default)]
pub struct Vault(Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>);
fn unavailable() -> SdkError {
    SdkError::CustodyVaultUnavailable
}
impl Vault {
    fn put(&self, reference: &str, bytes: &[u8]) -> Result<(), SdkError> {
        let mut entries = self.0.lock().map_err(|_| unavailable())?;
        if entries.len() >= 16 || entries.contains_key(reference) {
            return Err(unavailable());
        }
        entries.insert(reference.into(), Zeroizing::new(bytes.to_vec()));
        Ok(())
    }
    pub fn branch_seeds(&self, reference: &str) -> Result<Zeroizing<[u8; 64]>, SdkError> {
        let entries = self.0.lock().map_err(|_| unavailable())?;
        let value = entries.get(reference).ok_or_else(unavailable)?;
        let mut output = Zeroizing::new([0; 64]);
        if output.len() != value.len() {
            return Err(unavailable());
        }
        output.copy_from_slice(value);
        Ok(output)
    }
    pub fn local_branch(
        &self,
        record: &ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    ) -> Result<(ramflux_crypto::DeviceBranch, ramflux_crypto::X25519KeyPair, DeviceRef), SdkError>
    {
        let entries = self.0.lock().map_err(|_| unavailable())?;
        let mut owned = None;
        for seeds in entries.values().filter(|value| value.len() == 64) {
            let mut signing = Zeroizing::new([0; 32]);
            let mut agreement = Zeroizing::new([0; 32]);
            signing.copy_from_slice(seeds.get(..32).ok_or_else(unavailable)?);
            agreement.copy_from_slice(seeds.get(32..).ok_or_else(unavailable)?);
            let public = ramflux_crypto::public_key_base64url_from_seed(*signing);
            let device = record
                .body
                .devices
                .iter()
                .find(|device| {
                    device.branch_certificate.as_ref().is_some_and(|certificate| {
                        certificate.body.branch_signing_public_key == public
                    })
                })
                .ok_or_else(unavailable)?;
            if owned.is_some() {
                return Err(unavailable());
            }
            let reference = DeviceRef {
                account_anchor: record.body.account_anchor.clone(),
                device_id: device.device_id.clone(),
                device_epoch: device.device_epoch,
            };
            owned = Some((
                ramflux_crypto::create_device_branch(
                    &record.body.principal_id,
                    &device.device_id,
                    device.device_epoch,
                    *signing,
                ),
                ramflux_crypto::X25519KeyPair::from_seed(*agreement),
                reference,
            ));
        }
        owned.ok_or_else(unavailable)
    }
    pub fn owned_references(&self) -> Result<(String, Option<String>), SdkError> {
        let entries = self.0.lock().map_err(|_| unavailable())?;
        let branches: Vec<_> = entries.iter().filter(|(_, bytes)| bytes.len() == 64).collect();
        let primary: Vec<_> = entries.iter().filter(|(_, bytes)| bytes.len() == 32).collect();
        if branches.len() != 1 || primary.len() > 1 {
            return Err(unavailable());
        }
        Ok((
            branches.first().ok_or_else(unavailable)?.0.clone(),
            primary.first().map(|(reference, _)| (*reference).clone()),
        ))
    }
    pub fn primary_entries(&self) -> Result<usize, SdkError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| unavailable())?
            .values()
            .filter(|value| value.len() == 32)
            .count())
    }
}
impl PrimaryVault for Vault {
    fn preflight(&self) -> Result<(), SdkError> {
        Ok(())
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        self.put(reference, key.vault_seed().as_slice())
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        let entries = self.0.lock().map_err(|_| unavailable())?;
        let value = entries.get(reference).ok_or_else(unavailable)?;
        let mut seed = Zeroizing::new([0; 32]);
        if value.len() != seed.len() {
            return Err(unavailable());
        }
        seed.copy_from_slice(value);
        Ok(SelfSigningKey::from_vault_seed(&seed))
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        self.0.lock().map_err(|_| unavailable())?.remove(reference);
        Ok(())
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.put(reference, seeds.as_slice())
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        BranchCredentials::from_vault_seeds(principal, device, &self.branch_seeds(reference)?)
    }
}
