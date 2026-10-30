// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Integration fixture. No persistence, synchronisation or production fallback.
use super::{BranchCredentials, PrimaryVault};
use crate::SdkError;
use ramflux_crypto::custody::SelfSigningKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};
use zeroize::Zeroizing;
struct MigrationApproval {
    account: String,
    request_id: String,
}
#[derive(Default)]
struct MigrationApprovals {
    pending: Option<MigrationApproval>,
    consumed: BTreeSet<(String, String)>,
}
#[derive(Default)]
pub struct MemoryPrimaryVault {
    entries: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    migration_approval: Mutex<MigrationApprovals>,
}
impl MemoryPrimaryVault {
    /// Grant one exact migration signature in the default-off integration fixture only.
    /// # Errors
    /// Refuses a pending approval or any already-consumed account/request pair.
    pub fn approve_migration_once_for_test(
        &self,
        account: &str,
        request_id: &str,
    ) -> Result<(), SdkError> {
        let mut approval =
            self.migration_approval.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if approval.consumed.contains(&(account.into(), request_id.into())) {
            return Err(SdkError::LocalBusRefused {
                code: "MigrationApprovalConsumed".into(),
                message: "this migration fixture approval was already consumed".into(),
                body: Box::new(serde_json::json!({
                    "reason_code": "migration_approval_consumed"
                })),
            });
        }
        if approval.pending.is_some() {
            return Err(SdkError::LocalBusRefused {
                code: "MigrationApprovalAlreadyArmed".into(),
                message: "a migration fixture approval is already armed".into(),
                body: Box::new(serde_json::json!({
                    "reason_code": "migration_approval_already_armed"
                })),
            });
        }
        approval.pending =
            Some(MigrationApproval { account: account.into(), request_id: request_id.into() });
        Ok(())
    }
    fn put(&self, reference: &str, bytes: &[u8]) -> Result<(), SdkError> {
        let mut entries = self.entries.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if entries.contains_key(reference) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        entries.insert(reference.into(), Zeroizing::new(bytes.to_vec()));
        Ok(())
    }
    fn get<const N: usize>(&self, reference: &str) -> Result<Zeroizing<[u8; N]>, SdkError> {
        let entries = self.entries.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let bytes = entries.get(reference).ok_or(SdkError::CustodyVaultUnavailable)?;
        if bytes.len() != N {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut seed = Zeroizing::new([0; N]);
        seed.copy_from_slice(bytes);
        Ok(seed)
    }
}
impl PrimaryVault for MemoryPrimaryVault {
    #[cfg(feature = "itest-memory-vault")]
    fn approve_migration_once_for_test(
        &self,
        account: &str,
        request_id: &str,
    ) -> Result<(), SdkError> {
        Self::approve_migration_once_for_test(self, account, request_id)
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        self.entries.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.remove(reference);
        Ok(())
    }
    fn home_authorization_preflight(&self) -> Result<(), SdkError> {
        Ok(())
    }

    fn sign_home_authorization(
        &self,
        request: super::HomeAuthorizationRequest<'_>,
    ) -> Result<
        ramflux_protocol::home_migration::Signed<ramflux_protocol::home_migration::Authorization>,
        SdkError,
    > {
        let mut approval =
            self.migration_approval.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let matches = approval.pending.as_ref().is_some_and(|approval| {
            approval.account == request.local_account_id()
                && approval.request_id == request.request_id()
        });
        if !matches {
            return Err(super::home_authorization::unavailable());
        }
        if let Some(consumed) = approval.pending.take() {
            approval.consumed.insert((consumed.account, consumed.request_id));
        }
        drop(approval);
        let primary = self.load_primary(request.primary_reference())?;
        let now = request.requested_at;
        request.sign_once(&primary, now)
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

#[cfg(test)]
mod tests;
