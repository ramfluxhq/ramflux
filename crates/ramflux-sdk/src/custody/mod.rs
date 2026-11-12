// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 setup and explicit channel-bound networking; legacy authentication stays separate.
mod bus;
mod ceremony;
mod commit_gate;
pub use bus::{ConfirmedAccount, CustodyBusClient};
pub(crate) use commit_gate::CommitGate;
pub mod pairing;
mod secret_buffer;
pub(crate) use secret_buffer::serialize_secret;
pub(crate) mod home_authorization;
mod store;
mod vault;
pub use ceremony::{CreateInput, CreationCeremony};
pub use home_authorization::HomeAuthorizationRequest;
pub use store::RecoveryCeremony;
pub use store::{AgentProvisioningBundle, BornAccount, CreationState, load_account};
pub(crate) use store::{
    accept_publication, account_exists, custody_vault_reference, export_agent_credentials,
    failed_setup, failed_setup_error, list_accounts, load_data_account, pending_head_fence_blocks,
    reconcile_incomplete_markers, reserve_pairing_account,
};
pub(crate) use store::{finish_recovery, pending_restore};
pub(crate) use vault::require_vault_reference;
pub use vault::{
    BranchCredentials, CustodyVaultReason, NativePrimaryVault, PrimaryVault,
    VAULT_CLASS_LOGIN_KEYCHAIN, VAULT_CLASS_PROTECTED,
};
#[cfg(target_os = "ios")]
pub use vault::set_keychain_access_group;

#[cfg(any(target_os = "linux", test))]
pub use vault::linux::{
    LinuxCredentialPaths, LinuxVaultConfig, LinuxVaultConfigError, LinuxVaultMode, LinuxVaultRole,
};

use crate::SdkError;
fn invalid() -> SdkError {
    SdkError::CustodySetupInvalid
}
fn random() -> Result<zeroize::Zeroizing<[u8; 32]>, SdkError> {
    let mut seed = zeroize::Zeroizing::new([0; 32]);
    getrandom::fill(&mut *seed).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    Ok(seed)
}
fn valid_id(id: &str) -> Result<(), SdkError> {
    if id.is_empty()
        || id.len() > 128
        || !id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        || matches!(id, "." | "..")
    {
        return Err(invalid());
    }
    Ok(())
}

impl crate::RamfluxClient {
    /// Select verified local born-v3 authority on a fresh client without opening a session.
    /// # Errors
    /// Rejects missing, corrupt, unverified or downgraded local custody state.
    pub fn load_born_v3_account(
        &mut self,
        root: &std::path::Path,
        id: &str,
        now: u64,
    ) -> Result<CreationState, SdkError> {
        if self.active_account_db.is_some()
            || self.identity_root.is_some()
            || self.device_branch.is_some()
            || self.reader_device_identity.is_some()
        {
            return Err(SdkError::CustodySetupInvalid);
        }
        let account = load_account(root, id, now)?;
        self.identity_root = None;
        self.device_branch = None;
        self.born_v3_account = Some(Box::new(account));
        Ok(self.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?.state())
    }
    pub(crate) fn require_legacy_networking(&self) -> Result<(), SdkError> {
        if let Some(account) = &self.born_v3_account {
            return Err(if account.state() == CreationState::NetworkingPending {
                SdkError::NetworkingPending
            } else {
                SdkError::CustodyModeDowngrade
            });
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod observer;
#[cfg(test)]
pub(crate) mod tests;

#[cfg(any(test, feature = "itest-memory-vault"))]
pub(crate) mod memory_vault;
#[cfg(feature = "itest-memory-vault")]
pub use memory_vault::MemoryPrimaryVault;

mod layer_declaration;
pub use layer_declaration::DeclarationValidity;
#[cfg(test)]
pub(crate) use layer_declaration::candidate as sign_layer_declaration;
mod network;
mod node_pins;
pub(crate) mod retry;
pub use network::{CustodyConnection, CustodyNetworkConfig};
pub(crate) use node_pins::verify_authority as verify_public_authority;

#[cfg(test)]
pub(crate) mod network_tests;

mod discovery;

pub(crate) use network::now as network_now;

mod capacity_backoff;
pub(crate) mod capacity_hint;

pub(crate) use capacity_backoff::{
    RETRY_AFTER_MS as CAPACITY_RETRY_AFTER_MS, RETRY_AFTER_SECS as CAPACITY_RETRY_AFTER_SECS,
};

/// Dormant native DM bootstrap component adapters.
pub mod dm_fs_v3;

#[cfg(target_os = "linux")]
pub use vault::linux::{LinuxVaultInitError, LinuxVaultInstallation};

#[cfg(target_os = "linux")]
pub use vault::linux::{LinuxDataCredentials, LinuxPrimaryVault};
