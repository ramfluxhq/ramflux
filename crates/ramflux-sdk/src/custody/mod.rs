// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Born-v3 setup and explicit channel-bound networking; legacy authentication stays separate.
mod bus;
mod ceremony;
mod commit_gate;
pub use bus::{ConfirmedAccount, CustodyBusClient};
pub(crate) use commit_gate::CommitGate;
mod secret_buffer;
pub(crate) use secret_buffer::serialize_secret;
pub(crate) mod home_authorization;
mod store;
mod vault;
pub use ceremony::{CreateInput, CreationCeremony};
pub use home_authorization::HomeAuthorizationRequest;
pub use store::RecoveryCeremony;
pub use store::{BornAccount, CreationState, load_account};
pub(crate) use store::{accept_publication, account_exists, list_accounts, load_data_account};
pub(crate) use store::{finish_recovery, pending_restore};
pub use vault::{BranchCredentials, NativePrimaryVault, PrimaryVault};

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
pub(crate) mod tests;

#[cfg(any(test, feature = "itest-memory-vault"))]
pub(crate) mod memory_vault;
#[cfg(feature = "itest-memory-vault")]
pub use memory_vault::MemoryPrimaryVault;

mod network;
mod node_pins;
pub(crate) mod retry;
pub use network::{CustodyConnection, CustodyNetworkConfig};
pub(crate) use node_pins::verify_authority as verify_public_authority;

#[cfg(test)]
pub(crate) mod network_tests;

mod discovery;

pub(crate) use network::now as network_now;
