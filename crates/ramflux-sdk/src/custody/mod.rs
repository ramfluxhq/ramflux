// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local-only born-v3 setup. Live registration is intentionally unavailable.
mod bus;
mod ceremony;
pub use bus::{ConfirmedAccount, CustodyBusClient};
pub(crate) mod store;
mod vault;
pub use ceremony::CreateInput;
pub(crate) use ceremony::CreationCeremony;
pub use store::{BornAccount, CreationState, load_account};
pub(crate) use store::{account_exists, list_accounts};
pub use vault::{NativePrimaryVault, PrimaryVault};

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
        Ok(CreationState::NetworkingPending)
    }
    pub(crate) fn require_legacy_networking(&self) -> Result<(), SdkError> {
        if self.born_v3_account.is_some() {
            return Err(SdkError::NetworkingPending);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
