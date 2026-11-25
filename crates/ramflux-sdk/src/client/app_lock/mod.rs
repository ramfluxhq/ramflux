// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! App-lock owners: the in-memory device wrap of the open account key (this file), the policy
//! commit that stages a presence wrap before it is committed ([`policy`]), and the internal
//! platform presence provider the unlock and configure arms call ([`presence`]).

use super::RamfluxClient;
use crate::SdkError;
use ramflux_storage::WrappedAccountDbKey;

pub(crate) mod code;
pub(crate) mod policy;
pub(crate) mod presence;

impl RamfluxClient {
    /// Wraps the open account key for a silent restart. Does not write the index.
    ///
    /// # Errors
    /// Returns an error when the account is closed or the device secret cannot be read.
    pub(crate) fn silent_device_wrap(&self) -> Result<WrappedAccountDbKey, SdkError> {
        let database = self.account_db()?;
        let account_id = database.local_account_id.clone();
        let key = database.copy_current_key();
        let vault_secret =
            zeroize::Zeroizing::new(self.vault_secret_source()?.vault_secret(&account_id)?);
        super::device_unlock::wrapped_device_key(&account_id, &vault_secret, &key)
    }
}
