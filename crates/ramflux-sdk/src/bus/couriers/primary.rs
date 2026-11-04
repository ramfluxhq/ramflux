// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned primary-vault inputs for group signing outside the account writer.

use crate::prelude::LocalBusAccountState;
use crate::{
    SdkError,
    custody::{BornAccount, PrimaryVault},
};
use std::sync::Arc;

pub(crate) struct PrimarySnapshot {
    native: BornAccount,
    vault: Arc<dyn PrimaryVault>,
}
impl PrimarySnapshot {
    pub(crate) fn prepare(account: &LocalBusAccountState) -> Result<Option<Self>, SdkError> {
        let Some(native) = account.client.born_v3_account.as_deref().cloned() else {
            return Ok(None);
        };
        let setup = account.native_setup.as_ref().ok_or(SdkError::CustodyVaultUnavailable)?;
        Ok(Some(Self { native, vault: crate::bus::custody_setup::primary_provider(setup) }))
    }
    pub(crate) async fn load(self) -> Result<ramflux_crypto::custody::SelfSigningKey, SdkError> {
        tokio::task::spawn_blocking(move || self.native.group_primary(self.vault.as_ref()))
            .await
            .map_err(|_| SdkError::CustodyVaultUnavailable)?
    }
}
