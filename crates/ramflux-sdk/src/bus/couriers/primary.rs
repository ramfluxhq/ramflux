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
    retired: bool,
}
impl PrimarySnapshot {
    pub(crate) fn prepare(account: &LocalBusAccountState) -> Result<Option<Self>, SdkError> {
        let Some(native) = account.client.born_v3_account.as_deref().cloned() else {
            return Ok(None);
        };
        let setup = account.native_setup.as_ref().ok_or(SdkError::CustodyVaultUnavailable)?;
        Ok(Some(Self {
            native,
            vault: crate::bus::custody_setup::primary_provider(setup),
            retired: session_agent_retired(account),
        }))
    }
    pub(crate) async fn load(self) -> Result<crate::custody::PrimarySigningLease, SdkError> {
        if self.retired {
            return Err(SdkError::AgentCreationRefused("agent_retired"));
        }
        tokio::task::spawn_blocking(move || self.native.group_operation_signer(self.vault.as_ref()))
            .await
            .map_err(|_| SdkError::CustodyVaultUnavailable)?
    }
}

fn session_agent_retired(account: &LocalBusAccountState) -> bool {
    account.connection.as_ref().is_some_and(|connection| {
        connection
            .snapshot()
            .cause
            .as_ref()
            .is_some_and(crate::AccountNetworkingReason::agent_retired)
    })
}
