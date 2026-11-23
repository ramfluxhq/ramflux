// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned primary-vault inputs for group signing outside the account writer.

use crate::prelude::LocalBusAccountState;
use crate::{
    GatewaySessionConfig, SdkError,
    custody::{BornAccount, PrimaryVault},
};
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::custody::CustodyAuthority;
use std::sync::Arc;

pub(crate) struct PrimarySnapshot {
    native: BornAccount,
    vault: Arc<dyn PrimaryVault>,
    retired: bool,
    gateway: GatewaySessionConfig,
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
            gateway: account.gateway_config.clone(),
        }))
    }
    pub(crate) async fn load(self) -> Result<crate::custody::PrimarySigningLease, SdkError> {
        if self.retired {
            return Err(SdkError::AgentCreationRefused("agent_retired"));
        }
        let host = require_agent_operable(&self.native, &self.gateway).await?;
        let Self { native, vault, .. } = self;
        tokio::task::spawn_blocking(move || {
            native.group_operation_signer(vault.as_ref(), host.as_ref())
        })
        .await
        .map_err(|_| SdkError::CustodyVaultUnavailable)?
    }
}

/// Directory record of the custodian, for [`BornAccount::group_operation_signer`].
///
/// A human returns `Ok(None)` and does not fetch. A hosted agent returns the current
/// public device-manifest record so the signer can run the same active-device test as
/// `RouterCore::require_agent_operable` before it signs. The desktop's stored human
/// file is not consulted: a phone revoke is acknowledged on the node before that file
/// changes.
///
/// # Errors
/// A missing or mismatched directory record, or a fetch failure. The signer then
/// refuses `agent_retired` when the fetched record's primary or host desktop is inactive.
pub(crate) async fn require_agent_operable(
    native: &BornAccount,
    gateway: &GatewaySessionConfig,
) -> Result<Option<VerifiedRecord>, SdkError> {
    let Some(anchor) = native.hosted_human_anchor()? else {
        return Ok(None);
    };
    if !anchor_path_ok(&anchor) {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(Some(fetch_human(gateway, &anchor).await?))
}

async fn fetch_human(
    gateway: &GatewaySessionConfig,
    anchor: &str,
) -> Result<VerifiedRecord, SdkError> {
    let started = std::time::Instant::now();
    let manifest = crate::prekey::sdk_gateway_get_json::<Option<crate::SdkDeviceManifestResponse>>(
        gateway,
        &format!("/mvp1/device-manifest/{anchor}"),
    )
    .await?
    .map(|manifest| manifest.fetched_from(started))
    .ok_or_else(|| SdkError::InboundPending("native current head unavailable".into()))?;
    if manifest.principal_commitment != anchor {
        return Err(SdkError::CustodySetupInvalid);
    }
    let custody = manifest.custody.as_ref().ok_or(SdkError::CustodyModeDowngrade)?;
    if custody.publication.record.body.account_anchor != anchor {
        return Err(SdkError::CustodySetupInvalid);
    }
    let authority = CustodyAuthority {
        publication: custody.publication.clone(),
        custodian_publication: custody.custodian_publication.clone(),
    };
    let verified =
        ramflux_crypto::custody::verify_publication(&authority, crate::custody::network_now()?)?;
    if verified.envelope().body.account_anchor != anchor {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(verified)
}

fn anchor_path_ok(anchor: &str) -> bool {
    !anchor.is_empty()
        && anchor.len() <= 128
        && anchor.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
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
