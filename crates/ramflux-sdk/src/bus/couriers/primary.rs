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
        let host = custodian_directory(&self.native, &self.gateway).await?;
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
/// [`crate::custody::agent_creation::require_agent_operable`] runs first. Call invites
/// enter through [`call_agent_fence`], which starts here: a retirement row or a stored
/// host-branch marker refuses `agent_retired` before this fetch and before a call row.
/// A human returns `Ok(None)` and does not fetch. A hosted agent then returns the current public
/// device-manifest record so the signer can run the same active-device test as node
/// `agent_fence::require_operable`. The desktop's stored human file is not that
/// record. A phone revoke is acknowledged on the node before the file or the
/// host-branch marker changes, so the fetch is what sees that revoke.
///
/// # Errors
/// `AgentCreationRefused("agent_retired")` from the shared local fence. A missing or
/// mismatched directory record, or a fetch failure. The signer then refuses
/// `agent_retired` when the fetched record's primary or host desktop is inactive.
pub(crate) async fn custodian_directory(
    native: &BornAccount,
    gateway: &GatewaySessionConfig,
) -> Result<Option<VerifiedRecord>, SdkError> {
    crate::custody::agent_creation::require_agent_operable(
        native.data_root()?,
        native.local_account_id(),
    )?;
    let Some(anchor) = native.hosted_human_anchor()? else {
        return Ok(None);
    };
    if !anchor_path_ok(&anchor) {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(Some(fetch_human(gateway, &anchor).await?))
}

/// Refuse a call invite from a retired agent or a revoked host desktop.
///
/// The session cause is checked first. [`custodian_directory`] then applies the same
/// local fence and custodian fetch as a group operation, and
/// [`BornAccount::refuse_hosted_agent`] applies that record. A hosted agent whose own
/// directory says `agent_lifecycle = retired` is refused even when the custodian's
/// devices are still active. Nothing is written.
///
/// # Errors
/// `AgentCreationRefused("agent_retired")` when the agent must not invite. A missing
/// directory record or a fetch failure passes through, before a call row exists.
pub(crate) async fn call_agent_fence(account: &LocalBusAccountState) -> Result<(), SdkError> {
    if session_agent_retired(account) {
        return Err(SdkError::AgentCreationRefused("agent_retired"));
    }
    let Some(native) = account.client.born_v3_account.as_ref() else {
        return Ok(());
    };
    let host = custodian_directory(native, &account.gateway_config).await?;
    native.refuse_hosted_agent(host.as_ref())?;
    if host.is_some() {
        refuse_published_retirement(native, &account.gateway_config).await?;
    }
    Ok(())
}

async fn refuse_published_retirement(
    native: &BornAccount,
    gateway: &GatewaySessionConfig,
) -> Result<(), SdkError> {
    let anchor = native.record().body.account_anchor.clone();
    if !anchor_path_ok(&anchor) {
        return Err(SdkError::CustodySetupInvalid);
    }
    let manifest = crate::prekey::sdk_gateway_get_json::<Option<serde_json::Value>>(
        gateway,
        &format!("/mvp1/device-manifest/{anchor}"),
    )
    .await?
    .ok_or_else(|| SdkError::InboundPending("native current head unavailable".into()))?;
    if manifest.get("agent_lifecycle").and_then(serde_json::Value::as_str) == Some("retired") {
        return Err(SdkError::AgentCreationRefused("agent_retired"));
    }
    Ok(())
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
