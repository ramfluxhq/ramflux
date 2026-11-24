// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A desktop learns that its own branch was revoked from the public device manifest,
//! then stops reporting live and stops reconnecting. The node drops the revocation
//! phrase into `InvalidInput`, so a bare refusal is not proof. Proof is a verified
//! publication of this anchor in which this device id is revoked.

use super::state::LocalBusAccountState;
use crate::custody::agent_creation::{
    host_branch_marked, note_host_branch_revoked, suspend_hosted_agents,
};
use crate::prelude::*;
use ramflux_protocol::custody::{CustodyAuthority, CustodyRefusal};

/// The gateway config names an account whose marker file is already present.
#[must_use]
pub(super) fn marked_on(config: &crate::gateway::GatewaySessionConfig) -> bool {
    config
        .custody
        .as_ref()
        .is_some_and(|custody| host_branch_marked(&custody.account_root, &custody.account_id))
}

/// Replace a live status when the marker is present. The stored authority is not rewritten.
pub(super) fn overlay_status(
    status: &mut serde_json::Value,
    root: &std::path::Path,
    account_id: &str,
) {
    if !host_branch_marked(root, account_id) {
        return;
    }
    let Some(object) = status.as_object_mut() else {
        return;
    };
    object.insert("networking".into(), serde_json::Value::String("suspended".into()));
    object.insert("local_device_authorized".into(), serde_json::Value::Bool(false));
    object.insert("networking_reason".into(), serde_json::json!({ "kind": "branch_revoked" }));
    object.remove("networking_hint");
}

/// Suspend settled agents when the marker is already stored. A write problem is logged.
pub(super) fn suspend_marked(config: &crate::gateway::GatewaySessionConfig) {
    let Some(custody) = config.custody.as_ref() else {
        return;
    };
    if !host_branch_marked(&custody.account_root, &custody.account_id) {
        return;
    }
    if let Err(error) = suspend_hosted_agents(&custody.account_root, &custody.account_id) {
        tracing::warn!(%error, "hosted agents were not suspended");
    }
}

/// `true` when this failure should stop the reconnect loop.
/// A fetch or write problem leaves the loop on its existing retry.
pub(super) async fn stop_if_revoked(account: &LocalBusAccountState, error: &SdkError) -> bool {
    if marked_account(account) {
        suspend_marked(&account.gateway_config);
        return true;
    }
    if !revocation_candidate(error) {
        return false;
    }
    match learn(account).await {
        Ok(stopped) => stopped,
        Err(error) => {
            tracing::warn!(%error, "host branch revocation was not recorded");
            false
        }
    }
}

fn marked_account(account: &LocalBusAccountState) -> bool {
    account
        .gateway_config
        .custody
        .as_ref()
        .is_some_and(|custody| host_branch_marked(&custody.account_root, &custody.account_id))
}

fn revocation_candidate(error: &SdkError) -> bool {
    matches!(
        super::native_account::networking_reason(error),
        Some(AccountNetworkingReason::RegistrationRefused { code: CustodyRefusal::InvalidInput })
    )
}

async fn learn(account: &LocalBusAccountState) -> Result<bool, SdkError> {
    let Some((root, account_id)) = account
        .gateway_config
        .custody
        .as_ref()
        .map(|custody| (custody.account_root.clone(), custody.account_id.clone()))
    else {
        return Ok(false);
    };
    let now = crate::custody::network_now()?;
    let native = crate::custody::load_data_account(&root, &account_id, now)?;
    let device_id = native.local_device_id()?.to_owned();
    let anchor = native.record().body.account_anchor.clone();
    if !anchor_path_ok(&anchor) {
        return Ok(false);
    }
    let epoch = device_epoch(&native, &device_id);
    if !fetched_revokes(account, &anchor, &device_id, now).await? {
        return Ok(false);
    }
    note_host_branch_revoked(&root, &account_id, &device_id, epoch, &anchor, now)?;
    suspend_marked(&account.gateway_config);
    Ok(true)
}

fn device_epoch(native: &crate::custody::BornAccount, device_id: &str) -> u64 {
    native
        .record()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == device_id)
        .map_or(0, |device| device.device_epoch)
}

async fn fetched_revokes(
    account: &LocalBusAccountState,
    anchor: &str,
    device_id: &str,
    now: u64,
) -> Result<bool, SdkError> {
    let path = format!("/mvp1/device-manifest/{anchor}");
    let fetched = crate::prekey::sdk_gateway_get_json::<
        Option<crate::prekey::SdkDeviceManifestResponse>,
    >(&account.gateway_config, &path)
    .await;
    let Ok(Some(manifest)) = fetched else {
        return Ok(false);
    };
    Ok(publication_revokes(&manifest, anchor, device_id, now))
}

fn publication_revokes(
    manifest: &crate::prekey::SdkDeviceManifestResponse,
    anchor: &str,
    device_id: &str,
    now: u64,
) -> bool {
    if manifest.principal_commitment != anchor {
        return false;
    }
    let Some(custody) = manifest.custody.as_ref() else {
        return false;
    };
    if custody.publication.record.body.account_anchor != anchor {
        return false;
    }
    let authority = CustodyAuthority {
        publication: custody.publication.clone(),
        custodian_publication: custody.custodian_publication.clone(),
    };
    let Ok(verified) = ramflux_crypto::custody::verify_publication(&authority, now) else {
        return false;
    };
    verified.envelope().body.account_anchor == anchor && verified.revoked_ids().contains(device_id)
}

fn anchor_path_ok(anchor: &str) -> bool {
    !anchor.is_empty()
        && anchor.len() <= 128
        && anchor.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
