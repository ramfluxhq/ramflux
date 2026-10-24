// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-bound device authorization export, complete legacy migration and explicit refresh.
use crate::prelude::*;
use serde_json::json;
pub(super) async fn dispatch_identity_authority(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let id = request_account_id(request)?;
    let account = local_bus_account_mut(state, id)?;
    if request.method == "device.authorize" {
        let now = now_unix_timestamp();
        let proof = account.client.authorize_current_device(
            "ramflux-node",
            vec!["device.delivery.bind".into()],
            now,
            now.saturating_add(3600),
        )?;
        return Ok(local_bus_ok(serde_json::to_value(proof)?));
    }
    if request.method == "device.migrate" {
        let approvals: Vec<BranchProofDocument> = serde_json::from_value(
            request.body.get("authorizations").cloned().unwrap_or_else(|| json!([])),
        )?;
        account.client.import_legacy_device_authorizations(&approvals)?;
        let root = account.client.account_index()?.root();
        let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(root, id))?;
        let gateway = account.gateway_config.clone();
        account
            .client
            .initialize_and_publish_prekey_bundle_via_gateway_request(
                &gateway,
                &manifest.principal_commitment,
                &manifest.device_id,
                &manifest.target_delivery_id,
                manifest.device_seed,
            )
            .await?;
    }
    let commitment = request.body["principal_commitment"]
        .as_str()
        .unwrap_or(&account.principal_commitment)
        .to_owned();
    let manifest = account
        .client
        .cache_verified_device_manifest(&account.gateway_config, &commitment, "device.refresh")
        .await?;
    let record = manifest
        .signed_device_set
        .ok_or_else(|| SdkError::InboundRejected("signed device set absent".into()))?;
    Ok(local_bus_ok(
        json!({"principal_id":record.principal_id,"device_set_epoch":record.device_set_epoch,"principal_kind":record.principal_kind,"kind_verified":true,"devices":record.devices}),
    ))
}
