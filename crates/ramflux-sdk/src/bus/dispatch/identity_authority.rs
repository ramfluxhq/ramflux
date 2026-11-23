// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit device-manifest refresh.
use crate::prelude::*;
use serde_json::json;
pub(super) async fn dispatch_identity_authority(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let id = request_account_id(request)?;
    let account = local_bus_account_mut(state, id)?;
    let commitment = request.body["principal_commitment"]
        .as_str()
        .unwrap_or(&account.principal_commitment)
        .to_owned();
    let manifest = account
        .client
        .cache_verified_device_manifest(&account.gateway_config, &commitment, "device.refresh")
        .await?;
    if let Some(native) = &manifest.custody {
        let record = &native.publication.record.body;
        let mut body = json!({
            "principal_id":record.principal_id,"device_set_epoch":record.device_set_epoch,
            "principal_kind":record.principal_kind,"kind_asserted":record.profile.kind,
            "kind_verified":account.client.verified_identity_profile(&record.principal_id)?.is_some(),
            "safety_kind_verified":account.client.verified_principal_kind(&record.principal_id)?.is_some(),
            "identity_scheme":"custody_v3","devices":record.devices,
        });
        body[crate::VerifiedClassification::FIELD] =
            json!(account.client.verified_classification(&record.principal_id)?);
        return Ok(local_bus_ok(body));
    }
    let record = manifest
        .signed_device_set
        .ok_or_else(|| SdkError::InboundRejected("signed device set absent".into()))?;
    let mut body = json!({"principal_id":record.principal_id,"device_set_epoch":record.device_set_epoch,"principal_kind":record.principal_kind,"kind_asserted":record.profile.as_ref().map(|p|p.kind),"kind_verified":account.client.verified_identity_profile(&record.principal_id)?.is_some(),"safety_kind_verified":account.client.verified_principal_kind(&record.principal_id)?.is_some(),"devices":record.devices});
    body[crate::VerifiedClassification::FIELD] =
        json!(account.client.verified_classification(&record.principal_id)?);
    Ok(local_bus_ok(body))
}
