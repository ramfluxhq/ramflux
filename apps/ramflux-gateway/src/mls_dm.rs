// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The MLS DM frames of an authenticated session (MLS-SPEC 3.1, 3.5, 5): key package publish,
//! status and fetch, and `dm_order`. The session's home checks the device before anything is
//! stored or forwarded: Active, not revoked, lease valid, branch key = the registered one.
use crate::clients::router_post_json_async;
use crate::state::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_node_core::{
    DM_ORDER_ROUTER_PATH, DmOrderCall, DmOrderReply, GatewayClientFrame as Client,
    GatewayServerFrame as Server, KEY_PACKAGE_FETCH_PATH, KEY_PACKAGE_PUBLISH_PATH,
    KEY_PACKAGE_STATUS_PATH, KeyPackageFetchCall, KeyPackageFetchResponse, KeyPackagePublishCall,
    KeyPackagePublishOutcome, KeyPackageStatusCall, KeyPackageStatusResponse,
};
use ramflux_transport::TransportError;

fn nack(reason: &'static str) -> Server {
    Server::Nack { reason: reason.to_owned() }
}

/// The session's current device authority for `capability` (`authority.authorize`), compared with
/// what the session was opened with.
async fn authorized(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    capability: &str,
) -> bool {
    let lookup: Result<ramflux_node_core::DeviceAuthKeyLookup, TransportError> =
        crate::router_get_json_async(
            &context.router,
            &format!("/mvp1/device-auth-key/{}", runtime.source_identity.storage_key()),
        )
        .await;
    let Ok(Ok(key)) = lookup.map(crate::session_grant::require_native_key) else {
        return false;
    };
    let now = ramflux_node_core::now_unix_seconds();
    key.authenticated_device_identity_for(capability, now)
        .is_ok_and(|identity| identity == runtime.source_identity)
        && key.device_epoch == runtime.device_epoch
        && key.branch_public_key == runtime.branch_public_key
        && key.device_id == runtime.device_id
        && key.principal_id == runtime.principal_id
}

fn failed(error: &TransportError) -> Server {
    match error {
        TransportError::HttpStatus { status: 429, .. } => nack("rate_limited"),
        TransportError::HttpStatus { status: 502, .. } => nack("orderer_unreachable"),
        _ => nack("mls_dm_request_failed"),
    }
}

/// Answer one of the four MLS DM frames.
///
/// # Errors
/// Only a failed write of the answer to the client.
pub(crate) async fn handle(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    frame: Client,
) -> anyhow::Result<()> {
    let capability = match frame {
        Client::KeyPackagePublish { .. } | Client::KeyPackageStatus {} => "register",
        _ => "message",
    };
    let answer = if authorized(context, runtime, capability).await {
        answer(context, runtime, frame).await
    } else {
        nack("device_not_authorized")
    };
    crate::session::write_gateway_handle(send, &answer).await
}

async fn answer(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    frame: Client,
) -> Server {
    let anchor = runtime.source_identity.root_commitment().to_owned();
    let device_id = runtime.device_id.clone();
    let router = &context.router;
    match frame {
        Client::KeyPackagePublish { request } => {
            let call = KeyPackagePublishCall { anchor, device_id, request };
            match router_post_json_async::<_, KeyPackagePublishOutcome>(
                router,
                KEY_PACKAGE_PUBLISH_PATH,
                &call,
            )
            .await
            {
                Ok(response) => Server::KeyPackagePublished { response },
                Err(error) => failed(&error),
            }
        }
        Client::KeyPackageStatus {} => {
            let call = KeyPackageStatusCall { anchor, device_id };
            match router_post_json_async::<_, KeyPackageStatusResponse>(
                router,
                KEY_PACKAGE_STATUS_PATH,
                &call,
            )
            .await
            {
                Ok(response) => Server::KeyPackageStatus { response },
                Err(error) => failed(&error),
            }
        }
        Client::KeyPackageFetch { anchor: wanted } => {
            let call = KeyPackageFetchCall { anchor: wanted, requester: Some(anchor) };
            match router_post_json_async::<_, KeyPackageFetchResponse>(
                router,
                KEY_PACKAGE_FETCH_PATH,
                &call,
            )
            .await
            {
                Ok(response) => Server::KeyPackages { response },
                Err(error) => failed(&error),
            }
        }
        Client::DmOrder { request, orderer_node } => {
            let orderer_node =
                match crate::submit_target::route(&context.node_id, orderer_node.as_deref(), false)
                {
                    crate::submit_target::Route::Local => None,
                    crate::submit_target::Route::Remote(node) => Some(node.to_owned()),
                    crate::submit_target::Route::Refused(reason) => return nack(reason),
                };
            let call = DmOrderCall { anchor, orderer_node, op: request };
            match router_post_json_async::<_, DmOrderReply>(router, DM_ORDER_ROUTER_PATH, &call)
                .await
            {
                Ok(reply) => Server::DmOrder { reply },
                Err(error) => failed(&error),
            }
        }
        _ => nack("mls_dm_request_invalid"),
    }
}
