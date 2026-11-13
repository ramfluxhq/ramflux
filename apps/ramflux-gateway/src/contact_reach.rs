// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account/session binding before a reach owner operation leaves the gateway.
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_protocol::contact_reach::*;

pub(crate) fn recognizes(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_FRAME_BYTES
        && ramflux_protocol::parse_i_json::<serde_json::Value>(bytes).is_ok_and(|v| {
            v.get("frame_type").and_then(serde_json::Value::as_str) == Some("contact_foreign")
        })
}

pub(crate) async fn handle(
    bytes: &[u8],
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    native: Option<&crate::custody::GatewayGrant>,
) -> anyhow::Result<()> {
    let frame: GatewayReachRequest = decode(bytes, MAX_FRAME_BYTES)?;
    let request = frame.request;
    request.validate()?;
    let grant = native.ok_or_else(|| anyhow::anyhow!("contact reach requires native session"))?;
    anyhow::ensure!(
        grant.live(ramflux_node_core::now_unix_seconds()),
        "contact reach session expired"
    );
    anyhow::ensure!(
        request.session_id == runtime.session_id && request.session_generation == 1,
        "contact reach session correlation mismatch"
    );
    let actor = &grant.session().device_ref;
    anyhow::ensure!(
        actor.account_anchor == runtime.source_identity.root_commitment()
            && actor.device_id == runtime.device_id
            && actor.device_epoch == runtime.device_epoch,
        "contact reach source binding changed"
    );
    let root = match &request.operation {
        Operation::Policy { update } => update.body.account_anchor.as_str(),
        Operation::ProfilePublish { update, .. } => update.body.account_anchor.as_str(),
        Operation::Admission { update, .. }
        | Operation::Start { update, .. }
        | Operation::Reply { update, .. } => update.body.recipient_root.as_str(),
        _ => actor.account_anchor.as_str(),
    };
    let owner = RecipientRequest {
        kind: OwnerKind::Owner,
        request_id: request.request_id.clone(),
        remaining_ms: request.remaining_ms,
        recipient_root: root.into(),
        actor: actor.clone(),
        operation: request.operation,
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(owner.remaining_ms);
    let response: RecipientResponse =
        crate::clients::router_post_json_until(&context.router, RECIPIENT_PATH, &owner, deadline)
            .await?;
    anyhow::ensure!(
        response.request_id == request.request_id,
        "contact reach owner correlation mismatch"
    );
    let response = ramflux_node_core::GatewayServerFrame::ContactForeignResult {
        response: Box::new(Response {
            request_id: request.request_id,
            session_id: request.session_id,
            session_generation: request.session_generation,
            result: response.result,
        }),
    };
    let mut sink = send.lock().await;
    ramflux_transport::write_gateway_session_json(&mut **sink, &response).await?;
    Ok(())
}
