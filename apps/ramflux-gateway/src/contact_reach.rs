// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account/session binding before a reach owner operation leaves the gateway.
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_protocol::contact_reach::{
    GatewayReachRequest, MAX_FRAME_BYTES, Operation, OwnerKind, RECIPIENT_PATH, RecipientRequest,
    RecipientResponse, Response, decode,
};

pub(crate) fn recognizes(bytes: &[u8]) -> bool {
    ramflux_protocol::contact_reach::ephemeral_frame(bytes)
        || bytes.len() <= MAX_FRAME_BYTES
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
    if ramflux_protocol::contact_reach::ephemeral_frame(bytes) {
        let mut sink = send.lock().await;
        ramflux_transport::write_gateway_session_json(
            &mut **sink,
            &ramflux_protocol::contact_reach::unavailable(),
        )
        .await?;
        return Ok(());
    }
    let started = std::time::Instant::now();
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
        Operation::GroupRoster { roster, .. } => roster.header.body.recipient_root.as_str(),
        Operation::Policy { update } => update.body.account_anchor.as_str(),
        Operation::ProfilePublish { update, .. } => update.body.account_anchor.as_str(),
        Operation::Admission { update, .. }
        | Operation::Start { update, .. }
        | Operation::Reply { update, .. } => update.body.recipient_root.as_str(),
        _ => actor.account_anchor.as_str(),
    };
    check_snapshot(&request.operation, &runtime.session_id, ramflux_node_core::now_unix_seconds())?;
    let owner = RecipientRequest {
        kind: OwnerKind::Owner,
        request_id: request.request_id.clone(),
        remaining_ms: u64::try_from(
            std::time::Duration::from_millis(request.remaining_ms)
                .checked_sub(started.elapsed())
                .ok_or_else(|| anyhow::anyhow!("contact request deadline"))?
                .as_millis(),
        )?,
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
    owner.operation.validate_result(&response.result)?;
    remember_snapshot(
        &owner.operation,
        &response.result,
        &runtime.session_id,
        ramflux_node_core::now_unix_seconds(),
    )?;
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

// The exact owner DTO deliberately carries no client session fields. Keep gateway snapshot
// ownership separately so another session of the same device cannot continue a prior lease.
struct SnapshotOwner {
    session_id: String,
    expires_at: u64,
}
static SNAPSHOTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::BTreeMap<String, SnapshotOwner>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));

fn check_snapshot(operation: &Operation, session: &str, now: u64) -> anyhow::Result<()> {
    let Operation::ReachState { snapshot_id: Some(id), .. } = operation else { return Ok(()) };
    let mut snapshots =
        SNAPSHOTS.lock().map_err(|_| anyhow::anyhow!("snapshot owner lock unavailable"))?;
    snapshots.retain(|_, owner| owner.expires_at > now);
    anyhow::ensure!(
        snapshots.get(id).is_some_and(|owner| owner.session_id == session),
        "snapshot session mismatch"
    );
    Ok(())
}
fn remember_snapshot(
    operation: &Operation,
    result: &ramflux_protocol::contact_reach::OperationResult,
    session: &str,
    now: u64,
) -> anyhow::Result<()> {
    let Operation::ReachState { snapshot_id: None, .. } = operation else { return Ok(()) };
    let ramflux_protocol::contact_reach::OperationResult::ReachState { manifest, .. } = result
    else {
        return Ok(());
    };
    let body = &manifest.body;
    anyhow::ensure!(
        body.issued_at.checked_add(60) == Some(body.expires_at) && body.expires_at > now,
        "invalid snapshot lease"
    );
    let mut snapshots =
        SNAPSHOTS.lock().map_err(|_| anyhow::anyhow!("snapshot owner lock unavailable"))?;
    snapshots.retain(|_, owner| owner.expires_at > now);
    anyhow::ensure!(snapshots.len() < 2048, "snapshot ownership capacity");
    anyhow::ensure!(!snapshots.contains_key(&body.snapshot_id), "snapshot id reused");
    snapshots.insert(
        body.snapshot_id.clone(),
        SnapshotOwner { session_id: session.into(), expires_at: body.expires_at },
    );
    Ok(())
}
