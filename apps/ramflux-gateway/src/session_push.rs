// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Frozen capability binding and asynchronous durable-session adapters.
mod validation;
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime, RouterMeshClient};
use ramflux_node_core::{SessionPushClientFrame as Client, SessionPushNackReason as Reason};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(60);
const DISCOVERY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
#[derive(Default)]
pub(crate) struct Readiness {
    started: AtomicBool,
    ready: AtomicBool,
}
impl Readiness {
    pub(crate) fn start(self: &Arc<Self>, router: &RouterMeshClient) {
        self.start_with_interval(router, DISCOVERY_INTERVAL, DISCOVERY_PROBE_TIMEOUT);
    }
    fn start_with_interval(
        self: &Arc<Self>,
        router: &RouterMeshClient,
        period: Duration,
        probe_timeout: Duration,
    ) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        let router = router.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if weak.strong_count() == 0 {
                    return;
                }
                let result = tokio::time::timeout(
                    probe_timeout,
                    crate::router_get_json_async::<Value>(
                        &router,
                        "/mvp1/session-push-capabilities",
                    ),
                )
                .await;
                let ready =
                    result.ok().and_then(Result::ok).is_some_and(|value| capability_reply(&value));
                let Some(state) = weak.upgrade() else {
                    return;
                };
                state.ready.store(ready, Ordering::Release);
                drop(state);
            }
        });
    }
    pub(crate) fn supports(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}
fn capability_reply(value: &Value) -> bool {
    value.get("capabilities").and_then(Value::as_array).is_some_and(|caps| {
        caps.len() <= 64
            && caps.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 256))
            && caps.iter().any(|v| v == ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY)
    })
}
#[derive(Debug)]
pub(crate) struct Retired;
impl std::fmt::Display for Retired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("capable session router binding retired")
    }
}
impl std::error::Error for Retired {}
pub(crate) fn recognizes(bytes: &[u8], capable: bool) -> bool {
    #[derive(serde::Deserialize)]
    struct Tag {
        frame_type: String,
        #[serde(default)]
        incarnation_id: Option<String>,
    }
    serde_json::from_slice::<Tag>(bytes).is_ok_and(|tag| {
        matches!(tag.frame_type.as_str(), "fetch_entry" | "ack_batch")
            || ((capable || tag.incarnation_id.is_some())
                && matches!(tag.frame_type.as_str(), "resume" | "ack" | "nack"))
    })
}
pub(crate) async fn write(
    send: &GatewaySendHandle,
    value: &impl serde::Serialize,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    anyhow::ensure!(
        bytes.len() <= ramflux_node_core::ENTRY_FRAME_BYTE_CAP,
        "capable frame too large"
    );
    write_bytes(send, &bytes).await
}
async fn write_bytes(send: &GatewaySendHandle, bytes: &[u8]) -> anyhow::Result<()> {
    crate::push_queue::write_frame(send, bytes).await?;
    Ok(())
}
async fn nack(send: &GatewaySendHandle, id: &str, reason: Reason) -> anyhow::Result<()> {
    write(
        send,
        &ramflux_node_core::SessionPushServerFrame::Nack {
            reason,
            incarnation_id: Some(id.into()),
        },
    )
    .await
}
async fn post(context: &GatewayQuicContext, path: &str, body: &Value) -> anyhow::Result<Value> {
    let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
    let result = tokio::time::timeout(
        REQUEST_TIMEOUT,
        crate::router_post_json_until(&context.router, path, body, deadline),
    )
    .await;
    mesh_result(&context.hub.readiness, result)
}
async fn get(context: &GatewayQuicContext, path: &str) -> anyhow::Result<Value> {
    let result =
        tokio::time::timeout(REQUEST_TIMEOUT, crate::router_get_json_async(&context.router, path))
            .await;
    mesh_result(&context.hub.readiness, result)
}
fn mesh_result(
    readiness: &Readiness,
    result: Result<Result<Value, ramflux_transport::TransportError>, tokio::time::error::Elapsed>,
) -> anyhow::Result<Value> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(ramflux_transport::TransportError::HttpStatus { status: 400, body }))
            if body.len() <= ramflux_node_core::ENTRY_FRAME_BYTE_CAP =>
        {
            let value: Value = serde_json::from_str(&body).map_err(|_| Retired)?;
            anyhow::ensure!(
                value["reason"].is_string() && value.get("frame_type").is_none(),
                Retired
            );
            Ok(value)
        }
        Ok(Err(ramflux_transport::TransportError::HttpStatus {
            status: 404 | 405 | 410, ..
        })) => {
            readiness.ready.store(false, Ordering::Release);
            Err(Retired.into())
        }
        // Transport/5xx failures retire this session. They do not demote other sessions.
        _ => Err(Retired.into()),
    }
}
fn check_epoch(value: &Value, id: &str) -> anyhow::Result<()> {
    if value.get("incarnation_id").and_then(Value::as_str) != Some(id) {
        return Err(Retired.into());
    }
    Ok(())
}
async fn issued(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    id: &str,
) -> anyhow::Result<u64> {
    let value =
        post(context, "/mvp0/issued-seqs", &json!({"targets":[runtime.target_delivery_id]}))
            .await?;
    let rows = value["issued"].as_array().ok_or(Retired)?;
    anyhow::ensure!(
        rows.len() == 1 && rows[0]["target_delivery_id"] == runtime.target_delivery_id,
        Retired
    );
    check_epoch(&rows[0], id)?;
    rows[0]["inbox_seq"].as_u64().ok_or_else(|| Retired.into())
}
async fn router_refusal(send: &GatewaySendHandle, id: &str, value: &Value) -> anyhow::Result<bool> {
    if value.get("frame_type").is_some() {
        return Ok(false);
    }
    let Some(reason) = value.get("reason") else {
        return Ok(false);
    };
    if value.get("incarnation_id").is_some_and(|v| v != id) {
        return Err(Retired.into());
    }
    if reason == "incarnation_mismatch" {
        return Err(Retired.into());
    }
    let reason = serde_json::from_value::<Reason>(reason.clone()).map_err(|_| Retired)?;
    nack(send, id, reason).await?;
    Ok(true)
}
fn frame_id(frame: &Client) -> &str {
    match frame {
        Client::Resume { incarnation_id, .. }
        | Client::FetchEntry { incarnation_id, .. }
        | Client::AckBatch { incarnation_id, .. }
        | Client::Ack { incarnation_id, .. }
        | Client::Nack { incarnation_id, .. } => incarnation_id,
    }
}
#[cfg(test)]
pub(crate) async fn handle(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    bytes: &[u8],
) -> anyhow::Result<()> {
    handle_authorized(send, context, runtime, bytes, None).await
}
pub(crate) async fn handle_authorized(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    bytes: &[u8],
    native: Option<&crate::custody::GatewayGrant>,
) -> anyhow::Result<()> {
    let result = handle_bound(send, context, runtime, bytes, native).await;
    if result.as_ref().is_err_and(|e| e.downcast_ref::<Retired>().is_some())
        && let Some(id) = runtime.session_push.as_deref()
    {
        context.hub.retire_incarnation(&runtime.target_delivery_id, id, send).await;
    }
    result
}
async fn handle_bound(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    bytes: &[u8],
    native: Option<&crate::custody::GatewayGrant>,
) -> anyhow::Result<()> {
    if let Some(grant) = native
        && !matches!(
            tokio::time::timeout(
                REQUEST_TIMEOUT,
                crate::session::validate_native_frame(
                    context,
                    runtime,
                    grant,
                    &ramflux_node_core::GatewayClientFrame::Heartbeat { now: 0 }
                )
            )
            .await,
            Ok(Ok(()))
        )
    {
        crate::session::write_gateway_handle(
            send,
            &ramflux_node_core::GatewayServerFrame::Nack {
                reason: "native_session_authority_refused".into(),
            },
        )
        .await?;
        return Err(Retired.into());
    }
    let Some(id) = runtime.session_push.as_deref() else {
        return crate::session::write_gateway_handle(
            send,
            &ramflux_node_core::GatewayServerFrame::Nack {
                reason: "gateway_request_invalid".into(),
            },
        )
        .await;
    };
    if bytes.len() > ramflux_node_core::ENTRY_FRAME_BYTE_CAP {
        return nack(send, id, Reason::PayloadTooLarge).await;
    }
    let Ok(frame) = ramflux_protocol::parse_i_json::<Client>(bytes) else {
        return nack(send, id, Reason::GatewayRequestInvalid).await;
    };
    if !ramflux_node_core::valid_inbox_incarnation(frame_id(&frame)) || frame_id(&frame) != id {
        return nack(send, id, Reason::IncarnationMismatch).await;
    }
    if let Some(reason) = input_refusal(&frame, runtime) {
        return nack(send, id, reason).await;
    }
    match frame {
        Client::Resume { resume, .. } => resume_page(send, context, runtime, id, &resume).await,
        Client::FetchEntry { inbox_seq, .. } => {
            if inbox_seq == 0 {
                return nack(send, id, Reason::InvalidSeq).await;
            }
            if inbox_seq > issued(context, runtime, id).await? {
                return nack(send, id, Reason::InvalidSeq).await;
            }
            let response = get(
                context,
                &format!(
                    "/mvp1/inbox-entry/{}/{inbox_seq}?incarnation_id={id}",
                    runtime.target_delivery_id
                ),
            )
            .await?;
            if router_refusal(send, id, &response).await? {
                return Ok(());
            }
            check_epoch(&response, id)?;
            let bytes = validation::point(&response, &runtime.target_delivery_id, inbox_seq)?;
            write_bytes(send, &bytes).await
        }
        Client::AckBatch { inbox_seqs, .. } => {
            batch(send, context, runtime, id, inbox_seqs, false).await
        }
        Client::Ack { ack, .. } => {
            let Some(seq) = ack.ext.ext.get("inbox_seq").and_then(Value::as_u64) else {
                return nack(send, id, Reason::InvalidSeq).await;
            };
            batch(send, context, runtime, id, vec![seq], true).await
        }
        Client::Nack { nack: request, .. } => {
            apply_nack(send, context, runtime, id, &request).await
        }
    }
}
async fn apply_nack(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    id: &str,
    request: &ramflux_protocol::Nack,
) -> anyhow::Result<()> {
    let Some(seq) = request.ext.ext.get("inbox_seq").and_then(Value::as_u64) else {
        return nack(send, id, Reason::InvalidSeq).await;
    };
    if seq == 0 || seq > issued(context, runtime, id).await? {
        return nack(send, id, Reason::InvalidSeq).await;
    }
    let mut response=post(context,"/mvp0/nack-bound",&json!({"target_delivery_id":runtime.target_delivery_id,"incarnation_id":id,"nack":request})).await?;
    if router_refusal(send, id, &response).await? {
        return Ok(());
    }
    check_epoch(&response, id)?;
    anyhow::ensure!(
        response["cursor"]["target_delivery_id"] == runtime.target_delivery_id,
        Retired
    );
    response["frame_type"] = json!("cursor");
    write(send, &response).await
}

fn input_refusal(frame: &Client, runtime: &GatewaySessionRuntime) -> Option<Reason> {
    let valid_seq = |value: &Value| value.as_u64().is_some_and(|s| s > 0);
    match frame {
        Client::Resume { resume, .. }
            if resume.target_delivery_id != runtime.target_delivery_id
                || resume.resume_token != runtime.resume_token =>
        {
            Some(Reason::InvalidResumeToken)
        }
        Client::Resume { resume, .. } if resume.limit == 0 => Some(Reason::InvalidLimit),
        Client::FetchEntry { inbox_seq: 0, .. } => Some(Reason::InvalidSeq),
        Client::AckBatch { inbox_seqs, .. }
            if inbox_seqs.is_empty()
                || inbox_seqs.len() > 64
                || inbox_seqs.contains(&0)
                || inbox_seqs.windows(2).any(|p| p[0] >= p[1]) =>
        {
            Some(Reason::InvalidSeq)
        }
        Client::Ack { ack, .. } if ack.ext.ext.get("inbox_seq").is_none_or(|v| !valid_seq(v)) => {
            Some(Reason::InvalidSeq)
        }
        Client::Nack { nack, .. }
            if nack.ext.ext.get("inbox_seq").is_none_or(|v| !valid_seq(v)) =>
        {
            Some(Reason::InvalidSeq)
        }
        _ => None,
    }
}

async fn resume_page(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    id: &str,
    resume: &ramflux_node_core::GatewayResumeFrame,
) -> anyhow::Result<()> {
    if resume.target_delivery_id != runtime.target_delivery_id
        || resume.resume_token != runtime.resume_token
    {
        return nack(send, id, Reason::InvalidResumeToken).await;
    }
    if resume.limit == 0 {
        return nack(send, id, Reason::InvalidLimit).await;
    }
    let mut response = get(
        context,
        &format!(
            "/mvp1/inbox/{}?after={}&limit={}&session_push=1&incarnation_id={id}",
            runtime.target_delivery_id,
            resume.after_inbox_seq,
            resume.limit.min(256)
        ),
    )
    .await?;
    if router_refusal(send, id, &response).await? {
        return Ok(());
    }
    check_epoch(&response, id)?;
    response["frame_type"] = json!("resume_page");
    let bytes = validation::page(
        &response,
        &runtime.target_delivery_id,
        resume.after_inbox_seq,
        resume.limit.min(256),
    )?;
    write_bytes(send, &bytes).await
}

async fn batch(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    id: &str,
    seqs: Vec<u64>,
    single: bool,
) -> anyhow::Result<()> {
    if seqs.is_empty()
        || seqs.len() > 64
        || seqs.contains(&0)
        || seqs.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return nack(send, id, Reason::InvalidSeq).await;
    }
    let published = issued(context, runtime, id).await?;
    if seqs.iter().any(|s| *s > published) {
        return nack(send, id, Reason::InvalidSeq).await;
    }
    let mut response=post(context,"/mvp0/ack-bound-batch",&json!({"target_delivery_id":runtime.target_delivery_id,"incarnation_id":id,"inbox_seqs":seqs})).await?;
    if router_refusal(send, id, &response).await? {
        return Ok(());
    }
    check_epoch(&response, id)?;
    validation::batch(&response, &runtime.target_delivery_id, &seqs)?;
    if single {
        response.as_object_mut().ok_or(Retired)?.remove("results");
    }
    response["frame_type"] = json!(if single { "ack" } else { "ack_batch" });
    write(send, &response).await
}
/// Decode additive mesh metadata without changing the legacy public response type.
pub(crate) fn metadata(value: &Value, required: bool) -> anyhow::Result<Option<(String, i64)>> {
    let id = value.get("incarnation_id").and_then(Value::as_str);
    let deadline = value.get("retain_until").and_then(Value::as_i64);
    match (id, deadline) {
        (Some(id), Some(deadline)) if ramflux_node_core::valid_inbox_incarnation(id) => {
            Ok(Some((id.into(), deadline)))
        }
        (None, None) if !required => Ok(None),
        _ => Err(Retired.into()),
    }
}
pub(crate) fn submit_refused(outcome: &str) -> bool {
    outcome.starts_with("rejected_")
        || matches!(
            outcome,
            "forward_in_progress"
                | "capacity_retry_after"
                | "incarnation_mismatch"
                | "invalid_seq"
                | "aborted_retry_safe"
                | "idempotency_conflict"
                | "payload_too_large"
        )
}

pub(crate) async fn submit_reply(
    send: &GatewaySendHandle,
    runtime: &GatewaySessionRuntime,
    response: &ramflux_node_core::EnvelopeSubmitResponse,
    envelope: &ramflux_protocol::Envelope,
    legacy: &ramflux_node_core::GatewayServerFrame,
    metadata: Option<&(String, i64)>,
) -> anyhow::Result<()> {
    if let Some(expected) = runtime.session_push.as_deref() {
        let (id, _) = metadata.ok_or(Retired)?;
        anyhow::ensure!(
            response.target_delivery_id != runtime.target_delivery_id || id == expected,
            Retired
        );
        let inbox_seq = response.inbox_seq.filter(|s| *s > 0).ok_or(Retired)?;
        write(
            send,
            &ramflux_node_core::SessionPushServerFrame::SubmitAccepted {
                incarnation_id: id.clone(),
                envelope_id: envelope.envelope_id.clone(),
                target_delivery_id: response.target_delivery_id.clone(),
                inbox_seq,
            },
        )
        .await
    } else {
        crate::session::write_gateway_handle(send, legacy).await
    }
}

pub(crate) async fn negotiate(
    context: &GatewayQuicContext,
    auth: &ramflux_node_core::GatewayAuthFrame,
    descriptor: &ramflux_node_core::SessionDescriptor,
) -> anyhow::Result<Option<String>> {
    context.hub.readiness.start(&context.router);
    crate::issued_probe::start(&context.hub, &context.router);
    let capable = context.hub.readiness.supports()
        && auth
            .device_proof
            .capability_scope
            .iter()
            .any(|s| s == ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY);
    if capable {
        match capable_registration(context, descriptor).await {
            Ok(id) => return Ok(Some(id)),
            Err(error) => {
                // post() clears readiness only when the capable route is gone.
                tracing::debug!(%error,"capable registration unavailable; selecting compatibility");
            }
        }
    }
    let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
    let _: ramflux_node_core::SessionDescriptor = tokio::time::timeout(
        REQUEST_TIMEOUT,
        crate::router_post_json_until(&context.router, "/s1/session/upsert", descriptor, deadline),
    )
    .await??;
    Ok(None)
}
async fn capable_registration(
    context: &GatewayQuicContext,
    descriptor: &ramflux_node_core::SessionDescriptor,
) -> anyhow::Result<String> {
    let request = ramflux_node_core::SessionPushSessionRequest {
        session: descriptor.clone(),
        session_push: true,
        ephemeral: false,
    };
    let response = post(context, "/s1/session", &serde_json::to_value(request)?).await?;
    let id = response["incarnation_id"]
        .as_str()
        .filter(|id| ramflux_node_core::valid_inbox_incarnation(id))
        .ok_or(Retired)?;
    anyhow::ensure!(
        response["target_delivery_id"] == descriptor.target_delivery_id
            && response["session_id"] == descriptor.session_id,
        Retired
    );
    Ok(id.into())
}

pub(crate) async fn established(
    send: &mut (impl ramflux_transport::GatewaySessionFrameSink + ?Sized),
    session: ramflux_node_core::GatewaySessionEstablishedFrame,
    id: Option<&str>,
) -> anyhow::Result<()> {
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        if let Some(id) = id {
            crate::session::write_gateway_frame(
                send,
                &ramflux_node_core::SessionPushServerFrame::SessionEstablished {
                    session: ramflux_node_core::SessionPushEstablishedFrame {
                        session,
                        capabilities: vec![
                            ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into(),
                        ],
                        inbox_incarnation_id: id.into(),
                    },
                },
            )
            .await
        } else {
            crate::session::write_gateway_frame(
                send,
                &ramflux_node_core::GatewayServerFrame::SessionEstablished { session },
            )
            .await
        }
    })
    .await;
    result.map_err(|_| {
        crate::session_response::ClientWriteFailure(ramflux_transport::TransportError::Quic(
            "session establishment write deadline".into(),
        ))
    })?
}

#[cfg(test)]
pub(crate) mod tests;
