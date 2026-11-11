// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Frozen capability binding and asynchronous durable-session adapters.
mod validation;
use crate::{
    GatewayQuicContext, GatewaySendHandle, GatewaySessionHub, GatewaySessionRuntime,
    RouterMeshClient,
};
use ramflux_node_core::{SessionPushClientFrame as Client, SessionPushNackReason as Reason};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
tokio::task_local! {
    /// A manual expiry for the next router request of the task under test: the
    /// test fires it only after its fixture has captured the held request.
    static NEXT_REQUEST_EXPIRY: std::cell::Cell<Option<tokio::sync::oneshot::Receiver<()>>>;
}
/// Bounds one router request by `REQUEST_TIMEOUT`; a test may also end it
/// early through `NEXT_REQUEST_EXPIRY`, reported as the same `Elapsed`.
async fn bounded<T>(
    request: impl std::future::Future<Output = T>,
) -> Result<T, tokio::time::error::Elapsed> {
    #[cfg(test)]
    if let Some(expiry) = NEXT_REQUEST_EXPIRY.try_with(std::cell::Cell::take).ok().flatten() {
        let fired = async {
            if expiry.await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        return tokio::select! {
            out = tokio::time::timeout(REQUEST_TIMEOUT, request) => out,
            () = fired => tokio::time::timeout(Duration::ZERO, std::future::pending::<T>()).await,
        };
    }
    tokio::time::timeout(REQUEST_TIMEOUT, request).await
}
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(60);
const DISCOVERY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct DiscoveryClock {
    now_ms: Arc<tokio::sync::watch::Sender<u64>>,
}

#[cfg(test)]
impl DiscoveryClock {
    pub(crate) fn new() -> Self {
        let (now_ms, _) = tokio::sync::watch::channel(0);
        Self { now_ms: Arc::new(now_ms) }
    }

    pub(crate) fn advance(&self, by: Duration) {
        let ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.now_ms.send_modify(|now| *now = now.saturating_add(ms));
    }

    fn now_ms(&self) -> u64 {
        *self.now_ms.borrow()
    }

    async fn wait_until(&self, deadline: u64) {
        let mut rx = self.now_ms.subscribe();
        while *rx.borrow() < deadline {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct Readiness {
    started: AtomicBool,
    ready: AtomicBool,
    ephemeral: AtomicBool,
    refused_boot: Mutex<Option<String>>,
    #[cfg(test)]
    clock: Mutex<Option<DiscoveryClock>>,
}
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct NegotiatedBinding {
    pub incarnation_id: Option<String>,
    pub ephemeral: bool,
}
struct CapabilityEcho {
    session_push: bool,
    ephemeral: bool,
    boot_id: Option<String>,
}
impl Readiness {
    /// Fixtures that own every mesh request keep the discovery probe from starting.
    #[cfg(test)]
    pub(crate) fn suppress_discovery_for_test(&self) {
        self.started.store(true, Ordering::Release);
    }
    /// Test router advertisement: session-push and optional `gateway.ephemeral.v1`.
    #[cfg(test)]
    pub(crate) fn seed_echo_for_test(&self, session_push: bool, ephemeral: bool) {
        self.started.store(true, Ordering::Release);
        self.ready.store(session_push, Ordering::Release);
        self.ephemeral.store(session_push && ephemeral, Ordering::Release);
    }
    pub(crate) fn start_with_hub(
        self: &Arc<Self>,
        router: &RouterMeshClient,
        hub: &Arc<GatewaySessionHub>,
        gateway_id: &str,
    ) {
        self.start_with_interval(
            router,
            DISCOVERY_INTERVAL,
            DISCOVERY_PROBE_TIMEOUT,
            Some(Arc::downgrade(hub)),
            Some(gateway_id.to_owned()),
        );
    }
    #[cfg(test)]
    pub(crate) fn set_discovery_clock(&self, clock: DiscoveryClock) {
        *self.clock.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(clock);
    }

    pub(crate) fn start_with_interval(
        self: &Arc<Self>,
        router: &RouterMeshClient,
        period: Duration,
        probe_timeout: Duration,
        hub: Option<Weak<GatewaySessionHub>>,
        gateway_id: Option<String>,
    ) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        let router = router.clone();
        #[cfg(test)]
        let clock = self.clock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            #[cfg(test)]
            let mut next_tick_ms = 0u64;
            loop {
                #[cfg(test)]
                {
                    if let Some(ref clock) = clock {
                        clock.wait_until(next_tick_ms).await;
                        next_tick_ms = clock
                            .now_ms()
                            .saturating_add(u64::try_from(period.as_millis()).unwrap_or(u64::MAX));
                    } else {
                        interval.tick().await;
                    }
                }
                #[cfg(not(test))]
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
                let echo = result
                    .ok()
                    .and_then(Result::ok)
                    .and_then(|value| parse_capability_echo(&value));
                let Some(state) = weak.upgrade() else {
                    return;
                };
                let session_push = echo.as_ref().is_some_and(|echo| echo.session_push);
                let ephemeral = session_push && echo.as_ref().is_some_and(|echo| echo.ephemeral);
                state.ready.store(session_push, Ordering::Release);
                state.ephemeral.store(ephemeral, Ordering::Release);
                if let Some(boot) = echo.as_ref().and_then(|echo| echo.boot_id.as_deref()) {
                    reassert_if_boot_changed(
                        &state,
                        &router,
                        hub.as_ref(),
                        gateway_id.as_deref(),
                        boot,
                    )
                    .await;
                }
                drop(state);
            }
        });
    }
    pub(crate) fn supports(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    pub(crate) fn supports_ephemeral(&self) -> bool {
        self.ephemeral.load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(crate) async fn reassert_boot(
        self: &Arc<Self>,
        router: &RouterMeshClient,
        hub: &Arc<GatewaySessionHub>,
        gateway_id: &str,
        boot: &str,
    ) {
        reassert_if_boot_changed(self, router, Some(&Arc::downgrade(hub)), Some(gateway_id), boot)
            .await;
    }
}
fn parse_capability_echo(value: &Value) -> Option<CapabilityEcho> {
    let caps = value.get("capabilities")?.as_array()?;
    if caps.len() > 64
        || !caps.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 256))
    {
        return None;
    }
    let session_push =
        caps.iter().any(|v| v.as_str() == Some(ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY));
    let ephemeral = session_push
        && caps
            .iter()
            .any(|v| v.as_str() == Some(ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY));
    let boot_id = value
        .get("router_boot_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 256)
        .map(str::to_owned);
    Some(CapabilityEcho { session_push, ephemeral, boot_id })
}
async fn reassert_if_boot_changed(
    state: &Readiness,
    router: &RouterMeshClient,
    hub: Option<&Weak<GatewaySessionHub>>,
    gateway_id: Option<&str>,
    boot: &str,
) {
    let Some(hub) = hub.and_then(Weak::upgrade) else {
        return;
    };
    let Some(gateway_id) = gateway_id else {
        return;
    };
    if state.refused_boot.lock().is_ok_and(|refused_boot| refused_boot.as_deref() == Some(boot)) {
        return;
    }
    let items = hub.ephemeral_registrations(gateway_id, boot).await;
    if items.is_empty() {
        return;
    }
    let mut posted = 0_usize;
    for chunk in items.chunks(ramflux_node_core::EPHEMERAL_REASSERTION_ITEM_BOUND) {
        let body = json!({"router_boot_id": boot, "items": chunk});
        let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
        let result = tokio::time::timeout(
            REQUEST_TIMEOUT,
            crate::router_post_json_until::<Value, Value>(
                router,
                "/mvp0/ephemeral-registrations",
                &body,
                deadline,
            ),
        )
        .await;
        match result {
            Ok(Ok(response)) if response["applied"].as_u64() == u64::try_from(chunk.len()).ok() => {
            }
            Ok(Err(error)) if crate::registration::gateway_instance_rejection(&error) => {
                crate::registration::log_gateway_identity_rejection(&error);
                if let Ok(mut refused_boot) = state.refused_boot.lock() {
                    *refused_boot = Some(boot.to_owned());
                }
                return;
            }
            _ => break,
        }
        posted = posted.saturating_add(chunk.len());
    }
    if posted > 0 {
        hub.stamp_ephemeral_boot(boot, &items[..posted]).await;
    }
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
    }
    capable
        && serde_json::from_slice::<Tag>(bytes).is_ok_and(|tag| {
            matches!(
                tag.frame_type.as_str(),
                "fetch_entry" | "ack_batch" | "resume" | "ack" | "nack"
            )
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
    let result =
        bounded(crate::router_post_json_until(&context.router, path, body, deadline)).await;
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
        Ok(Err(error)) if crate::registration::log_gateway_identity_rejection(&error) => {
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
        let (observed, _) = metadata.ok_or(Retired)?;
        anyhow::ensure!(
            response.target_delivery_id != runtime.target_delivery_id || observed == expected,
            Retired
        );
        let inbox_seq = response.inbox_seq.filter(|s| *s > 0).ok_or(Retired)?;
        // submit_accepted is the sender session T/E. Mesh metadata E is the
        // recipient inbox and belongs only on the Deliver frame.
        write(
            send,
            &ramflux_node_core::SessionPushServerFrame::SubmitAccepted {
                incarnation_id: expected.to_owned(),
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
) -> anyhow::Result<NegotiatedBinding> {
    context.hub.readiness.start_with_hub(&context.router, &context.hub, &context.gateway_id);
    crate::issued_probe::start(&context.hub, &context.router);
    let capable = context.hub.readiness.supports()
        && auth
            .device_proof
            .capability_scope
            .iter()
            .any(|s| s == ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY);
    let ephemeral = capable && context.hub.readiness.supports_ephemeral();
    if capable {
        match capable_registration(context, descriptor, ephemeral).await {
            Ok(id) => {
                return Ok(NegotiatedBinding { incarnation_id: Some(id), ephemeral });
            }
            Err(error) => {
                // post() clears readiness only when the capable route is gone.
                tracing::debug!(%error,"capable registration unavailable; selecting compatibility");
            }
        }
    }
    let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
    let upsert = tokio::time::timeout(
        REQUEST_TIMEOUT,
        crate::router_post_json_until(&context.router, "/s1/session/upsert", descriptor, deadline),
    )
    .await;
    let _: ramflux_node_core::SessionDescriptor = match upsert {
        Ok(Ok(descriptor)) => descriptor,
        Ok(Err(error)) => {
            let _ = crate::registration::log_gateway_identity_rejection(&error);
            return Err(error.into());
        }
        Err(elapsed) => return Err(elapsed.into()),
    };
    Ok(NegotiatedBinding { incarnation_id: None, ephemeral: false })
}
async fn capable_registration(
    context: &GatewayQuicContext,
    descriptor: &ramflux_node_core::SessionDescriptor,
    ephemeral: bool,
) -> anyhow::Result<String> {
    let request = ramflux_node_core::SessionPushSessionRequest {
        session: descriptor.clone(),
        session_push: true,
        ephemeral,
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

fn established_capabilities(ephemeral: bool) -> Vec<String> {
    let mut capabilities = vec![ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into()];
    if ephemeral {
        capabilities.push(ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.into());
    }
    capabilities
}

pub(crate) async fn established(
    send: &mut (impl ramflux_transport::GatewaySessionFrameSink + ?Sized),
    session: ramflux_node_core::GatewaySessionEstablishedFrame,
    id: Option<&str>,
    ephemeral: bool,
) -> anyhow::Result<()> {
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        if let Some(id) = id {
            crate::session::write_gateway_frame(
                send,
                &ramflux_node_core::SessionPushServerFrame::SessionEstablished {
                    session: ramflux_node_core::SessionPushEstablishedFrame {
                        session,
                        capabilities: established_capabilities(ephemeral),
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
