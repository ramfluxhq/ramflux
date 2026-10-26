// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keeps this device's push route registered with its home node.
//!
//! The node assigns a sliding 30-day route lifetime. The engine registers the configured route
//! after every authenticated session (re)connect, again whenever the token changes, and renews
//! it from [`GatewaySessionEngine::ensure_live`] once less than 15 days remain, so a device left
//! in the background keeps receiving wakes. Registration never blocks the session: the frame is
//! written outside the connect timeout and its answer is matched by request id whenever it
//! arrives. Clearing the route deregisters it; revoking the device deletes it on the node.
#![allow(clippy::wildcard_imports)]
use super::{GatewaySessionEngine, write_gateway_client_frame};
use crate::prelude::*;

/// Gateway path the registration request is signed for.
pub const GATEWAY_PUSH_ROUTE_PATH: &str = "/notify/v1/push-route";
/// Gateway path the deregistration request is signed for.
pub const GATEWAY_PUSH_ROUTE_DELETE_PATH: &str = "/notify/v1/push-route/delete";
/// Re-register once less than this much node-assigned route lifetime remains.
pub const GATEWAY_PUSH_ROUTE_RENEW_BEFORE_SECONDS: u64 = 15 * 86_400;

#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayPushProvider {
    Apns,
    Fcm,
    #[serde(rename = "webpush")]
    WebPush,
}

/// Provider credential for this device. Owner, mailbox and lifetime are assigned by the node.
///
/// Optional fields serialize as `null`: the signed body hash covers the canonical form the
/// gateway recomputes.
#[derive(Clone, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayPushRouteRegistration {
    pub provider: GatewayPushProvider,
    pub token: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub webpush_p256dh: Option<String>,
    #[serde(default)]
    pub webpush_auth: Option<String>,
}

impl std::fmt::Debug for GatewayPushRouteRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayPushRouteRegistration")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayPushRouteFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub body: GatewayPushRouteRegistration,
}

/// Explicit deregistration of this device's route (`None` removes every provider).
#[derive(Clone, Debug, Default, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayPushRouteDeregistration {
    #[serde(default)]
    pub provider: Option<GatewayPushProvider>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct GatewayPushRouteDeregistrationFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub body: GatewayPushRouteDeregistration,
}

/// Why the node refused push route control (mirrors the node's refusal codes).
#[derive(Clone, Copy, Debug, Default, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayPushRouteRefusal {
    ProviderUnavailable,
    #[default]
    Rejected,
    Unavailable,
    Superseded,
    /// A code from a newer node; retried like `unavailable` so it never breaks the session.
    #[serde(other)]
    Unknown,
}

/// Frames other than push answers that a waiting `set_push_route` keeps for later readers.
const PUSH_ROUTE_STASH_LIMIT: usize = 64;

/// Whether a route that expires at `expires_at` must be registered again at `now`.
#[must_use]
pub fn push_route_renewal_due(expires_at: Option<u64>, now: u64) -> bool {
    expires_at.is_none_or(|expires_at| {
        expires_at.saturating_sub(now) < GATEWAY_PUSH_ROUTE_RENEW_BEFORE_SECONDS
    })
}

/// Bound for writing a registration frame; the reply is awaited only by explicit callers.
const PUSH_ROUTE_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// How long an explicit caller waits for the node's answer.
const PUSH_ROUTE_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// After this long without an answer a control is considered lost (counted as a failure).
const PUSH_ROUTE_RETRY_AFTER_SECONDS: u64 = 60;
/// First retry delay after a transient failure; doubles per consecutive failure.
const PUSH_ROUTE_BACKOFF_BASE_SECONDS: u64 = 30;
/// Ceiling for the transient-failure backoff.
const PUSH_ROUTE_BACKOFF_MAX_SECONDS: u64 = 6 * 3_600;
/// Wait after a permanent refusal (no provider credential, request rejected) unless the
/// token changes first.
const PUSH_ROUTE_PERMANENT_RETRY_SECONDS: u64 = 24 * 3_600;

/// Registration or deregistration awaiting the node's answer.
#[derive(Clone, Debug)]
pub(crate) struct PendingPushRoute {
    request_id: String,
    sent_at: u64,
    deregister: bool,
}

/// Retry state for push route control; kept in the session config so it survives reconnects.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PushRouteRetry {
    failures: u32,
    not_before: u64,
}

impl PushRouteRetry {
    /// Delay after `failures` consecutive transient failures, with up to 20% random jitter.
    #[must_use]
    pub fn transient_delay(failures: u32, jitter: u8) -> u64 {
        let exponent = failures.saturating_sub(1).min(20);
        let delay = PUSH_ROUTE_BACKOFF_BASE_SECONDS
            .saturating_mul(1 << exponent)
            .min(PUSH_ROUTE_BACKOFF_MAX_SECONDS);
        delay.saturating_add(delay.saturating_mul(u64::from(jitter % 21)) / 100)
    }

    fn record(&mut self, code: GatewayPushRouteRefusal, sent_at: u64) {
        match code {
            GatewayPushRouteRefusal::Superseded => {}
            GatewayPushRouteRefusal::ProviderUnavailable | GatewayPushRouteRefusal::Rejected => {
                self.failures = 0;
                self.not_before = sent_at.saturating_add(PUSH_ROUTE_PERMANENT_RETRY_SECONDS);
            }
            GatewayPushRouteRefusal::Unavailable | GatewayPushRouteRefusal::Unknown => {
                self.failures = self.failures.saturating_add(1);
                let jitter = ramflux_crypto::random_32().map_or(0, |bytes| bytes[0]);
                self.not_before =
                    sent_at.saturating_add(Self::transient_delay(self.failures, jitter));
            }
        }
    }
}

impl GatewaySessionEngine {
    /// Node-assigned expiry of the last successful registration in this session.
    #[must_use]
    pub const fn push_route_expires_at(&self) -> Option<u64> {
        self.push_route_expires_at
    }

    /// Replaces the device's push route (for example after a token rotation) and registers it
    /// now; `None` sends an explicit deregistration that deletes the node's route and keeps
    /// retrying it with backoff until the node confirms. Waits a bounded time for the answer;
    /// a later answer is still matched by request id. A drain or close frame that arrives
    /// meanwhile ends the wait and stays queued for the next reader.
    /// # Errors
    /// Returns transport, signing, refusal or session-ending errors.
    pub async fn set_push_route(
        &mut self,
        registration: Option<GatewayPushRouteRegistration>,
    ) -> Result<Option<u64>, SdkError> {
        if self.config.push_route != registration {
            self.push_route_expires_at = None;
        }
        // A token change (or a clear) is a new intent: it is never held back by old backoff.
        self.config.push_route_retry = PushRouteRetry::default();
        self.config.push_route_clear_pending = registration.is_none();
        self.config.push_route.clone_from(&registration);
        let now = now_unix_timestamp().unsigned_abs();
        let request_id = if registration.is_some() {
            self.send_push_route_registration(now).await?
        } else {
            self.send_push_route_deregistration(now).await?
        };
        let Some(request_id) = request_id else {
            return Ok(None);
        };
        match tokio::time::timeout(PUSH_ROUTE_REPLY_TIMEOUT, self.await_push_reply(&request_id))
            .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(SdkError::GatewaySessionRejected(
                "push route answer pending; it will be applied when it arrives".to_owned(),
            )),
        }
    }

    /// Sends the configured registration without waiting for the answer.
    /// # Errors
    /// Returns signing or transport write errors.
    pub async fn register_push_route(&mut self) -> Result<Option<String>, SdkError> {
        self.send_push_route_registration(now_unix_timestamp().unsigned_abs()).await
    }

    async fn send_push_route_registration(&mut self, now: u64) -> Result<Option<String>, SdkError> {
        let Some(body) = self.config.push_route.clone() else {
            return Ok(None);
        };
        let signed_request = self.session_bound_request(GATEWAY_PUSH_ROUTE_PATH, &body)?;
        let request_id = signed_request.request_id.clone();
        self.write_push_route_frame(GatewayClientFrame::PushRouteRegister {
            request: Box::new(GatewayPushRouteFrame { signed_request, body }),
        })
        .await?;
        self.pending_push_route = Some(PendingPushRoute {
            request_id: request_id.clone(),
            sent_at: now,
            deregister: false,
        });
        Ok(Some(request_id))
    }

    async fn send_push_route_deregistration(
        &mut self,
        now: u64,
    ) -> Result<Option<String>, SdkError> {
        let body = GatewayPushRouteDeregistration { provider: None };
        let signed_request = self.session_bound_request(GATEWAY_PUSH_ROUTE_DELETE_PATH, &body)?;
        let request_id = signed_request.request_id.clone();
        self.write_push_route_frame(GatewayClientFrame::PushRouteDeregister {
            request: Box::new(GatewayPushRouteDeregistrationFrame { signed_request, body }),
        })
        .await?;
        self.pending_push_route = Some(PendingPushRoute {
            request_id: request_id.clone(),
            sent_at: now,
            deregister: true,
        });
        Ok(Some(request_id))
    }

    fn session_bound_request<T: serde::Serialize>(
        &mut self,
        path: &str,
        body: &T,
    ) -> Result<ramflux_protocol::SignedRequest, SdkError> {
        let mut signed_request = self.signed_request("POST", path, "already_authed", body)?;
        signed_request
            .ext
            .ext
            .insert("session_id".to_owned(), serde_json::json!(self.session.session_id));
        // Strictly increasing per device: the node refuses a registration older than its last
        // confirmed deregistration, whatever order the two finish in.
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis()),
        )
        .unwrap_or(u64::MAX);
        let seq = now_ms.max(self.config.push_route_last_seq.saturating_add(1));
        self.config.push_route_last_seq = seq;
        signed_request.ext.ext.insert("push_route_seq".to_owned(), serde_json::json!(seq));
        let branch = self.config.device_branch.as_ref().ok_or_else(|| {
            SdkError::GatewaySessionRejected("missing registered device branch".to_owned())
        })?;
        signed_request.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(branch, &signed_request)?;
        Ok(signed_request)
    }

    async fn write_push_route_frame(&mut self, frame: GatewayClientFrame) -> Result<(), SdkError> {
        tokio::time::timeout(
            PUSH_ROUTE_SEND_TIMEOUT,
            write_gateway_client_frame(&mut *self.stream, &frame),
        )
        .await
        .map_err(|_| SdkError::GatewaySessionRejected("push route send timed out".to_owned()))?
    }

    /// Reads frames until the answer to `request_id`, buffering deliveries meanwhile. Any other
    /// frame is kept for the next reader; a drain or close also ends the wait.
    async fn await_push_reply(&mut self, request_id: &str) -> Result<Option<u64>, SdkError> {
        // Read the stream, never the deferred queue: a stashed frame is not seen again here,
        // so every iteration awaits I/O and the caller's timeout can always fire.
        let mut stash = Vec::new();
        let outcome = self.await_push_reply_into(request_id, &mut stash).await;
        self.deferred_frames.extend(stash);
        outcome
    }

    async fn await_push_reply_into(
        &mut self,
        request_id: &str,
        stash: &mut Vec<GatewayServerFrame>,
    ) -> Result<Option<u64>, SdkError> {
        loop {
            let frame = self.read_stream_frame("push route answer").await?;
            match frame {
                GatewayServerFrame::Deliver { entry } => self.pending_deliveries.push_back(entry),
                frame if is_push_route_reply(&frame) => {
                    let matched = push_route_reply_id(&frame) == Some(request_id);
                    let outcome = self.apply_push_route_reply(frame);
                    if matched {
                        return outcome;
                    }
                }
                frame @ (GatewayServerFrame::Drain { .. } | GatewayServerFrame::Close { .. }) => {
                    stash.push(frame);
                    return Err(SdkError::GatewaySessionRejected(
                        "gateway session is ending; push route answer pending".to_owned(),
                    ));
                }
                frame => {
                    stash.push(frame);
                    if stash.len() >= PUSH_ROUTE_STASH_LIMIT {
                        return Err(SdkError::GatewaySessionRejected(
                            "too many unrelated frames while waiting for a push route answer"
                                .to_owned(),
                        ));
                    }
                }
            }
        }
    }

    /// Applies a push route answer and its retry consequence; answers to superseded requests
    /// only update state.
    pub(crate) fn apply_push_route_reply(
        &mut self,
        frame: GatewayServerFrame,
    ) -> Result<Option<u64>, SdkError> {
        let id = push_route_reply_id(&frame).map(str::to_owned);
        let pending =
            self.pending_push_route.take_if(|pending| Some(&pending.request_id) == id.as_ref());
        match frame {
            GatewayServerFrame::PushRouteRegistered { expires_at, .. } => {
                if pending.is_some() {
                    self.config.push_route_retry = PushRouteRetry::default();
                }
                if self.config.push_route.is_some() {
                    self.push_route_expires_at = Some(expires_at);
                }
                Ok(Some(expires_at))
            }
            GatewayServerFrame::PushRouteDeregistered { .. } => {
                if pending.is_some() {
                    self.config.push_route_retry = PushRouteRetry::default();
                    self.config.push_route_clear_pending = false;
                }
                self.push_route_expires_at = None;
                Ok(None)
            }
            GatewayServerFrame::PushRouteRefused { reason, code, .. } => {
                if let Some(pending) = pending {
                    if pending.deregister && code == GatewayPushRouteRefusal::Rejected {
                        // Not the routes' owner (or not allowed): retrying cannot succeed.
                        tracing::warn!(
                            "push route deregistration refused; dropping the pending clear"
                        );
                        self.config.push_route_clear_pending = false;
                        self.config.push_route_retry = PushRouteRetry::default();
                    } else {
                        self.config.push_route_retry.record(code, pending.sent_at);
                    }
                }
                Err(SdkError::GatewaySessionRejected(reason))
            }
            _ => Ok(None),
        }
    }

    /// Best-effort, non-blocking push route control after (re)connect, when renewal is due, or
    /// while a deregistration is unconfirmed. Only the frame is written; the answer is applied
    /// whenever it arrives. Refusals and lost answers back off (30 s doubling to 6 h, jittered;
    /// 24 h after a permanent refusal), so a misconfigured or degraded node is not flooded.
    pub(crate) async fn refresh_push_route_if_due(&mut self) {
        self.refresh_push_route_at(now_unix_timestamp().unsigned_abs()).await;
    }

    pub(crate) async fn refresh_push_route_at(&mut self, now: u64) {
        if let Some(pending) = &self.pending_push_route {
            if now.saturating_sub(pending.sent_at) < PUSH_ROUTE_RETRY_AFTER_SECONDS {
                return;
            }
            let sent_at = pending.sent_at;
            self.pending_push_route = None;
            self.config.push_route_retry.record(GatewayPushRouteRefusal::Unavailable, sent_at);
        }
        if now < self.config.push_route_retry.not_before {
            return;
        }
        let sent = if self.config.push_route.is_some() {
            if !push_route_renewal_due(self.push_route_expires_at, now) {
                return;
            }
            Box::pin(self.send_push_route_registration(now)).await
        } else if self.config.push_route_clear_pending {
            Box::pin(self.send_push_route_deregistration(now)).await
        } else {
            return;
        };
        if let Err(error) = sent {
            tracing::warn!(%error, "push route control deferred");
            self.config.push_route_retry.record(GatewayPushRouteRefusal::Unavailable, now);
        }
    }
}

/// Whether a server frame answers push route control (registration or deregistration).
#[must_use]
pub(crate) const fn is_push_route_reply(frame: &GatewayServerFrame) -> bool {
    matches!(
        frame,
        GatewayServerFrame::PushRouteRegistered { .. }
            | GatewayServerFrame::PushRouteRefused { .. }
            | GatewayServerFrame::PushRouteDeregistered { .. }
    )
}

fn push_route_reply_id(frame: &GatewayServerFrame) -> Option<&str> {
    match frame {
        GatewayServerFrame::PushRouteRegistered { request_id, .. } => request_id.as_deref(),
        GatewayServerFrame::PushRouteRefused { request_id, .. }
        | GatewayServerFrame::PushRouteDeregistered { request_id, .. } => Some(request_id),
        _ => None,
    }
}

#[cfg(test)]
#[path = "push_route_session_tests.rs"]
mod session_tests;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
    use std::sync::{Arc, Mutex};

    type FrameFuture<'a, T> =
        std::pin::Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

    /// Answers heartbeats and push registrations; records every registration frame.
    struct PushGateway {
        last: Option<GatewayClientFrame>,
        registrations: Arc<Mutex<Vec<GatewayPushRouteFrame>>>,
        expires_at: u64,
    }

    impl GatewaySessionFrameSink for PushGateway {
        fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> FrameFuture<'a, ()> {
            Box::pin(async move {
                let frame: GatewayClientFrame = serde_json::from_slice(frame)
                    .map_err(|error| TransportError::Quic(error.to_string()))?;
                if let GatewayClientFrame::PushRouteRegister { request } = &frame {
                    self.registrations.lock().expect("lock").push((**request).clone());
                }
                self.last = Some(frame);
                Ok(())
            })
        }
        fn finish(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    impl GatewaySessionFrameSource for PushGateway {
        fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
            Box::pin(async move {
                let response = match self.last.take() {
                    Some(GatewayClientFrame::Heartbeat { now }) => {
                        GatewayServerFrame::Heartbeat { now }
                    }
                    Some(GatewayClientFrame::PushRouteRegister { request }) => {
                        GatewayServerFrame::PushRouteRegistered {
                            expires_at: self.expires_at,
                            request_id: Some(request.signed_request.request_id),
                        }
                    }
                    Some(GatewayClientFrame::PushRouteDeregister { request }) => {
                        GatewayServerFrame::PushRouteDeregistered {
                            request_id: request.signed_request.request_id,
                            removed: 1,
                        }
                    }
                    _ => GatewayServerFrame::Nack { reason: "unexpected".into() },
                };
                serde_json::to_vec(&response)
                    .map_err(|error| TransportError::Quic(error.to_string()))
            })
        }
    }

    fn engine(expires_at: u64) -> (GatewaySessionEngine, Arc<Mutex<Vec<GatewayPushRouteFrame>>>) {
        let root = ramflux_crypto::create_identity_root("principal_push", [0x93; 32]);
        let branch =
            ramflux_crypto::create_device_branch("principal_push", "device_push", 1, [9_u8; 32]);
        let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse().expect("bind addr"),
            gateway_addr: "127.0.0.1:443".parse().expect("gateway addr"),
            server_name: "localhost".to_owned(),
            ca_cert: std::path::PathBuf::from("test-ca.pem"),
            principal_id: "principal_push".to_owned(),
            device_id: "device_push".to_owned(),
            target_delivery_id: "target_push".to_owned(),
            prekey_http_url: None,
        })
        .with_owned_device(&root, branch)
        .expect("owned device");
        let registrations = Arc::new(Mutex::new(Vec::new()));
        let gateway =
            PushGateway { last: None, registrations: Arc::clone(&registrations), expires_at };
        (GatewaySessionEngine::with_test_transport(config, Box::new(gateway)), registrations)
    }

    fn webpush(token: &str) -> GatewayPushRouteRegistration {
        GatewayPushRouteRegistration {
            provider: GatewayPushProvider::WebPush,
            token: token.into(),
            endpoint: Some("https://push.example/sub".into()),
            webpush_p256dh: Some("p256dh".into()),
            webpush_auth: Some("auth".into()),
        }
    }

    #[tokio::test]
    async fn push_route_registration_is_session_bound_signed_and_renewed_before_expiry() {
        let now = now_unix_timestamp().unsigned_abs();
        let (mut engine, registrations) = engine(now + 30 * 86_400);
        assert_eq!(
            engine.set_push_route(Some(webpush("first"))).await.expect("register"),
            Some(now + 30 * 86_400)
        );
        let frame = registrations.lock().expect("lock")[0].clone();
        assert_eq!(frame.signed_request.path, GATEWAY_PUSH_ROUTE_PATH);
        assert_eq!(frame.signed_request.ext.ext["session_id"], "test-session");
        let body_bytes = ramflux_protocol::canonical_json_bytes(&frame.body).expect("body");
        assert_eq!(
            frame.signed_request.body_hash,
            ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::ENVELOPE, &body_bytes)
        );
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&frame.signed_request).expect("signed bytes"),
            &frame.signed_request.signed.signature,
            &ramflux_crypto::public_key_base64url_from_seed([9_u8; 32]),
        )
        .expect("branch signature covers the session binding");
        // A fresh route is not re-sent on every liveness check.
        engine.ensure_live(0).await.expect("live");
        assert_eq!(registrations.lock().expect("lock").len(), 1);
        // Token rotation registers immediately.
        engine.set_push_route(Some(webpush("rotated"))).await.expect("rotate");
        assert_eq!(registrations.lock().expect("lock")[1].body.token, "rotated");
        // Inside the renewal window the next liveness check renews the route.
        engine.push_route_expires_at = Some(now + 86_400);
        engine.ensure_live(0).await.expect("live");
        assert_eq!(registrations.lock().expect("lock").len(), 3);
    }

    #[tokio::test]
    async fn transient_refusals_back_off_and_permanent_ones_wait_a_day() {
        for (code, bound) in [("unavailable", 8), ("provider_unavailable", 1), ("rejected", 1)] {
            let (mut engine, registrations) =
                super::session_tests::engine_with(false, Some(code), false);
            let start = 2_000_000_000;
            // One simulated hour of 5-second sync ticks.
            for tick in 0..720 {
                engine.refresh_push_route_at(start + tick * 5).await;
                let _ = engine.heartbeat().await;
            }
            let attempts = *registrations.lock().expect("lock");
            assert!(attempts <= bound, "{code}: {attempts} registrations in an hour");
            assert!(attempts >= 1);
        }
        assert_eq!(PushRouteRetry::transient_delay(1, 0), 30);
        assert_eq!(PushRouteRetry::transient_delay(2, 0), 60);
        assert_eq!(PushRouteRetry::transient_delay(30, 0), 6 * 3_600);
        assert_eq!(PushRouteRetry::transient_delay(1, 20), 36);
    }

    #[tokio::test]
    async fn an_unconfirmed_deregistration_is_retried_with_backoff() {
        let (mut engine, attempts) =
            super::session_tests::engine_with(false, Some("unavailable"), false);
        assert!(engine.set_push_route(None).await.is_err());
        assert!(engine.config.push_route_clear_pending, "the clear stays pending until confirmed");
        let start = now_unix_timestamp().unsigned_abs();
        for tick in 0..720 {
            engine.refresh_push_route_at(start + tick * 5).await;
            let _ = engine.heartbeat().await;
        }
        let attempts = *attempts.lock().expect("lock");
        assert!((2..=9).contains(&attempts), "{attempts} deregistrations in an hour");
        assert!(engine.config.push_route_clear_pending);
    }

    #[tokio::test]
    async fn a_deregistration_refused_as_not_the_owner_is_not_retried() {
        let (mut engine, attempts) =
            super::session_tests::engine_with(false, Some("rejected"), false);
        assert!(engine.set_push_route(None).await.is_err());
        assert!(!engine.config.push_route_clear_pending, "the pending clear is dropped");
        let start = now_unix_timestamp().unsigned_abs();
        for tick in 0..720 {
            engine.refresh_push_route_at(start + tick * 5).await;
            let _ = engine.heartbeat().await;
        }
        assert_eq!(*attempts.lock().expect("lock"), 1);
    }

    #[tokio::test]
    async fn unknown_refusal_codes_back_off_like_transient_failures() {
        let (mut engine, attempts) =
            super::session_tests::engine_with(false, Some("a_code_from_a_newer_node"), false);
        let start = 2_000_000_000;
        for tick in 0..720 {
            engine.refresh_push_route_at(start + tick * 5).await;
            let _ = engine.heartbeat().await;
        }
        let attempts = *attempts.lock().expect("lock");
        assert!((2..=8).contains(&attempts), "{attempts} registrations in an hour");
    }

    #[tokio::test]
    async fn clearing_the_push_route_sends_an_explicit_deregistration() {
        let now = now_unix_timestamp().unsigned_abs();
        let (mut engine, _registrations) = engine(now + 30 * 86_400);
        engine.set_push_route(Some(webpush("first"))).await.expect("register");
        assert_eq!(engine.set_push_route(None).await.expect("deregister"), None);
        assert_eq!(engine.push_route_expires_at(), None);
        assert!(engine.config.push_route.is_none());
    }

    #[test]
    fn push_route_renews_before_the_node_assigned_expiry() {
        let day = 86_400;
        assert!(push_route_renewal_due(None, 1_000));
        assert!(!push_route_renewal_due(Some(1_000 + 30 * day), 1_000));
        assert!(!push_route_renewal_due(Some(1_000 + 16 * day), 1_000));
        assert!(push_route_renewal_due(Some(1_000 + 14 * day), 1_000));
        assert!(push_route_renewal_due(Some(500), 1_000));
    }

    #[test]
    fn push_route_body_serializes_absent_fields_as_null_for_the_signed_hash() {
        let body = GatewayPushRouteRegistration {
            provider: GatewayPushProvider::WebPush,
            token: "t".into(),
            endpoint: None,
            webpush_p256dh: None,
            webpush_auth: None,
        };
        let value = serde_json::to_value(&body).expect("json");
        assert_eq!(value["provider"], "webpush");
        assert!(value["endpoint"].is_null());
        assert!(!format!("{body:?}").contains("\"t\""));
    }
}
