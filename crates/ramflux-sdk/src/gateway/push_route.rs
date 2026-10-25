// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keeps this device's push route registered with its home node.
//!
//! The node assigns a sliding 30-day route lifetime. The engine registers the configured route
//! on every authenticated session (re)connect, again whenever the token changes, and renews it
//! from [`GatewaySessionEngine::ensure_live`] once less than 15 days remain, so a device left in
//! the background keeps receiving wakes. Revoking the device deletes the route on the node.
#![allow(clippy::wildcard_imports)]
use super::{GatewaySessionEngine, write_gateway_client_frame};
use crate::prelude::*;

/// Gateway path the registration request is signed for.
pub const GATEWAY_PUSH_ROUTE_PATH: &str = "/notify/v1/push-route";
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

/// Whether a route that expires at `expires_at` must be registered again at `now`.
#[must_use]
pub fn push_route_renewal_due(expires_at: Option<u64>, now: u64) -> bool {
    expires_at.is_none_or(|expires_at| {
        expires_at.saturating_sub(now) < GATEWAY_PUSH_ROUTE_RENEW_BEFORE_SECONDS
    })
}

impl GatewaySessionEngine {
    /// Node-assigned expiry of the last successful registration in this session.
    #[must_use]
    pub const fn push_route_expires_at(&self) -> Option<u64> {
        self.push_route_expires_at
    }

    /// Replaces the device's push route (for example after a token rotation) and registers it
    /// immediately; `None` stops future re-registration. Reconnects re-register automatically.
    /// # Errors
    /// Returns transport, signing or gateway rejection errors.
    pub async fn set_push_route(
        &mut self,
        registration: Option<GatewayPushRouteRegistration>,
    ) -> Result<Option<u64>, SdkError> {
        let changed = self.config.push_route != registration;
        self.config.push_route = registration;
        if changed {
            self.push_route_expires_at = None;
        }
        self.register_push_route().await
    }

    /// Registers the configured route over the authenticated session.
    /// # Errors
    /// Returns transport, signing or gateway rejection errors.
    pub async fn register_push_route(&mut self) -> Result<Option<u64>, SdkError> {
        let Some(body) = self.config.push_route.clone() else {
            return Ok(None);
        };
        let mut signed_request =
            self.signed_request("POST", GATEWAY_PUSH_ROUTE_PATH, "already_authed", &body)?;
        signed_request
            .ext
            .ext
            .insert("session_id".to_owned(), serde_json::json!(self.session.session_id));
        let branch = self.config.device_branch.as_ref().ok_or_else(|| {
            SdkError::GatewaySessionRejected("missing registered device branch".to_owned())
        })?;
        signed_request.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(branch, &signed_request)?;
        write_gateway_client_frame(
            &mut *self.stream,
            &GatewayClientFrame::PushRouteRegister {
                request: Box::new(GatewayPushRouteFrame { signed_request, body }),
            },
        )
        .await?;
        match self.read_non_deliver_frame().await? {
            GatewayServerFrame::PushRouteRegistered { expires_at } => {
                self.push_route_expires_at = Some(expires_at);
                Ok(Some(expires_at))
            }
            GatewayServerFrame::Nack { reason } => Err(SdkError::GatewaySessionRejected(reason)),
            other => Err(SdkError::GatewaySessionRejected(format!(
                "expected push route registration, got {other:?}"
            ))),
        }
    }

    /// Best-effort registration after (re)connect or when renewal is due. A failure is
    /// retried on the next liveness check and never fails the session itself.
    pub(crate) async fn refresh_push_route_if_due(&mut self) {
        if self.config.push_route.is_none()
            || !push_route_renewal_due(
                self.push_route_expires_at,
                now_unix_timestamp().unsigned_abs(),
            )
        {
            return;
        }
        if let Err(error) = Box::pin(self.register_push_route()).await {
            tracing::warn!(%error, "push route registration deferred");
        }
    }
}

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
                    Some(GatewayClientFrame::PushRouteRegister { .. }) => {
                        GatewayServerFrame::PushRouteRegistered { expires_at: self.expires_at }
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
