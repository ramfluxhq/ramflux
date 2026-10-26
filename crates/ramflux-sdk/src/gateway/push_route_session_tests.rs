// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A slow or unreachable push backend must never delay or desynchronise the session.
#![allow(clippy::expect_used)]
use crate::gateway::{
    GatewayPushProvider, GatewayPushRouteRegistration, GatewayQuicEndpointConfig,
    GatewaySessionConfig, GatewaySessionEngine,
};
use crate::prelude::*;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

/// Answers heartbeats; registration replies are either dropped or delayed until the next
/// client frame, as a slow notify would produce them.
struct SlowPushGateway {
    outbox: VecDeque<serde_json::Value>,
    held_reply: Option<serde_json::Value>,
    blackhole: bool,
    /// Answer every registration at once with this refusal code.
    refuse: Option<&'static str>,
    /// Send a drain frame before answering a registration.
    drain_first: bool,
    registrations: Arc<Mutex<usize>>,
    waker: Option<std::task::Waker>,
}

impl GatewaySessionFrameSink for SlowPushGateway {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            let frame: serde_json::Value = serde_json::from_slice(frame)
                .map_err(|error| TransportError::Quic(error.to_string()))?;
            match frame["frame_type"].as_str() {
                Some("push_route_register" | "push_route_deregister") => {
                    *self.registrations.lock().expect("lock") += 1;
                    let id = frame["request"]["signed_request"]["request_id"].clone();
                    if let Some(code) = self.refuse {
                        self.outbox.push_back(serde_json::json!({
                            "frame_type": "push_route_refused", "request_id": id,
                            "reason": "refused", "code": code,
                        }));
                    } else if self.drain_first {
                        self.outbox.push_back(serde_json::json!({
                            "frame_type": "drain", "session_id": "test-session", "reason": "restart",
                        }));
                        self.outbox.push_back(serde_json::json!({
                            "frame_type": "push_route_registered", "expires_at": 4_000_000_000_u64,
                            "request_id": id,
                        }));
                    } else if !self.blackhole {
                        self.held_reply = Some(serde_json::json!({
                            "frame_type": "push_route_registered",
                            "expires_at": 4_000_000_000_u64,
                            "request_id": frame["request"]["signed_request"]["request_id"],
                        }));
                    }
                }
                Some("heartbeat") => {
                    if let Some(late) = self.held_reply.take() {
                        self.outbox.push_back(late);
                    }
                    self.outbox.push_back(
                        serde_json::json!({ "frame_type": "heartbeat", "now": frame["now"] }),
                    );
                }
                _ => {}
            }
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
            Ok(())
        })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for SlowPushGateway {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        Box::pin(std::future::poll_fn(move |context| {
            if let Some(frame) = self.outbox.pop_front() {
                return std::task::Poll::Ready(
                    serde_json::to_vec(&frame)
                        .map_err(|error| TransportError::Quic(error.to_string())),
                );
            }
            self.waker = Some(context.waker().clone());
            std::task::Poll::Pending
        }))
    }
}

fn engine(blackhole: bool) -> (GatewaySessionEngine, Arc<Mutex<usize>>) {
    engine_with(blackhole, None, false)
}

pub(super) fn engine_with(
    blackhole: bool,
    refuse: Option<&'static str>,
    drain_first: bool,
) -> (GatewaySessionEngine, Arc<Mutex<usize>>) {
    let root = ramflux_crypto::create_identity_root("principal_slow_push", [0x95; 32]);
    let branch =
        ramflux_crypto::create_device_branch("principal_slow_push", "device_slow", 1, [11_u8; 32]);
    let mut config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse().expect("bind addr"),
        gateway_addr: "127.0.0.1:443".parse().expect("gateway addr"),
        server_name: "localhost".to_owned(),
        ca_cert: std::path::PathBuf::from("test-ca.pem"),
        principal_id: "principal_slow_push".to_owned(),
        device_id: "device_slow".to_owned(),
        target_delivery_id: "target_slow".to_owned(),
        prekey_http_url: None,
    })
    .with_owned_device(&root, branch)
    .expect("owned device");
    config.push_route = Some(GatewayPushRouteRegistration {
        provider: GatewayPushProvider::WebPush,
        token: "slow-token".into(),
        endpoint: Some("https://push.example/sub".into()),
        webpush_p256dh: Some("p256dh".into()),
        webpush_auth: Some("auth".into()),
    });
    let registrations = Arc::new(Mutex::new(0));
    let gateway = SlowPushGateway {
        outbox: VecDeque::new(),
        held_reply: None,
        blackhole,
        refuse,
        drain_first,
        registrations: Arc::clone(&registrations),
        waker: None,
    };
    (GatewaySessionEngine::with_test_transport(config, Box::new(gateway)), registrations)
}

#[tokio::test]
async fn blackholed_push_backend_does_not_delay_the_liveness_check() {
    let (mut engine, registrations) = engine(true);
    let started = std::time::Instant::now();
    engine.ensure_live(0).await.expect("liveness check succeeds");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "registration held the session for {:?}",
        started.elapsed()
    );
    assert_eq!(*registrations.lock().expect("lock"), 1);
    engine.heartbeat().await.expect("session stays usable");
}

#[tokio::test]
async fn late_registration_reply_is_matched_and_never_read_as_a_heartbeat() {
    let (mut engine, registrations) = engine(false);
    tokio::time::timeout(Duration::from_secs(30), engine.ensure_live(0))
        .await
        .expect("bounded")
        .expect("liveness check succeeds");
    assert_eq!(*registrations.lock().expect("lock"), 1);
    // The gateway answers the registration only now, just before the heartbeat reply.
    engine.heartbeat().await.expect("a late registration reply must not fail the heartbeat");
    assert_eq!(engine.push_route_expires_at, Some(4_000_000_000));
}

#[tokio::test]
async fn refused_registration_is_not_resent_on_every_liveness_check() {
    let (mut engine, registrations) = engine_with(false, Some("unavailable"), false);
    for _ in 0..20 {
        engine.ensure_live(0).await.expect("liveness check succeeds");
    }
    assert_eq!(
        *registrations.lock().expect("lock"),
        1,
        "a refused registration must back off instead of retrying on every sync tick"
    );
}

#[tokio::test]
async fn a_drain_during_push_route_set_is_kept_for_the_next_reader() {
    let (mut engine, _registrations) = engine_with(false, None, true);
    let registration = engine.config.push_route.clone();
    assert!(engine.set_push_route(registration).await.is_err(), "the drain must end the wait");
    let error = engine.heartbeat().await.expect_err("the drain is delivered, not dropped");
    assert!(format!("{error:?}").contains("Drain"), "{error:?}");
}
