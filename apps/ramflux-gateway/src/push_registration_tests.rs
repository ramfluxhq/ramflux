// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Route control is serial per session and the latest intent wins.
use super::{Execute, Reply, RouteControlQueue, RouteIntent};
use ramflux_node_core::{GatewayServerFrame, PushRouteRefusal};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn signed(id: &str) -> ramflux_protocol::SignedRequest {
    serde_json::from_value(serde_json::json!({
        "schema": "ramflux.signed_request.v1", "version": 1, "domain": "ramflux.signed_request.v1",
        "signing_key_id": "device:phone", "signature_alg": "ed25519", "signature": "fixture",
        "source_device_id": "phone", "request_id": id, "method": "POST", "path": "/p",
        "device_proof_hash": "already_authed", "body_hash": "h", "nonce": id,
        "created_at": 1, "expires_at": 2
    }))
    .unwrap_or_else(|_| unreachable!("fixture signed request"))
}

fn register(id: &str) -> RouteIntent {
    RouteIntent::Register(ramflux_node_core::PushRouteRegistrationFrame {
        signed_request: signed(id),
        body: ramflux_node_core::PushRouteRegistration {
            provider: ramflux_node_core::PushProviderKind::WebPush,
            token: "t".into(),
            endpoint: None,
            webpush_p256dh: None,
            webpush_auth: None,
        },
    })
}

fn deregister(id: &str) -> RouteIntent {
    RouteIntent::Deregister(ramflux_node_core::PushRouteDeregistrationFrame {
        signed_request: signed(id),
        body: ramflux_node_core::PushRouteDeregistration::default(),
    })
}

struct Harness {
    queue: RouteControlQueue,
    executed: Arc<Mutex<Vec<String>>>,
    replies: Arc<Mutex<Vec<GatewayServerFrame>>>,
    max_in_flight: Arc<AtomicUsize>,
}

/// A notify that takes `delay` per control, like a slow backend.
fn harness(delay: std::time::Duration) -> Harness {
    let executed = Arc::new(Mutex::new(Vec::new()));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let execute: Execute = {
        let (executed, in_flight, max) =
            (Arc::clone(&executed), Arc::clone(&in_flight), Arc::clone(&max_in_flight));
        Arc::new(move |intent| {
            let (executed, in_flight, max) =
                (Arc::clone(&executed), Arc::clone(&in_flight), Arc::clone(&max));
            Box::pin(async move {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                let id = intent.request_id().to_owned();
                let frame = match intent {
                    RouteIntent::Register(_) => GatewayServerFrame::PushRouteRegistered {
                        expires_at: 9,
                        request_id: Some(id.clone()),
                    },
                    RouteIntent::Deregister(_) => GatewayServerFrame::PushRouteDeregistered {
                        request_id: id.clone(),
                        removed: 1,
                    },
                };
                executed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(id);
                frame
            })
        })
    };
    let reply: Reply = {
        let replies = Arc::clone(&replies);
        Arc::new(move |frame| {
            let replies = Arc::clone(&replies);
            Box::pin(async move {
                replies.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(frame);
            })
        })
    };
    Harness { queue: RouteControlQueue::start(execute, reply), executed, replies, max_in_flight }
}

async fn settle(harness: &Harness, replies: usize) {
    for _ in 0..200 {
        if harness.replies.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
            >= replies
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn slow_notify_register_then_deregister_ends_deregistered() {
    let harness = harness(std::time::Duration::from_millis(200));
    harness.queue.submit(register("register-1")).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    harness.queue.submit(deregister("deregister-2")).await;
    settle(&harness, 2).await;
    let executed =
        harness.executed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(executed, ["register-1", "deregister-2"], "the clear must take effect last");
    assert_eq!(harness.max_in_flight.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn queued_control_is_superseded_by_the_latest_intent() {
    let harness = harness(std::time::Duration::from_millis(200));
    harness.queue.submit(register("first")).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    harness.queue.submit(register("queued")).await;
    harness.queue.submit(deregister("latest")).await;
    settle(&harness, 3).await;
    let executed =
        harness.executed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(executed, ["first", "latest"]);
    let replies = harness.replies.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert!(replies.iter().any(|frame| matches!(
        frame,
        GatewayServerFrame::PushRouteRefused { request_id, code: PushRouteRefusal::Superseded, .. }
            if request_id == "queued"
    )));
    assert_eq!(harness.max_in_flight.load(Ordering::SeqCst), 1);
}
