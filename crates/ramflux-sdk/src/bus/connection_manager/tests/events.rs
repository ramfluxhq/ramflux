// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unsolicited push application and slow subscribers never borrow the active exchange.

use super::{entry, fixture, send, watchdog};
use crate::bus::connection_manager::subscriptions::SessionEvent;
use crate::gateway::frame_dispatch::FrameKind;
use crate::{
    GatewayClientFrame, GatewayPushProvider, GatewayPushRouteRegistration, GatewayServerFrame,
};
use std::time::{Duration, Instant as WallClock};
use tokio::time::Instant;

type Case = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn session_host_applies_interleaved_push_routes_before_notifying_the_subscriber() -> Case {
    watchdog(async {
        let (handle, mut io) = fixture().await?;
        handle
            .call(
                |engine| {
                    Box::pin(async move {
                        engine.config.push_routes.insert(
                            GatewayPushProvider::Apns,
                            GatewayPushRouteRegistration {
                                provider: GatewayPushProvider::Apns,
                                token: "fixture".into(),
                                endpoint: None,
                                webpush_p256dh: None,
                                webpush_auth: None,
                            },
                        );
                        Ok(())
                    })
                },
                Instant::now() + Duration::from_secs(600),
            )
            .await?;
        let mut subscriber = handle.subscribe([
            FrameKind::InBandWake,
            FrameKind::PushRouteRegistered,
            FrameKind::Deliver,
        ]);
        let caller = handle.clone();
        let started = WallClock::now();
        let call = tokio::spawn(async move {
            caller
                .call(|engine| Box::pin(engine.cursor()), Instant::now() + Duration::from_secs(600))
                .await
        });
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        send(
            &io,
            &GatewayServerFrame::InBandWake {
                target_delivery_id: "host-target".into(),
                delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
            },
        )?;
        send(
            &io,
            &GatewayServerFrame::PushRouteRegistered {
                expires_at: 4242,
                request_id: Some("earlier-registration".into()),
            },
        )?;
        send(&io, &GatewayServerFrame::Deliver { entry: entry("unsolicited", 42)? })?;
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        call.await??;
        let mut kinds = Vec::new();
        for _ in 0..3 {
            let SessionEvent::Frame { frame, .. } =
                subscriber.recv().await.ok_or("push missing")?
            else {
                return Err("unexpected lag during interleaving".into());
            };
            kinds.push(FrameKind::of(&frame));
            if matches!(&*frame, GatewayServerFrame::PushRouteRegistered { .. }) {
                let expiry = handle
                    .call(
                        |engine| Box::pin(async move { Ok(engine.push_route_expires_at) }),
                        Instant::now() + Duration::from_secs(600),
                    )
                    .await?;
                assert_eq!(expiry, Some(4242), "the notification must follow application");
            }
        }
        assert_eq!(
            kinds,
            [FrameKind::InBandWake, FrameKind::PushRouteRegistered, FrameKind::Deliver]
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_host_slow_subscriber_lags_without_blocking_calls_or_another_subscriber() -> Case {
    watchdog(async {
        let (handle, mut io) = fixture().await?;
        let mut slow = handle.subscribe([FrameKind::InBandWake]);
        let mut fast = handle.subscribe([FrameKind::InBandWake]);
        let caller = handle.clone();
        let started = WallClock::now();
        let call = tokio::spawn(async move {
            caller
                .call(
                    |engine| Box::pin(engine.heartbeat()),
                    Instant::now() + Duration::from_secs(600),
                )
                .await
        });
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Heartbeat { .. })));
        for _ in 0..=crate::bus::runtime_limits::SUBSCRIBER_QUEUE {
            send(
                &io,
                &GatewayServerFrame::InBandWake {
                    target_delivery_id: "host-target".into(),
                    delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
                },
            )?;
            assert!(matches!(fast.recv().await, Some(SessionEvent::Frame { .. })));
        }
        assert!(matches!(slow.recv().await, Some(SessionEvent::Lagged { dropped: 1, .. })));
        send(&io, &GatewayServerFrame::Heartbeat { now: 42 })?;
        call.await??;
        assert!(started.elapsed() < Duration::from_secs(1));
        for _ in 0..crate::bus::runtime_limits::SUBSCRIBER_QUEUE {
            assert!(
                matches!(slow.recv().await, Some(SessionEvent::Frame { .. })),
                "one overflow episode has one Lagged event"
            );
        }
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn late_call_result_is_fenced_when_its_sender_survives_a_generation_change() -> Case {
    watchdog(async {
        let (mut handle, mut io) = fixture().await?;
        // Retain the real call's result sender outside host cancellation so only the result fence can reject it.
        let (calls, mut queued) = tokio::sync::mpsc::channel(1);
        handle.calls = calls;
        let generation = handle.generation();
        let owner = handle.clone();
        let answer = tokio::spawn(async move {
            owner
                .call(
                    |_| Box::pin(async { Ok::<_, crate::SdkError>(42_u64) }),
                    Instant::now() + Duration::from_secs(600),
                )
                .await
        });
        let call = queued.recv().await.ok_or("call was not admitted")?;
        handle
            .shared
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation = super::super::new_generation();
        call.reply
            .send(Ok((Box::new(42_u64), generation)))
            .map_err(|_| "call receiver was dropped before the result fence")?;
        assert!(
            matches!(answer.await?, Err(crate::SdkError::NetworkingPendingContext { .. })),
            "an old-generation success must not reach the caller"
        );
        assert!(
            io.output.try_recv().is_err(),
            "the retained result is independent of wire cancellation"
        );
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_resident_session_child_does_not_monopolize_a_concurrent_host_call() -> Case {
    watchdog(async {
        let (handle, mut io) = fixture().await?;
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let started = std::sync::Arc::clone(&entered);
        let released = std::sync::Arc::clone(&release);
        handle.spawn_session_child("long-child-without-engine-borrow", move |_| {
            let entered = std::sync::Arc::clone(&started);
            let release = std::sync::Arc::clone(&released);
            Box::pin(async move {
                entered.notify_one();
                release.notified().await;
            })
        })?;
        entered.notified().await;
        let owner = handle.clone();
        let call = tokio::spawn(async move {
            owner
                .call(
                    |engine| Box::pin(engine.heartbeat()),
                    Instant::now() + Duration::from_secs(600),
                )
                .await
        });
        let wall = WallClock::now();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), io.output.recv()).await?,
            Some(GatewayClientFrame::Heartbeat { .. })
        ));
        send(&io, &GatewayServerFrame::Heartbeat { now: 42 })?;
        tokio::time::timeout(Duration::from_secs(1), call).await???;
        assert!(wall.elapsed() < Duration::from_secs(1));
        // The child remains held throughout the exchange; only this test releases it.
        release.notify_one();
        handle.stop().await;
        Ok(())
    })
    .await
}
