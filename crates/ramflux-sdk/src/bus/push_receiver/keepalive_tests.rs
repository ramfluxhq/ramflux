// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named P24a cell: activity on every complete frame, 25 s/10 s heartbeat, 35 s retire.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use crate::bus::connection_manager::tests::{entry, reconnecting_fixture, send, watchdog};
use crate::bus::connection_manager::{ConnectionEvent, DisconnectReason};
use crate::bus::runtime_limits::{KEEPALIVE_CALL, KEEPALIVE_IDLE, RuntimeTimeouts};
use crate::{GatewayClientFrame, GatewayServerFrame};
use std::time::Duration;
use tokio::time::Instant;

type Case = Result<(), Box<dyn std::error::Error>>;

async fn wait_read_after(
    handle: &crate::bus::connection_manager::ConnectionHandle,
    before: u64,
) -> Instant {
    for _ in 0..10_000 {
        if handle.test_read_count() > before {
            return handle.test_context().last_read_at();
        }
        tokio::task::yield_now().await;
    }
    panic!("complete frame was not noted");
}

async fn wait_client_frame(
    output: &mut tokio::sync::mpsc::UnboundedReceiver<GatewayClientFrame>,
) -> GatewayClientFrame {
    for _ in 0..10_000 {
        if let Ok(frame) = output.try_recv() {
            return frame;
        }
        tokio::task::yield_now().await;
    }
    panic!("client frame was not written");
}

/// Reply/push/heartbeat update activity with no subscribers; missing reply retires at 35 s.
/// Negative: activity from the push subscription would ping after a recent reply.
#[tokio::test(start_paused = true)]
async fn keepalive_all_reads() -> Case {
    watchdog(async {
        let mut limits = RuntimeTimeouts::held_for_test();
        limits.keepalive_idle = KEEPALIVE_IDLE;
        limits.keepalive_call = KEEPALIVE_CALL;
        let (handle, mut sessions) = reconnecting_fixture(limits)?;
        let mut io = sessions.recv().await.ok_or("connector did not enter")?;
        handle.require_live(Duration::from_secs(600)).await?;
        let mut events = handle.events();
        while let Ok(event) = events.try_recv() {
            let _ = event;
        }

        let t0 = handle.test_read_count();
        send(&io, &GatewayServerFrame::Deliver { entry: entry("push", 1)? })?;
        let after_push = wait_read_after(&handle, t0).await;

        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(io.output.try_recv().is_err(), "idle 20 s after a push must not ping yet");

        let caller = handle.clone();
        let heartbeat = tokio::spawn(async move {
            caller
                .call(
                    |engine| Box::pin(engine.heartbeat()),
                    Instant::now() + Duration::from_secs(600),
                )
                .await
        });
        assert!(matches!(
            wait_client_frame(&mut io.output).await,
            GatewayClientFrame::Heartbeat { .. }
        ));
        send(&io, &GatewayServerFrame::Heartbeat { now: 7 })?;
        heartbeat.await??;
        let after_heartbeat_count = handle.test_read_count();
        assert!(after_heartbeat_count > t0, "heartbeat reply must note a complete frame");

        let caller = handle.clone();
        let cursor = tokio::spawn(async move {
            caller
                .call(|engine| Box::pin(engine.cursor()), Instant::now() + Duration::from_secs(600))
                .await
        });
        assert!(matches!(
            wait_client_frame(&mut io.output).await,
            GatewayClientFrame::Cursor { .. }
        ));
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        cursor.await??;
        let after_reply = wait_read_after(&handle, after_heartbeat_count).await;
        assert!(after_reply > after_push, "reply must update activity without subscribers");

        tokio::time::advance(Duration::from_secs(24)).await;
        tokio::task::yield_now().await;
        assert!(
            io.output.try_recv().is_err(),
            "a ping sent after a recent reply means activity came from the push subscription"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            wait_client_frame(&mut io.output).await,
            GatewayClientFrame::Heartbeat { .. }
        ));
        assert!(io.output.try_recv().is_err(), "exactly one keepalive ping");

        let generation = handle.generation();
        tokio::time::advance(KEEPALIVE_CALL).await;
        let mut retired = false;
        for _ in 0..10_000 {
            match events.try_recv() {
                Ok(ConnectionEvent::Disconnected {
                    reason: DisconnectReason::CallTimeout,
                    generation: g,
                }) if g == generation => {
                    retired = true;
                    break;
                }
                Ok(_) => {}
                Err(_) => tokio::task::yield_now().await,
            }
        }
        assert!(retired, "missing heartbeat reply must retire at 35 s idle");
        handle.stop().await;
        Ok(())
    })
    .await
}
