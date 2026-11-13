// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named P24a cell: activity on every complete frame, 25 s/10 s heartbeat, 35 s retire.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use crate::bus::connection_manager::tests::{
    SessionIo, entry, reconnecting_fixture, send, wait_bulk_held, watchdog,
};
use crate::bus::connection_manager::{
    ConnectionEvent, ConnectionHandle, ConnectionPhase, DisconnectReason,
};
use crate::bus::runtime_limits::{CALL_QUEUE, KEEPALIVE_CALL, KEEPALIVE_IDLE, RuntimeTimeouts};
use crate::{GatewayClientFrame, GatewayServerFrame};
use std::time::Duration;
use tokio::sync::mpsc;
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
        let (handle, mut sessions) = reconnecting_fixture(limits.clone())?;
        let _io = sessions.recv().await.ok_or("connector did not enter")?;
        handle.require_live(Duration::from_secs(600)).await?;
        wait_keepalive_running(&handle, true).await;
        handle.request_stop(DisconnectReason::Lock);
        wait_keepalive_running(&handle, false).await;
        assert!(
            !handle.test_keepalive_running(),
            "lock must abort the keepalive task, not only the output stream"
        );
        handle.stop().await;

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

async fn wait_keepalive_running(handle: &ConnectionHandle, running: bool) {
    for _ in 0..10_000 {
        if handle.test_keepalive_running() == running {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("keepalive running={running} was not observed");
}

fn keepalive_limits() -> RuntimeTimeouts {
    let mut limits = RuntimeTimeouts::held_for_test();
    limits.keepalive_idle = KEEPALIVE_IDLE;
    limits.keepalive_call = KEEPALIVE_CALL;
    limits
}

fn spawn_cursor(
    handle: &ConnectionHandle,
) -> tokio::task::JoinHandle<Result<Option<crate::GatewayCursor>, crate::SdkError>> {
    let handle = handle.clone();
    tokio::spawn(async move {
        handle
            .call(|engine| Box::pin(engine.cursor()), Instant::now() + Duration::from_secs(600))
            .await
    })
}

async fn wait_disconnected(
    events: &mut tokio::sync::broadcast::Receiver<ConnectionEvent>,
    generation: u64,
    reason: DisconnectReason,
) {
    for _ in 0..10_000 {
        match events.try_recv() {
            Ok(ConnectionEvent::Disconnected { reason: r, generation: g })
                if r == reason && g == generation =>
            {
                return;
            }
            Ok(_) => {}
            Err(_) => tokio::task::yield_now().await,
        }
    }
    panic!("session was not retired with {reason:?}");
}

async fn next_session(
    handle: &ConnectionHandle,
    sessions: &mut mpsc::Receiver<SessionIo>,
    generation: u64,
) -> Result<SessionIo, Box<dyn std::error::Error>> {
    for _ in 0..10_000 {
        if handle.snapshot().phase == ConnectionPhase::Backoff {
            break;
        }
        tokio::task::yield_now().await;
    }
    let delay = handle.snapshot().retry_after_ms.ok_or("retry not recorded")?;
    tokio::time::advance(Duration::from_millis(delay)).await;
    let io = sessions.recv().await.ok_or("session was not opened")?;
    handle.require_live(Duration::from_secs(600)).await?;
    assert_ne!(handle.generation(), generation);
    Ok(io)
}

/// Queue-full must not kill keepalive; the next idle window still pings and a dead path retires.
#[tokio::test(start_paused = true)]
async fn keepalive_survives_queue_full() -> Case {
    watchdog(async {
        let (handle, mut sessions) = reconnecting_fixture(keepalive_limits())?;
        let mut io = sessions.recv().await.ok_or("connector did not enter")?;
        handle.require_live(Duration::from_secs(600)).await?;
        let mut events = handle.events();
        while let Ok(event) = events.try_recv() {
            let _ = event;
        }

        let first = spawn_cursor(&handle);
        assert!(matches!(
            wait_client_frame(&mut io.output).await,
            GatewayClientFrame::Cursor { .. }
        ));
        // Exchange drops the in-flight bulk place at dequeue, so CALL_QUEUE extras fill it.
        let mut extra = Vec::new();
        for _ in 0..CALL_QUEUE {
            extra.push(spawn_cursor(&handle));
            tokio::task::yield_now().await;
        }
        wait_bulk_held(&handle, CALL_QUEUE).await;
        let probe = spawn_cursor(&handle);
        assert!(probe.await?.is_err(), "bulk places must be exhausted");

        tokio::time::advance(KEEPALIVE_IDLE).await;
        for _ in 0..10_000 {
            tokio::task::yield_now().await;
        }
        assert!(io.output.try_recv().is_err(), "a full bulk queue must not emit a keepalive ping");

        for call in extra {
            call.abort();
            let _ = call.await;
        }
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        first.await??;
        wait_bulk_held(&handle, 0).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::advance(KEEPALIVE_IDLE).await;
        assert!(matches!(
            wait_client_frame(&mut io.output).await,
            GatewayClientFrame::Heartbeat { .. }
        ));

        let generation = handle.generation();
        tokio::time::advance(KEEPALIVE_CALL).await;
        wait_disconnected(&mut events, generation, DisconnectReason::CallTimeout).await;
        handle.stop().await;
        Ok(())
    })
    .await
}

/// Gateway rejection must not kill keepalive; a later unanswered ping still retires at 35 s.
#[tokio::test(start_paused = true)]
async fn keepalive_survives_gateway_rejection() -> Case {
    watchdog(async {
        let (handle, mut sessions) = reconnecting_fixture(keepalive_limits())?;
        let mut io = sessions.recv().await.ok_or("connector did not enter")?;
        handle.require_live(Duration::from_secs(600)).await?;
        let mut events = handle.events();
        while let Ok(event) = events.try_recv() {
            let _ = event;
        }

        tokio::time::advance(KEEPALIVE_IDLE).await;
        assert!(matches!(
            wait_client_frame(&mut io.output).await,
            GatewayClientFrame::Heartbeat { .. }
        ));
        send(&io, &GatewayServerFrame::Nack { reason: "native-authority".into() })?;
        tokio::task::yield_now().await;
        assert!(events.try_recv().is_err(), "a heartbeat nack must leave the session live");

        tokio::time::advance(Duration::from_secs(24)).await;
        tokio::task::yield_now().await;
        assert!(io.output.try_recv().is_err(), "nack is activity; no ping for 24 s");

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            wait_client_frame(&mut io.output).await,
            GatewayClientFrame::Heartbeat { .. }
        ));

        let generation = handle.generation();
        tokio::time::advance(KEEPALIVE_CALL).await;
        wait_disconnected(&mut events, generation, DisconnectReason::CallTimeout).await;
        handle.stop().await;
        Ok(())
    })
    .await
}

/// A heartbeat queued behind an in-flight reply must not write after that reply (L1).
#[tokio::test(start_paused = true)]
async fn keepalive_skips_ping_queued_behind_a_reply() -> Case {
    watchdog(async {
        let (handle, mut sessions) = reconnecting_fixture(keepalive_limits())?;
        let mut io = sessions.recv().await.ok_or("connector did not enter")?;
        handle.require_live(Duration::from_secs(600)).await?;

        let cursor = spawn_cursor(&handle);
        assert!(matches!(
            wait_client_frame(&mut io.output).await,
            GatewayClientFrame::Cursor { .. }
        ));
        // In-flight exchange already dropped its place; held=1 means keepalive is queued behind it.
        tokio::time::advance(KEEPALIVE_IDLE).await;
        wait_bulk_held(&handle, 1).await;

        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        cursor.await??;
        tokio::task::yield_now().await;
        assert!(
            io.output.try_recv().is_err(),
            "a ping sent after a recent reply means the send-time re-check is missing"
        );

        tokio::time::advance(Duration::from_secs(24)).await;
        tokio::task::yield_now().await;
        assert!(io.output.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            wait_client_frame(&mut io.output).await,
            GatewayClientFrame::Heartbeat { .. }
        ));
        handle.stop().await;
        Ok(())
    })
    .await
}

/// Keepalive stops on lock and disconnect, restarts next generation, one Connected per live (L3).
#[tokio::test(start_paused = true)]
async fn keepalive_stops_on_lock_and_restarts_without_duplicate_connected() -> Case {
    watchdog(async {
        let (handle, mut sessions) = reconnecting_fixture(keepalive_limits())?;
        let mut events = handle.events();
        let mut io = sessions.recv().await.ok_or("connector did not enter")?;
        handle.require_live(Duration::from_secs(600)).await?;
        let generation = handle.generation();
        assert!(matches!(
            events.recv().await?,
            ConnectionEvent::Connected { generation: g, .. } if g == generation
        ));

        handle.request_stop(DisconnectReason::Lock);
        wait_disconnected(&mut events, generation, DisconnectReason::Lock).await;
        wait_keepalive_running(&handle, false).await;
        tokio::time::advance(KEEPALIVE_IDLE + KEEPALIVE_CALL).await;
        assert!(io.output.recv().await.is_none(), "lock must close the stream");
        assert!(!handle.test_keepalive_running(), "lock must abort the keepalive task");
        handle.stop_with_reason(DisconnectReason::Lock).await;

        let (handle, mut sessions) = reconnecting_fixture(keepalive_limits())?;
        let mut events = handle.events();
        let mut io = sessions.recv().await.ok_or("connector did not enter")?;
        handle.require_live(Duration::from_secs(600)).await?;
        let generation = handle.generation();
        assert!(matches!(
            events.recv().await?,
            ConnectionEvent::Connected { generation: g, .. } if g == generation
        ));
        send(
            &io,
            &GatewayServerFrame::Drain { session_id: "fixture".into(), reason: "rotation".into() },
        )?;
        wait_disconnected(&mut events, generation, DisconnectReason::Drain).await;
        wait_keepalive_running(&handle, false).await;
        assert!(io.output.recv().await.is_none(), "disconnect must abort keepalive");
        assert!(!handle.test_keepalive_running(), "drain must abort the keepalive task");

        let mut fresh = next_session(&handle, &mut sessions, generation).await?;
        let next = handle.generation();
        let mut connected = 0_u32;
        for _ in 0..10_000 {
            match events.try_recv() {
                Ok(ConnectionEvent::Connected { generation: g, .. }) if g == next => {
                    connected += 1;
                }
                Ok(_) => {}
                Err(_) if connected == 0 => tokio::task::yield_now().await,
                Err(_) => break,
            }
        }
        assert_eq!(connected, 1, "S8 renewal must send exactly one Connected");

        tokio::time::advance(KEEPALIVE_IDLE).await;
        assert!(matches!(
            wait_client_frame(&mut fresh.output).await,
            GatewayClientFrame::Heartbeat { .. }
        ));
        assert!(
            events.try_recv().is_err(),
            "keepalive must not emit Connected on the next generation"
        );
        handle.stop().await;
        Ok(())
    })
    .await
}
