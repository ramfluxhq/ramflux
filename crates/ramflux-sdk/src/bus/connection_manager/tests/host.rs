// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real engine exchanges over the host fixture, with no actor or competing timers.

use super::{ConnectionHandle, GatewayClientFrame, GatewayServerFrame, entry, fixture, send};
use crate::bus::connection_manager::{NetworkingState, subscriptions::SessionEvent};
use crate::gateway::frame_dispatch::FrameKind;
use std::time::{Duration, Instant as WallClock};
use tokio::time::Instant;

type Case = Result<(), Box<dyn std::error::Error>>;
fn cursor(
    handle: ConnectionHandle,
    deadline: Instant,
) -> tokio::task::JoinHandle<Result<Option<crate::GatewayCursor>, crate::SdkError>> {
    tokio::spawn(async move { handle.call(|engine| Box::pin(engine.cursor()), deadline).await })
}

#[tokio::test]
async fn session_host_real_heartbeat_completes_without_publishing_a_heartbeat() -> Case {
    super::watchdog(async {
        let (handle, mut io) = fixture().await?;
        let mut subscription = handle.subscribe([FrameKind::Heartbeat]);
        let started = WallClock::now();
        let call = {
            let handle = handle.clone();
            tokio::spawn(async move {
                handle
                    .call(
                        |engine| Box::pin(engine.heartbeat()),
                        Instant::now() + Duration::from_secs(600),
                    )
                    .await
            })
        };
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Heartbeat { .. })));
        send(&io, &GatewayServerFrame::Heartbeat { now: 42 })?;
        call.await??;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), subscription.recv()).await.is_err()
        );
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_host_submit_matches_only_its_pending_envelope_and_routes_other_deliveries() -> Case
{
    super::watchdog(async {

    let (handle, mut io) = fixture().await?;
    let mut first = handle.subscribe([FrameKind::Deliver]);
    let mut second = handle.subscribe([FrameKind::Deliver]);
    let envelope = entry("submitted", 7)?.envelope;
    let submitted = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .call(
                    move |engine| Box::pin(engine.submit_envelope(envelope)),
                    Instant::now() + Duration::from_secs(600),
                )
                .await
        })
    };
    assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Submit { .. })));
    send(&io, &GatewayServerFrame::Deliver { entry: entry("unmatched", 8)? })?;
    send(&io, &GatewayServerFrame::Deliver { entry: entry("submitted", 7)? })?;
    assert_eq!(submitted.await??.envelope.envelope_id, "submitted");
    for subscription in [&mut first, &mut second] {
        match subscription.recv().await.ok_or("missing push")? {
            SessionEvent::Frame { frame, generation } => {
                assert_eq!(generation, handle.generation());
                assert!(
                    matches!(&*frame,GatewayServerFrame::Deliver {entry} if entry.envelope.envelope_id=="unmatched")
                );
            }
            other => return Err(format!("unexpected subscription event {other:?}").into()),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(10), subscription.recv()).await.is_err(),
            "the matched Submit receipt is not a push"
        );
    }
    handle.stop().await;
    Ok(())

    }).await
}

#[tokio::test(start_paused = true)]
async fn session_host_expires_a_queued_call_at_its_passed_deadline() -> Case {
    super::watchdog(async {
        let (handle, mut io) = fixture().await?;
        let first = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        let start = Instant::now();
        let second = cursor(handle.clone(), start + Duration::from_secs(7));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(7)).await;
        assert!(second.await?.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(7));
        let removals = handle.removals();
        assert_eq!(removals.len(), 1);
        assert_eq!(removals[0].cause, "QueuedCallExpired");
        assert_eq!(removals[0].deadline, start + Duration::from_secs(7));
        assert!(io.output.try_recv().is_err(), "queued expiry must precede any request write");
        assert_eq!(handle.snapshot().state, NetworkingState::Live);
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        first.await??;
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_host_fifo_and_queued_cancellation_preserve_the_live_session() -> Case {
    super::watchdog(async {
        let (handle, mut io) = fixture().await?;
        let first = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        let cancelled = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
        tokio::task::yield_now().await;
        cancelled.abort();
        let _ = cancelled.await;
        let third = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
        tokio::task::yield_now().await;
        assert!(io.output.try_recv().is_err());
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        first.await??;
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        third.await??;
        assert_eq!(handle.snapshot().state, NetworkingState::Live);
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_host_entry_cap_drops_exactly_ten_without_acknowledging_them() -> Case {
    super::watchdog(async { overflow_case(266, 16 * 1024, 256, 10).await }).await
}

#[tokio::test]
async fn session_host_byte_cap_is_independent_of_the_entry_cap() -> Case {
    super::watchdog(async { overflow_case(9, 960 * 1024, 8, 1).await }).await
}

async fn overflow_case(count: usize, body_size: usize, retained: usize, dropped: usize) -> Case {
    let (handle, mut io) = fixture().await?;
    let held = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
    assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
    for sequence in 0..count {
        let mut entry = entry(&format!("overflow-{sequence}"), sequence as u64)?;
        entry.envelope.encrypted_payload = "x".repeat(body_size);
        send(&io, &GatewayServerFrame::Deliver { entry })?;
    }
    send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
    held.await??;
    let (stats, actual, bytes) = handle
        .call(
            |engine| {
                Box::pin(async move {
                    Ok((
                        engine.buffer_stats,
                        engine.pending_deliveries.len(),
                        engine.buffered_bytes,
                    ))
                })
            },
            Instant::now() + Duration::from_secs(600),
        )
        .await?;
    assert_eq!(stats.entries, retained);
    assert_eq!(stats.dropped, dropped);
    assert_eq!(actual, retained);
    assert_eq!(stats.bytes, bytes);
    assert!(bytes <= crate::bus::runtime_limits::SESSION_BUFFER_BYTES);
    assert!(handle.resync_needed(), "dropping an entry requires a cursor resync");
    assert!(io.output.try_recv().is_err(), "a dropped delivery cannot be ACKed");
    handle.stop().await;
    Ok(())
}
