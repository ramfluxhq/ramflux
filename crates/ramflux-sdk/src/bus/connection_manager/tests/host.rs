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

async fn wait_for_queued(handle: &ConnectionHandle, bulk: usize, priority: usize) {
    while handle.places.available_permits() != super::super::CALL_QUEUE - bulk
        || handle.priority_places.available_permits() != super::super::CALL_QUEUE - priority
    {
        tokio::task::yield_now().await;
    }
}

fn receipt_cursor(
    handle: ConnectionHandle,
) -> tokio::task::JoinHandle<Result<Option<crate::GatewayCursor>, crate::SdkError>> {
    tokio::spawn(async move {
        handle
            .test_context()
            .priority_call(|engine| Box::pin(engine.cursor()), Duration::from_secs(3))
            .await
    })
}

#[tokio::test]
async fn session_host_priority_call_dequeues_before_queued_bulk() -> Case {
    super::watchdog(async {
        let (handle, mut io) = fixture().await?;
        let first = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        let bulk = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
        wait_for_queued(&handle, 1, 0).await;
        let receipt = receipt_cursor(handle.clone());
        wait_for_queued(&handle, 1, 1).await;
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        first.await??;
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        receipt.await??;
        assert!(!bulk.is_finished());
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        bulk.await??;
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn receipt_waits_at_most_one_inflight_bulk_call() -> Case {
    super::watchdog(async {
        let (handle, mut io) = fixture().await?;
        let first = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        let mut bulk = Vec::new();
        // Fill all bulk places: the receipt still has reserved admission capacity.
        for _ in 0..super::super::CALL_QUEUE {
            bulk.push(cursor(handle.clone(), Instant::now() + Duration::from_secs(600)));
        }
        wait_for_queued(&handle, super::super::CALL_QUEUE, 0).await;
        let receipt = receipt_cursor(handle.clone());
        wait_for_queued(&handle, super::super::CALL_QUEUE, 1).await;
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        first.await??;
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        receipt.await??;
        assert!(bulk.iter().all(|call| !call.is_finished()));
        for call in bulk {
            call.abort();
            let _ = call.await;
        }
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn session_host_receipt_deadline_counts_from_dequeue() -> Case {
    super::watchdog(async {
        let (handle, mut io) = fixture().await?;
        let first = cursor(handle.clone(), Instant::now() + Duration::from_secs(600));
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        let receipt = receipt_cursor(handle.clone());
        wait_for_queued(&handle, 0, 1).await;
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(!receipt.is_finished(), "queue wait must not consume the exchange budget");
        send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
        first.await??;
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!receipt.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(receipt.await?.is_err(), "the exchange must expire three seconds after dequeue");
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn priority_call_cannot_await_writer_apply() -> Result<(), Box<dyn std::error::Error>> {
    let (handle, _io) = super::fixture().await?;
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let writer = crate::bus::couriers::writer::Writer::new(sender, handle.generation());
    let context = handle.test_context();
    let rejected = context
        .priority_call(
            move |_engine| {
                Box::pin(async move {
                    let mut checkpoint = Box::pin(writer.apply(|_| Ok(())));
                    let rejected = std::future::poll_fn(|cx| {
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            std::future::Future::poll(checkpoint.as_mut(), cx)
                        })) {
                            Err(_) => std::task::Poll::Ready(true),
                            Ok(std::task::Poll::Ready(_)) => std::task::Poll::Ready(false),
                            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
                        }
                    })
                    .await;
                    Ok(rejected)
                })
            },
            std::time::Duration::from_secs(1),
        )
        .await?;
    assert!(rejected, "the priority closure must reject writer access before queueing");
    assert!(receiver.try_recv().is_err());
    handle.stop().await;
    Ok(())
}

#[tokio::test]
async fn ephemeral_session_client_generation_owns_exchange_and_consumer() -> Case {
    use crate::gateway::access::GatewaySessionAccess;
    super::watchdog(async {
        let (handle, mut io) = fixture().await?;
        let deadline = Instant::now() + Duration::from_secs(600);
        handle.call(|engine| Box::pin(async move {
            engine.ephemeral_negotiated = true;
            Ok(())
        }), deadline).await?;
        let metadata = handle.metadata().ok_or("metadata missing")?;
        let mut stale = crate::bus::connection_manager::SessionClient::new(handle.clone(), metadata.clone(), deadline);
        let mut client = crate::bus::connection_manager::SessionClient::new(handle.clone(), metadata, deadline);
        let mut consumer = client.take_ephemeral_consumer().await?.ok_or("consumer missing")?;
        assert!(client.take_ephemeral_consumer().await?.is_none());
        let mut envelope = entry("host-ephemeral", 1)?.envelope;
        envelope.envelope_id = "host-ephemeral".into();
        envelope.created_at = crate::time::now_unix_timestamp();
        envelope.ttl = 5;
        envelope.priority = ramflux_protocol::Priority::Low;
        envelope.ext.ext.insert("delivery_mode".into(), serde_json::json!("ephemeral"));
        let call = tokio::spawn(async move { client.submit_ephemeral(envelope).await });
        let submitted = io.output.recv().await.ok_or("submit missing")?;
        assert!(matches!(submitted, GatewayClientFrame::Submit { submit } if submit.envelope.envelope_id == "host-ephemeral"));
        send(&io, &GatewayServerFrame::EphemeralResult {
            envelope_id: "host-ephemeral".into(), result: ramflux_protocol::ephemeral::EphemeralSubmitResult::accepted(),
        })?;
        assert_eq!(call.await??, crate::EphemeralSendOutcome::Delivered);
        handle.stop().await;
        assert!(matches!(stale.take_ephemeral_consumer().await, Err(crate::SdkError::NetworkingPendingContext { .. })), "retired generation cannot obtain an adapter");
        assert!(consumer.next(|_| None).await.is_none(), "account stop closes the transient consumer");
        Ok(())
    }).await
}
