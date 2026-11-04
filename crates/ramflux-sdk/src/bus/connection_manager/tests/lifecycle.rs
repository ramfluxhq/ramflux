// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session retirement isolates late replies and joins generation-owned children.

use super::*;
use crate::bus::connection_manager::{ConnectionEvent, DisconnectReason, model::ConnectionPhase};
use tokio::time::Instant;

type Case = Result<(), Box<dyn std::error::Error>>;

async fn connected(
    handle: &ConnectionHandle,
    sessions: &mut mpsc::UnboundedReceiver<SessionIo>,
) -> Result<SessionIo, Box<dyn std::error::Error>> {
    let io = sessions.recv().await.ok_or("session was not opened")?;
    handle.require_live(Duration::from_secs(600)).await?;
    Ok(io)
}
async fn next_session(
    handle: &ConnectionHandle,
    sessions: &mut mpsc::UnboundedReceiver<SessionIo>,
    generation: u64,
) -> Result<SessionIo, Box<dyn std::error::Error>> {
    while handle.snapshot().phase != ConnectionPhase::Backoff {
        tokio::task::yield_now().await;
    }
    let delay = handle.snapshot().retry_after_ms.ok_or("retry not recorded")?;
    tokio::time::advance(Duration::from_millis(delay)).await;
    let io = connected(handle, sessions).await?;
    assert_ne!(handle.generation(), generation);
    Ok(io)
}
async fn heartbeat(handle: &ConnectionHandle, io: &mut SessionIo) -> Case {
    let caller = handle.clone();
    let call = tokio::spawn(async move {
        caller
            .call(|engine| Box::pin(engine.heartbeat()), Instant::now() + Duration::from_secs(600))
            .await
    });
    assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Heartbeat { .. })));
    send(io, &GatewayServerFrame::Heartbeat { now: 42 })?;
    call.await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn session_host_drain_fails_the_active_call_and_opens_a_fresh_session() -> Case {
    watchdog(async {
        let (handle, mut sessions) = reconnecting_fixture(limits())?;
        let mut io = connected(&handle, &mut sessions).await?;
        let generation = handle.generation();
        let mut events = handle.events();
        let caller = handle.clone();
        let call = tokio::spawn(async move {
            caller.call(|engine| Box::pin(engine.cursor()), Instant::now() + Duration::from_secs(600)).await
        });
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        send(&io, &GatewayServerFrame::Drain { session_id: "fixture".into(), reason: "rotation".into() })?;
        assert!(call.await?.is_err());
        assert!(matches!(events.recv().await?, ConnectionEvent::Disconnected { reason: DisconnectReason::Drain, generation: g } if g==generation));
        assert!(io.output.recv().await.is_none(), "retired session must never write again");
        let mut fresh = next_session(&handle, &mut sessions, generation).await?;
        heartbeat(&handle, &mut fresh).await?;
        handle.stop().await;
        Ok(())
    }).await
}

#[tokio::test(start_paused = true)]
async fn session_host_stray_reply_retires_the_session_instead_of_answering_the_next_call() -> Case {
    watchdog(async {
        let (handle, mut sessions) = reconnecting_fixture(limits())?;
        let io = connected(&handle, &mut sessions).await?;
        let generation = handle.generation();
        let mut events = handle.events();
        send(
            &io,
            &GatewayServerFrame::ForwardAck {
                ack: crate::gateway::GatewayForwardAck {
                    envelope_id: "stray".into(),
                    target_delivery_id: "host-target".into(),
                    inbox_seq: None,
                },
            },
        )?;
        assert!(matches!(
            events.recv().await?,
            ConnectionEvent::Disconnected { reason: DisconnectReason::UnexpectedReply, .. }
        ));
        let mut fresh = next_session(&handle, &mut sessions, generation).await?;
        heartbeat(&handle, &mut fresh).await?;
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn session_host_written_call_timeout_drops_the_stream_and_its_late_reply() -> Case {
    retirement_timeout(Duration::from_secs(7), Duration::from_secs(600)).await
}
#[tokio::test(start_paused = true)]
async fn session_host_live_frame_timeout_retires_at_fifteen_seconds() -> Case {
    retirement_timeout(Duration::from_secs(600), Duration::from_secs(15)).await
}
async fn retirement_timeout(call_budget: Duration, frame_budget: Duration) -> Case {
    watchdog(async {
        let mut timeouts = limits();
        timeouts.frame = frame_budget;
        let (handle, mut sessions) = reconnecting_fixture(timeouts)?;
        let mut io = connected(&handle, &mut sessions).await?;
        let generation = handle.generation();
        let mut events = handle.events();
        let caller = handle.clone();
        let start = Instant::now();
        let call = tokio::spawn(async move {
            caller.call(|engine| Box::pin(engine.cursor()), start + call_budget).await
        });
        assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
        let expected = call_budget.min(frame_budget);
        tokio::time::advance(
            expected.checked_sub(Duration::from_secs(1)).ok_or("invalid test deadline")?,
        )
        .await;
        tokio::task::yield_now().await;
        assert!(!call.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(call.await?.is_err());
        assert_eq!(start.elapsed(), expected);
        assert!(matches!(
            events.recv().await?,
            ConnectionEvent::Disconnected { reason: DisconnectReason::CallTimeout, .. }
        ));
        assert!(
            io.input
                .send(serde_json::to_vec(&GatewayServerFrame::Cursor { cursor: None })?)
                .is_err(),
            "late reply must have no reader"
        );
        let mut fresh = next_session(&handle, &mut sessions, generation).await?;
        heartbeat(&handle, &mut fresh).await?;
        handle.stop().await;
        Ok(())
    })
    .await
}

struct ChildDrop {
    generation: u64,
    dropped: mpsc::UnboundedSender<u64>,
}
impl Drop for ChildDrop {
    fn drop(&mut self) {
        let _ = self.dropped.send(self.generation);
    }
}
#[tokio::test(start_paused = true)]
async fn connection_events_and_child_slot_lifecycle_follow_each_session_generation() -> Case {
    watchdog(async {
        let (handle, mut sessions) = reconnecting_fixture(limits())?;
        let mut events = handle.events();
        let mut io = connected(&handle, &mut sessions).await?;
        let generation = handle.generation();
        let event = events.recv().await?;
        assert!(matches!(event, ConnectionEvent::Connected { generation:g, .. } if g==generation));
        let (started, mut starts) = mpsc::unbounded_channel();
        let (dropped, mut drops) = mpsc::unbounded_channel();
        handle.spawn_session_child("lifecycle-proof", move |context| {
            let started = started.clone();
            let dropped = dropped.clone();
            Box::pin(async move {
                let _guard = ChildDrop { generation: context.generation, dropped };
                let _ = started.send((context.generation, context.session_id.clone()));
                std::future::pending::<()>().await;
            })
        })?;
        assert_eq!(starts.recv().await.ok_or("child not started")?.0, generation);
        heartbeat(&handle, &mut io).await?;
        assert!(events.try_recv().is_err(), "ordinary calls must not emit another Connected");
        send(&io, &GatewayServerFrame::Close { reason: "rotate".into() })?;
        assert_eq!(drops.recv().await, Some(generation));
        let mut fresh = next_session(&handle, &mut sessions, generation).await?;
        let next = handle.generation();
        let (child_generation, session) = starts.recv().await.ok_or("child not restarted")?;
        assert_eq!(child_generation, next);
        assert_eq!(Some(session), handle.snapshot().session_id);
        heartbeat(&handle, &mut fresh).await?;
        let failed = handle
            .call::<(), _>(
                |engine| {
                    Box::pin(async move {
                        std::panic::resume_unwind(Box::new(format!(
                            "injected restart of live session {}",
                            engine.session().session_id
                        )));
                    })
                },
                Instant::now() + Duration::from_secs(600),
            )
            .await;
        assert!(failed.is_err());
        assert_eq!(drops.recv().await, Some(next), "restart must join the previous child");
        let mut restarted = next_session(&handle, &mut sessions, next).await?;
        let restarted_generation = handle.generation();
        assert_eq!(
            starts.recv().await.ok_or("child not restarted after panic")?.0,
            restarted_generation
        );
        heartbeat(&handle, &mut restarted).await?;
        let wall = std::time::Instant::now();
        handle.stop_with_reason(DisconnectReason::Lock).await;
        assert!(wall.elapsed() < Duration::from_secs(1));
        assert_eq!(
            drops.recv().await,
            Some(restarted_generation),
            "lock reply must follow child cancellation"
        );
        assert!(starts.try_recv().is_err());
        assert!(handle.test_finished());
        Ok(())
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn engine_is_resident_across_consecutive_network_calls() -> Case {
    watchdog(async {
        let (handle, mut sessions) = reconnecting_fixture(limits())?;
        let mut io = connected(&handle, &mut sessions).await?;
        let generation = handle.generation();
        heartbeat(&handle, &mut io).await?;
        heartbeat(&handle, &mut io).await?;
        assert_eq!(handle.generation(), generation);
        assert_eq!(handle.snapshot().attempt, 1);
        assert!(
            sessions.try_recv().is_err(),
            "consecutive commands must reuse one resident engine"
        );
        handle.stop().await;
        Ok(())
    })
    .await
}
