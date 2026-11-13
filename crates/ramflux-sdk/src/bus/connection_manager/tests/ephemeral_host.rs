// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Worker lifecycle boundaries for the account-generation-owned transient consumer.

use super::*;
use crate::bus::connection_manager::{ConnectionEvent, DisconnectReason};
use crate::gateway::session_push::ephemeral_tests::{envelope, frame, source};
use std::future::Future;
use tokio::sync::Semaphore;

type Case = Result<(), Box<dyn std::error::Error>>;
// A runnable witness prevents Tokio from auto-advancing across I/O or semaphore barriers.
struct ManualClock(tokio::task::JoinHandle<()>);
impl ManualClock {
    fn hold() -> Self {
        Self(tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        }))
    }
}
impl Drop for ManualClock {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct HeldConnector {
    opened: mpsc::UnboundedSender<SessionIo>,
    permits: Semaphore,
}
impl SessionConnector for HeldConnector {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        _deadline: tokio::time::Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(async move {
            self.permits
                .acquire()
                .await
                .map_err(|_| SdkError::GatewaySessionNotEstablished)?
                .forget();
            let (mut engine, io) = seeded_engine(config, &limits());
            engine.ephemeral_negotiated = true;
            self.opened.send(io).map_err(|_| SdkError::GatewaySessionNotEstablished)?;
            Ok(engine)
        })
    }
}
async fn read_through(handle: &ConnectionHandle, before: u64, count: u64) {
    while handle.shared.read_clock.read_count() < before + count {
        tokio::task::yield_now().await;
    }
}
async fn disconnected(
    events: &mut tokio::sync::broadcast::Receiver<ConnectionEvent>,
    expected: DisconnectReason,
) -> Case {
    loop {
        if let ConnectionEvent::Disconnected { reason, .. } = events.recv().await? {
            assert_eq!(reason, expected);
            return Ok(());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn ephemeral_worker_disconnect_reconnect_keeps_consumer_and_dedup_clears_pending() -> Case {
    watchdog(async {
        let _clock = ManualClock::hold();
        let (opened, mut sessions) = mpsc::unbounded_channel();
        let connector = Arc::new(HeldConnector { opened, permits: Semaphore::new(1) });
        let handle =
            ConnectionHandle::start_with(config()?, None, limits(), connector.clone(), None);
        let io = sessions.recv().await.ok_or("first connection missing")?;
        handle.require_live(Duration::from_secs(600)).await?;
        let inbox = handle
            .shared
            .ephemeral_inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut consumer = inbox.consumer().ok_or("consumer missing")?;
        // Freeze only the receiver's signed-lifetime fixture clock. Retry uses Tokio's
        // independently advanced monotonic clock; this row tests wiring while D is live.
        inbox.set_clock(crate::ReceiverClock { local_now_ms: 1_000_000, monotonic_ms: 0 });
        let now = 1_000;
        let first = frame(envelope(now, "dedup-before-disconnect").map_err(|e| e.to_string())?)?;
        let before = handle.shared.read_clock.read_count();
        io.input.send(first.clone())?;
        read_through(&handle, before, 1).await;
        let handoff = consumer.next(|_| source().ok()).await.ok_or("initial handoff missing")?;
        assert_eq!(handoff.0, first);
        consumer.complete();
        let pending =
            frame(envelope(now, "pending-before-disconnect").map_err(|e| e.to_string())?)?;
        let before = handle.shared.read_clock.read_count();
        io.input.send(pending)?;
        read_through(&handle, before, 1).await;
        assert_eq!(inbox.observation().0, 1);
        let mut events = handle.shared.events.subscribe();
        drop(io);
        disconnected(&mut events, DisconnectReason::Transport).await?;
        assert_eq!(
            inbox.observation(),
            (0, 0, 0, 1),
            "real worker disconnect must clear pending and preserve live dedup"
        );
        while handle.snapshot().retry_after_ms.is_none() {
            tokio::task::yield_now().await;
        }
        let delay = handle.snapshot().retry_after_ms.ok_or("retry boundary missing")?;
        tokio::time::advance(Duration::from_millis(delay)).await;
        connector.permits.add_permits(1);
        let io = sessions.recv().await.ok_or("reconnection missing")?;
        handle.require_live(Duration::from_secs(600)).await?;
        let fresh = frame(envelope(now, "fresh-after-reconnect").map_err(|e| e.to_string())?)?;
        let before = handle.shared.read_clock.read_count();
        io.input.send(first)?;
        io.input.send(fresh.clone())?;
        read_through(&handle, before, 2).await;
        let mut next = Box::pin(consumer.next(|_| source().ok()));
        let completion =
            std::future::poll_fn(|cx| std::task::Poll::Ready(next.as_mut().poll(cx))).await;
        let std::task::Poll::Ready(Some(handoff)) = completion else {
            return Err(
                "reconnected worker must deliver fresh ciphertext to the same consumer".into()
            );
        };
        drop(next);
        assert_eq!(
            handoff.0, fresh,
            "same consumer must suppress replay and accept fresh ciphertext after reconnect"
        );
        consumer.complete();
        assert_eq!(inbox.observation().3, 2);
        handle.stop().await;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn ephemeral_worker_lock_closes_consumer_and_removes_lease() -> Case {
    watchdog(async {
        let (handle, io) = fixture().await?;
        let inbox = handle
            .shared
            .ephemeral_inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut consumer = inbox.consumer().ok_or("consumer missing")?;
        let raw = frame(
            envelope(crate::time::now_unix_timestamp(), "pending-at-lock")
                .map_err(|e| e.to_string())?,
        )?;
        inbox.push(&raw, u64::MAX);
        assert_eq!(inbox.observation().0, 1);
        handle.stop_with_reason(DisconnectReason::Lock).await;
        let mut next = Box::pin(consumer.next(|_| source().ok()));
        let completion =
            std::future::poll_fn(|cx| std::task::Poll::Ready(next.as_mut().poll(cx))).await;
        assert!(
            matches!(completion, std::task::Poll::Ready(None)),
            "Lock must terminate the existing consumer before stop returns"
        );
        assert!(inbox.consumer().is_none(), "Lock must refuse a replacement consumer");
        assert_eq!(inbox.observation(), (0, 0, 0, 0));
        drop(io);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn ephemeral_worker_error_closes_old_consumer_and_replaces_generation_inbox() -> Case {
    watchdog(async {
        let (handle, io) = fixture().await?;
        let inbox = handle
            .shared
            .ephemeral_inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut consumer = inbox.consumer().ok_or("consumer missing")?;
        let raw = frame(
            envelope(crate::time::now_unix_timestamp(), "pending-at-error")
                .map_err(|e| e.to_string())?,
        )?;
        inbox.push(&raw, u64::MAX);
        assert_eq!(inbox.observation().0, 1);
        let mut events = handle.shared.events.subscribe();
        let owner = handle.clone();
        let call = tokio::spawn(async move {
            owner
                .call::<(), _>(
                    |engine| {
                        Box::pin(async move {
                            engine.terminal_reason = Some(DisconnectReason::Restart);
                            Err(SdkError::GatewaySessionRejected("fixture host failure".into()))
                        })
                    },
                    tokio::time::Instant::now() + Duration::from_secs(600),
                )
                .await
        });
        assert!(
            matches!(call.await?, Err(SdkError::GatewaySessionRejected(_))),
            "failed host call must return its typed error"
        );
        disconnected(&mut events, DisconnectReason::Restart).await?;
        let mut next = Box::pin(consumer.next(|_| source().ok()));
        let completion =
            std::future::poll_fn(|cx| std::task::Poll::Ready(next.as_mut().poll(cx))).await;
        assert!(
            matches!(completion, std::task::Poll::Ready(None)),
            "error retirement must close the displaced generation's consumer before restart publication"
        );
        assert_eq!(inbox.observation(), (0, 0, 0, 0));
        assert!(
            handle
                .shared
                .ephemeral_inbox
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .consumer()
                .is_some(),
            "error retirement must install a fresh inbox capability"
        );
        handle.stop().await;
        drop(io);
        Ok(())
    })
    .await
}
