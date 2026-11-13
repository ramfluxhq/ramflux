// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Manager-only attempt deadline and restart tests isolate the connector from engine timers.

use super::*;
use crate::bus::connection_manager::model::ConnectionPhase;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::{sync::Notify, time::Instant};

struct Lease {
    file: std::fs::File,
    dropped: Arc<AtomicBool>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
        self.dropped.store(true, Ordering::Release);
    }
}
struct NeverConnector {
    lease: Mutex<Option<Lease>>,
    entered: Arc<Notify>,
}
impl SessionConnector for NeverConnector {
    fn connect(
        &self,
        _config: GatewaySessionConfig,
        _deadline: Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        let lease = self.lease.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        Box::pin(async move {
            let _lease = lease;
            self.entered.notify_one();
            std::future::pending().await
        })
    }
}

#[tokio::test(start_paused = true)]
async fn manager_attempt_timeout_drops_an_uncooperative_connector_and_real_lease()
-> Result<(), Box<dyn std::error::Error>> {
    super::watchdog(async {
        let root = tempfile::tempdir()?;
        let path = root.path().join(".network.lock");
        let file = std::fs::File::create(&path)?;
        fs2::FileExt::try_lock_exclusive(&file)?;
        let contender = std::fs::File::open(&path)?;
        assert!(fs2::FileExt::try_lock_exclusive(&contender).is_err());
        let dropped = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(Notify::new());
        let mut limits = limits();
        limits.attempt = Duration::from_secs(120);
        let handle = ConnectionHandle::start_with(
            config()?,
            None,
            limits,
            Arc::new(NeverConnector {
                lease: Mutex::new(Some(Lease { file, dropped: Arc::clone(&dropped) })),
                entered: Arc::clone(&entered),
            }),
            None,
        );
        entered.notified().await;
        let start = Instant::now();
        tokio::time::advance(Duration::from_secs(119)).await;
        tokio::task::yield_now().await;
        assert_eq!(handle.snapshot().phase, ConnectionPhase::Connecting);
        assert!(!dropped.load(Ordering::Acquire));
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(start.elapsed(), Duration::from_secs(120));
        assert_eq!(handle.snapshot().phase, ConnectionPhase::Backoff);
        assert_eq!(handle.snapshot().attempt, 1);
        assert!(handle.metadata().is_none());
        assert!(dropped.load(Ordering::Acquire));
        fs2::FileExt::try_lock_exclusive(&contender)?;
        fs2::FileExt::unlock(&contender)?;
        handle.stop().await;
        assert_eq!(handle.snapshot().phase, ConnectionPhase::Stopped);
        Ok(())
    })
    .await
}

struct FailsOnce {
    attempts: Arc<AtomicUsize>,
    next: Connector,
}
impl SessionConnector for FailsOnce {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        deadline: Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(async move {
            if self.attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                return Err(SdkError::GatewaySessionRejected("injected connector failure".into()));
            }
            self.next.connect(config, deadline).await
        })
    }
}

#[tokio::test(start_paused = true)]
async fn manager_retries_connector_error_with_the_same_backoff_policy()
-> Result<(), Box<dyn std::error::Error>> {
    super::watchdog(async {
        let limits = limits();
        let (sessions, mut receive) = mpsc::channel(8);
        let attempts = Arc::new(AtomicUsize::new(0));
        let handle = ConnectionHandle::start_with(
            config()?,
            None,
            limits.clone(),
            Arc::new(FailsOnce {
                attempts: Arc::clone(&attempts),
                next: Connector { sessions, frame: limits.frame },
            }),
            None,
        );
        tokio::task::yield_now().await;
        assert_eq!(handle.snapshot().phase, ConnectionPhase::Backoff);
        assert!(
            handle
                .snapshot()
                .last_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("injected connector failure")),
            "the real manager must publish the connector's typed failure"
        );
        let until = handle.snapshot().retry_after_ms.ok_or("missing restart backoff")?;
        let before = handle.generation();
        tokio::time::advance(Duration::from_millis(until - 1)).await;
        for _ in 0..10 {
            let _ = handle.snapshot();
            tokio::task::yield_now().await;
        }
        assert_eq!(attempts.load(Ordering::Acquire), 1, "reads cannot restart an attempt");
        tokio::time::advance(Duration::from_millis(1)).await;
        let _io = receive.recv().await.ok_or("restart did not connect")?;
        handle.require_live(Duration::from_secs(600)).await?;
        assert_eq!(handle.snapshot().phase, ConnectionPhase::Live);
        assert_eq!(attempts.load(Ordering::Acquire), 2);
        assert_ne!(handle.generation(), before);
        handle.stop().await;
        Ok(())
    })
    .await
}

struct CapacityOnce {
    attempts: Arc<AtomicUsize>,
    next: Connector,
    resets: u64,
}
impl SessionConnector for CapacityOnce {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        deadline: Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(async move {
            if self.attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                return Err(SdkError::CustodyCapacity {
                    capacity: ramflux_protocol::custody::CapacityHint {
                        scope: ramflux_protocol::custody::CapacityScope::PrefixDaily,
                        resets_at_unix: self.resets,
                    },
                });
            }
            self.next.connect(config, deadline).await
        })
    }
}
#[tokio::test(start_paused = true)]
async fn manager_honours_a_long_local_cooldown_across_status_polls_and_network_requests()
-> Result<(), Box<dyn std::error::Error>> {
    watchdog(async {
        let limits = limits();
        let (sessions, mut receive) = mpsc::channel(8);
        let attempts = Arc::new(AtomicUsize::new(0));
        let handle = ConnectionHandle::start_with(
            config()?,
            None,
            limits.clone(),
            Arc::new(CapacityOnce {
                attempts: Arc::clone(&attempts),
                next: Connector { sessions, frame: limits.frame },
                resets: crate::custody::capacity_hint::unix_now() + 600,
            }),
            None,
        );
        while handle.snapshot().phase != ConnectionPhase::Backoff {
            tokio::task::yield_now().await;
        }
        let delay = handle.snapshot().retry_after_ms.ok_or("cooldown")?;
        assert!((599_000..=600_000).contains(&delay));
        let first = handle.snapshot().next_retry_at_ms;
        let generation = handle.generation();
        let start = Instant::now();
        while start.elapsed().as_millis() + 1000 < u128::from(delay) {
            tokio::time::advance(Duration::from_secs(1)).await;
            let snapshot = handle.snapshot();
            assert_eq!(
                snapshot.next_retry_at_ms, first,
                "poll must not reset the monotonic schedule"
            );
            assert!(matches!(
                snapshot.cause,
                Some(crate::AccountNetworkingReason::NodeBusy { .. })
            ));
            assert!(handle.require_live(Duration::ZERO).await.is_err());
            assert_eq!(attempts.load(Ordering::Acquire), 1);
        }
        tokio::time::advance(
            Duration::from_millis(delay)
                .checked_sub(start.elapsed())
                .and_then(|remaining| remaining.checked_sub(Duration::from_millis(1)))
                .ok_or("cooldown boundary already crossed")?,
        )
        .await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::Acquire), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        let _io = receive.recv().await.ok_or("retry at expiry")?;
        handle.require_live(Duration::ZERO).await?;
        assert_eq!(start.elapsed(), Duration::from_millis(delay));
        assert_eq!(attempts.load(Ordering::Acquire), 2);
        assert_ne!(handle.generation(), generation);
        handle.stop().await;
        Ok(())
    })
    .await
}
