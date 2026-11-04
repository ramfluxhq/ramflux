// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Running and queued jobs retain cleanup ownership until cancellation is fully joined.

use super::*;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

struct Cleanup(Arc<AtomicUsize>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[tokio::test]
async fn transfer_slots_are_bounded_and_cancellable_including_unpolled_jobs()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(30), Box::pin(case())).await?
}
async fn case() -> Result<(), Box<dyn std::error::Error>> {
    let slots = TransferSlots::start();
    let cleanup = Arc::new(AtomicUsize::new(0));
    let (entered, mut waiting) = mpsc::channel(TRANSFER_SLOTS);
    let release = Arc::new(Notify::new());
    let mut running = Vec::new();
    for _ in 0..TRANSFER_SLOTS {
        let entered = entered.clone();
        let release = Arc::clone(&release);
        let guard = Cleanup(Arc::clone(&cleanup));
        running.push(slots.submit(slots.reserve()?.bind(7, async move {
            let _guard = guard;
            entered.send(()).await.map_err(|_| cancelled())?;
            release.notified().await;
            Ok::<_, SdkError>(())
        })));
    }
    for _ in 0..TRANSFER_SLOTS {
        waiting.recv().await.ok_or("job did not enter")?;
    }
    let polled = Arc::new(AtomicUsize::new(0));
    let mut queued = Vec::new();
    for _ in 0..TRANSFER_QUEUE {
        let guard = Cleanup(Arc::clone(&cleanup));
        let polled = Arc::clone(&polled);
        queued.push(slots.submit(slots.reserve()?.bind(7, async move {
            let _guard = guard;
            polled.fetch_add(1, Ordering::AcqRel);
            std::future::pending::<Result<(), SdkError>>().await
        })));
    }
    let started = Instant::now();
    assert!(slots.reserve().is_err(), "the seventeenth queued job must be refused");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(polled.load(Ordering::Acquire), 0);
    assert_eq!(running[0].generation(), 7);
    queued[0].cancel();
    while !queued[0].is_finished() {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        cleanup.load(Ordering::Acquire),
        1,
        "unpolled cancellation must drop its cleanup guard"
    );
    let started = Instant::now();
    slots.stop().await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(running.iter().all(JobHandle::is_finished));
    assert!(queued.iter().all(JobHandle::is_finished));
    assert_eq!(polled.load(Ordering::Acquire), 0);
    assert_eq!(cleanup.load(Ordering::Acquire), TRANSFER_SLOTS + TRANSFER_QUEUE);
    for job in running.iter_mut().chain(queued.iter_mut()) {
        assert!(job.wait().await.is_err());
    }
    Ok(())
}
