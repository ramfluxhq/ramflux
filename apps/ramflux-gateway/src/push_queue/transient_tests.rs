// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Isolated occupancy, D4 priority, expiry and retirement rows for the transient FIFO.
use super::{EMPTY, Next, PushQueue, TRANSIENT_BYTE_CAP, TRANSIENT_FRAME_CAP, TransientAdmission};
use crate::session_push::tests::support::{ID, sink};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NOW_MS: u64 = 1_000_000;
const LIVE_MS: u64 = NOW_MS + 1;
const MAX_FRAME: usize = 32_768;

type TestResult<T = ()> = anyhow::Result<T>;

/// Hang guard: fails the test (assertion panic) if `future` does not finish within 10 s.
async fn guard_10s<F: std::future::Future>(what: &str, future: F) -> F::Output {
    let finished = tokio::time::timeout(Duration::from_secs(10), future).await;
    assert!(finished.is_ok(), "{what} did not finish within 10s");
    match finished {
        Ok(output) => output,
        Err(_) => unreachable!("guarded by the assert above"),
    }
}

fn queue() -> PushQueue {
    let (closed, _) = tokio::sync::watch::channel(false);
    let queue = PushQueue::new(16, closed);
    queue.set_clock_ms(NOW_MS);
    queue
}

fn transient_bytes(n: u32) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({"frame_type":"ephemeral","n":n}))?)
}

fn max_frame_bytes() -> anyhow::Result<Vec<u8>> {
    let base = serde_json::to_vec(&json!({"frame_type":"ephemeral","pad":""}))?.len();
    let bytes =
        serde_json::to_vec(&json!({"frame_type":"ephemeral","pad":"x".repeat(MAX_FRAME - base)}))?;
    anyhow::ensure!(bytes.len() == MAX_FRAME, "fixture is {} bytes", bytes.len());
    Ok(bytes)
}

fn durable_bytes(seq: u64) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({"frame_type":"deliver","seq":seq}))?)
}

fn occupancy(queue: &PushQueue) -> (usize, usize) {
    queue
        .inner
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .transient_occupancy()
}

fn durable_occupancy(queue: &PushQueue) -> (usize, usize) {
    queue.inner.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).occupancy()
}

fn slot(queue: &PushQueue) -> u64 {
    queue.inner.slot.load(Ordering::Acquire)
}

fn coverage_prefix(queue: &PushQueue) -> u64 {
    queue.inner.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).coverage.prefix
}

async fn installed() -> TestResult<(PushQueue, crate::GatewaySendHandle, Arc<Mutex<Vec<Value>>>)> {
    let queue = queue();
    let (send, frames) = sink();
    queue.install(&send, Some(ID.into())).await?;
    Ok((queue, send, frames))
}

fn row_frame_cap_inclusive() -> TestResult {
    let queue = queue();
    for n in 0..TRANSIENT_FRAME_CAP {
        assert_eq!(
            queue.try_push_transient(transient_bytes(u32::try_from(n)?)?, LIVE_MS),
            TransientAdmission::Queued
        );
    }
    assert_eq!(occupancy(&queue), (TRANSIENT_FRAME_CAP, occupancy(&queue).1));
    assert_eq!(
        queue.try_push_transient(transient_bytes(64)?, LIVE_MS),
        TransientAdmission::QueueFull
    );
    assert_eq!(occupancy(&queue).0, TRANSIENT_FRAME_CAP);
    assert_eq!(slot(&queue), EMPTY);
    Ok(())
}

fn row_byte_cap_inclusive() {
    let at_cap = queue();
    assert_eq!(
        at_cap.try_push_transient(vec![0; TRANSIENT_BYTE_CAP], LIVE_MS),
        TransientAdmission::Queued
    );
    assert_eq!(occupancy(&at_cap), (1, TRANSIENT_BYTE_CAP));
    assert_eq!(at_cap.try_push_transient(vec![0; 1], LIVE_MS), TransientAdmission::QueueFull);
    let over = queue();
    assert_eq!(
        over.try_push_transient(vec![0; TRANSIENT_BYTE_CAP.saturating_add(1)], LIVE_MS),
        TransientAdmission::QueueFull
    );
    assert_eq!(occupancy(&over), (0, 0));
}

fn row_eight_max_frames_ninth_queue_full() {
    let queue = queue();
    for _ in 0..8 {
        assert_eq!(
            queue.try_push_transient(vec![0; MAX_FRAME], LIVE_MS),
            TransientAdmission::Queued
        );
    }
    assert_eq!(occupancy(&queue), (8, TRANSIENT_BYTE_CAP));
    assert_eq!(
        queue.try_push_transient(vec![0; MAX_FRAME], LIVE_MS),
        TransientAdmission::QueueFull
    );
    assert_eq!(occupancy(&queue), (8, TRANSIENT_BYTE_CAP));
}

fn row_inflight_counts_toward_frame_cap() -> TestResult {
    let queue = queue();
    for n in 0..TRANSIENT_FRAME_CAP {
        assert_eq!(
            queue.try_push_transient(transient_bytes(u32::try_from(n)?)?, LIVE_MS),
            TransientAdmission::Queued
        );
    }
    let Next::Transient(inflight) = queue.next() else {
        anyhow::bail!("expected in-flight transient");
    };
    assert_eq!(occupancy(&queue), (TRANSIENT_FRAME_CAP, occupancy(&queue).1));
    assert_eq!(
        queue.try_push_transient(transient_bytes(65)?, LIVE_MS),
        TransientAdmission::QueueFull
    );
    queue.complete_transient(&inflight);
    assert_eq!(occupancy(&queue).0, TRANSIENT_FRAME_CAP.saturating_sub(1));
    assert_eq!(queue.try_push_transient(transient_bytes(66)?, LIVE_MS), TransientAdmission::Queued);
    Ok(())
}

async fn row_inflight_sink_write_still_occupies() -> TestResult {
    let (queue, send, _frames) = installed().await?;
    for n in 0..TRANSIENT_FRAME_CAP {
        assert_eq!(
            queue.try_push_transient(transient_bytes(u32::try_from(n)?)?, LIVE_MS),
            TransientAdmission::Queued
        );
    }
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    queue.park_next_write(entered.clone(), release.clone());
    let writer = queue.clone();
    let sink = send.clone();
    let task = tokio::spawn(async move {
        let Next::Transient(frame) = writer.next() else {
            anyhow::bail!("expected transient");
        };
        let wrote = writer.write(&sink, &frame.bytes, Some(ID), Some(frame.expires_at_ms)).await;
        writer.complete_transient(&frame);
        Ok(wrote)
    });
    guard_10s("writer sink barrier", entered.notified()).await;
    assert_eq!(occupancy(&queue).0, TRANSIENT_FRAME_CAP);
    assert_eq!(
        queue.try_push_transient(transient_bytes(99)?, LIVE_MS),
        TransientAdmission::QueueFull
    );
    release.add_permits(1);
    let wrote = guard_10s("writer task", task).await??;
    assert!(wrote);
    Ok(())
}

/// M2: one 32,768-byte write held in flight plus seven queued maximum frames fill the byte cap;
/// the ninth admission is an exact `QueueFull`, and the in-flight frame still occupies.
async fn row_inflight_max_write_seven_queued_ninth_queue_full() -> TestResult {
    let (queue, send, frames) = installed().await?;
    for _ in 0..8 {
        assert_eq!(
            queue.try_push_transient(max_frame_bytes()?, LIVE_MS),
            TransientAdmission::Queued
        );
    }
    assert_eq!(occupancy(&queue), (8, TRANSIENT_BYTE_CAP));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    queue.park_next_write(entered.clone(), release.clone());
    let writer = queue.clone();
    let sink = send.clone();
    let task = tokio::spawn(async move {
        let Next::Transient(frame) = writer.next() else {
            anyhow::bail!("expected transient");
        };
        let wrote = writer.write(&sink, &frame.bytes, Some(ID), Some(frame.expires_at_ms)).await;
        writer.complete_transient(&frame);
        Ok(wrote)
    });
    guard_10s("in-flight sink barrier", entered.notified()).await;
    assert_eq!(occupancy(&queue), (8, TRANSIENT_BYTE_CAP));
    assert_eq!(
        queue.try_push_transient(max_frame_bytes()?, LIVE_MS),
        TransientAdmission::QueueFull
    );
    assert_eq!(occupancy(&queue), (8, TRANSIENT_BYTE_CAP));
    release.add_permits(1);
    let wrote = guard_10s("in-flight writer task", task).await??;
    assert!(wrote);
    assert_eq!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.len(), 1);
    assert_eq!(occupancy(&queue), (7, 7 * MAX_FRAME));
    Ok(())
}

/// M1: a frame selected at D-1 that waits on the sink mutex past D is dropped silently.
async fn row_expired_while_waiting_for_sink_not_written() -> TestResult {
    let (queue, send, frames) = installed().await?;
    let deadline = NOW_MS + 10;
    assert_eq!(queue.try_push_transient(transient_bytes(1)?, deadline), TransientAdmission::Queued);
    queue.set_clock_ms(deadline - 1);
    let Next::Transient(frame) = queue.next() else {
        anyhow::bail!("expected transient at D-1");
    };
    let held = send.lock().await;
    let writer = queue.clone();
    let sink = send.clone();
    let task = tokio::spawn(async move {
        let wrote = writer.write(&sink, &frame.bytes, Some(ID), Some(frame.expires_at_ms)).await;
        writer.complete_transient(&frame);
        wrote
    });
    queue.set_clock_ms(deadline);
    drop(held);
    let wrote = guard_10s("expired writer task", task).await?;
    assert!(wrote, "expiry is a silent drop, not a sink failure");
    assert!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.is_empty());
    assert_eq!(occupancy(&queue), (0, 0));
    Ok(())
}

fn row_transient_does_not_touch_durable_or_resync() -> TestResult {
    let queue = queue();
    for n in 0..TRANSIENT_FRAME_CAP {
        assert_eq!(
            queue.try_push_transient(transient_bytes(u32::try_from(n)?)?, LIVE_MS),
            TransientAdmission::Queued
        );
    }
    assert_eq!(durable_occupancy(&queue), (0, 0));
    assert_eq!(slot(&queue), EMPTY);
    assert_eq!(coverage_prefix(&queue), 0);
    assert_eq!(
        queue.try_push_transient(transient_bytes(70)?, LIVE_MS),
        TransientAdmission::QueueFull
    );
    assert_eq!(slot(&queue), EMPTY);
    assert_eq!(coverage_prefix(&queue), 0);
    Ok(())
}

fn row_closed_refuses() -> TestResult {
    let queue = queue();
    queue.retire();
    assert_eq!(queue.try_push_transient(transient_bytes(1)?, LIVE_MS), TransientAdmission::Closed);
    assert_eq!(occupancy(&queue), (0, 0));
    Ok(())
}

fn row_expired_at_deadline_dropped_unexpired_kept() -> TestResult {
    let queue = queue();
    assert_eq!(queue.try_push_transient(transient_bytes(1)?, NOW_MS), TransientAdmission::Queued);
    assert_eq!(queue.try_push_transient(transient_bytes(2)?, LIVE_MS), TransientAdmission::Queued);
    let Next::Transient(live) = queue.next() else {
        anyhow::bail!("unexpired transient");
    };
    let body: Value = serde_json::from_slice(&live.bytes)?;
    assert_eq!(body["n"], 2);
    assert_eq!(occupancy(&queue).0, 1);
    queue.complete_transient(&live);
    assert_eq!(occupancy(&queue), (0, 0));
    assert!(matches!(queue.next(), Next::Idle));
    Ok(())
}

async fn row_silent_expiry_not_on_sink() -> TestResult {
    let (queue, send, frames) = installed().await?;
    assert_eq!(queue.try_push_transient(transient_bytes(1)?, NOW_MS), TransientAdmission::Queued);
    let worker = queue.clone();
    let handle = send.clone();
    tokio::spawn(async move {
        worker.run(handle, "target".into(), Some(ID.into())).await;
    });
    queue.flushed().await?;
    assert!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.is_empty());
    assert_eq!(occupancy(&queue), (0, 0));
    Ok(())
}

async fn row_retire_drops_queued_transients() -> TestResult {
    let (queue, send, frames) = installed().await?;
    assert_eq!(queue.try_push_transient(transient_bytes(1)?, LIVE_MS), TransientAdmission::Queued);
    queue.retire();
    let worker = queue.clone();
    tokio::spawn(async move {
        worker.run(send, "target".into(), Some(ID.into())).await;
    });
    queue.flushed().await?;
    assert!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.is_empty());
    assert_eq!(occupancy(&queue), (0, 0));
    assert_eq!(queue.try_push_transient(transient_bytes(2)?, LIVE_MS), TransientAdmission::Closed);
    Ok(())
}

async fn row_writer_priority_resync_durable_transient() -> TestResult {
    let (queue, send, frames) = installed().await?;
    for seq in 1..=16 {
        assert_eq!(
            queue.try_push_versioned(durable_bytes(seq)?, seq, Some(ID.into())),
            super::Admission::Queued
        );
    }
    assert_eq!(
        queue.try_push_versioned(durable_bytes(17)?, 17, Some(ID.into())),
        super::Admission::Overflowed
    );
    for _ in 0..8 {
        let Next::Frame(frame) = queue.next() else {
            anyhow::bail!("durable drain");
        };
        queue.complete(Some(&frame));
    }
    for n in 1..=3 {
        assert_eq!(
            queue.try_push_transient(transient_bytes(n)?, LIVE_MS),
            TransientAdmission::Queued
        );
    }
    let worker = queue.clone();
    let handle = send.clone();
    tokio::spawn(async move {
        worker.run(handle, "target".into(), Some(ID.into())).await;
    });
    queue.flushed().await?;
    let wire = frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.clone();
    anyhow::ensure!(!wire.is_empty(), "empty sink");
    assert_eq!(wire[0]["frame_type"], "resync");
    let mut saw_deliver = false;
    let mut ephemerals = Vec::new();
    for frame in &wire[1..] {
        match frame["frame_type"].as_str() {
            Some("deliver") => {
                anyhow::ensure!(ephemerals.is_empty(), "durable after transient");
                saw_deliver = true;
            }
            Some("ephemeral") => {
                anyhow::ensure!(saw_deliver, "transient before durable");
                ephemerals.push(frame["n"].as_u64());
            }
            Some("resync") => anyhow::bail!("second resync"),
            other => anyhow::bail!("unexpected {other:?}"),
        }
    }
    assert!(saw_deliver);
    assert_eq!(ephemerals, vec![Some(1), Some(2), Some(3)], "transients in FIFO order");
    assert_eq!(occupancy(&queue), (0, 0));
    Ok(())
}

async fn row_durable_before_transient_without_resync() -> TestResult {
    let (queue, send, frames) = installed().await?;
    assert_eq!(
        queue.try_push_versioned(durable_bytes(1)?, 1, Some(ID.into())),
        super::Admission::Queued
    );
    assert_eq!(queue.try_push_transient(transient_bytes(1)?, LIVE_MS), TransientAdmission::Queued);
    let worker = queue.clone();
    tokio::spawn(async move {
        worker.run(send, "target".into(), Some(ID.into())).await;
    });
    queue.flushed().await?;
    let wire = frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.clone();
    assert_eq!(wire.len(), 2);
    assert_eq!(wire[0]["frame_type"], "deliver");
    assert_eq!(wire[1]["frame_type"], "ephemeral");
    assert_eq!(slot(&queue), EMPTY);
    Ok(())
}

#[tokio::test]
async fn transient_queue_bounds_and_priority() -> TestResult {
    row_frame_cap_inclusive()?;
    row_byte_cap_inclusive();
    row_eight_max_frames_ninth_queue_full();
    row_inflight_counts_toward_frame_cap()?;
    row_inflight_sink_write_still_occupies().await?;
    row_transient_does_not_touch_durable_or_resync()?;
    row_closed_refuses()?;
    row_expired_at_deadline_dropped_unexpired_kept()?;
    row_silent_expiry_not_on_sink().await?;
    row_retire_drops_queued_transients().await?;
    row_writer_priority_resync_durable_transient().await?;
    row_durable_before_transient_without_resync().await?;
    row_inflight_max_write_seven_queued_ninth_queue_full().await?;
    row_expired_while_waiting_for_sink_not_written().await?;
    Ok(())
}
