// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
#[test]
fn queue_half_drain_and_inflight() {
    for limit in [16, 256] {
        let (closed, _) = tokio::sync::watch::channel(false);
        let queue = PushQueue::new(limit, closed);
        for seq in 1..=limit {
            let before = queue.inner.accesses.load(Ordering::Relaxed);
            assert_eq!(queue.try_push(vec![0; 32], seq as u64), Admission::Queued);
            assert!(queue.inner.accesses.load(Ordering::Relaxed) - before <= 4);
        }
        let Next::Frame(inflight) = queue.next() else { unreachable!() };
        assert_eq!(queue.try_push(vec![0; 32], 300), Admission::Overflowed);
        let state = queue.inner.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = queue.inner.accesses.load(Ordering::Relaxed);
        assert_eq!(state.occupancy(), (limit, limit * 32));
        assert!(queue.inner.accesses.load(Ordering::Relaxed) - before <= 4);
        assert_eq!(state.frames, limit);
        assert_eq!(state.bytes, limit * 32);
        drop(state);
        queue.complete(Some(&inflight));
        for _ in 1..limit / 2 {
            let Next::Frame(frame) = queue.next() else { unreachable!() };
            queue.complete(Some(&frame));
        }
        assert!(matches!(queue.next(), Next::Hint(299)));
        assert_eq!(queue.try_push(vec![1], 200), Admission::Overflowed);
        queue.complete(None);
        assert!(matches!(queue.next(), Next::Hint(199)));
        queue.complete(None);
    }
}
#[test]
fn resync_threshold() {
    let (closed, _) = tokio::sync::watch::channel(false);
    let queue = PushQueue::new(16, closed);
    for seq in 1..=4 {
        assert_eq!(queue.try_push(vec![0; 1024 * 1024], seq), Admission::Queued);
    }
    assert_eq!(queue.try_push(vec![0], 20), Admission::Overflowed);
    let Next::Frame(frame) = queue.next() else { unreachable!() };
    queue.complete(Some(&frame));
    // Three frames are below the frame threshold but above the byte threshold.
    let Next::Frame(frame) = queue.next() else { unreachable!() };
    queue.complete(Some(&frame));
    assert!(matches!(queue.next(), Next::Hint(19)));
    assert_eq!(queue.try_push(vec![0], 19), Admission::Overflowed);
    queue.complete(None);
    assert!(matches!(queue.next(), Next::Hint(18)));
}

#[cfg(feature = "itest-local-mint")]
mod callers;

mod wire;

#[test]
fn contended_admission_waits_and_queues() -> anyhow::Result<()> {
    let (closed, _) = tokio::sync::watch::channel(false);
    let queue = PushQueue::new(16, closed);
    let guard = queue.inner.state.lock().map_err(|_| anyhow::anyhow!("admission poisoned"))?;
    let (started, ready) = std::sync::mpsc::channel();
    let (result, received) = std::sync::mpsc::channel();
    let producer = queue.clone();
    let worker = std::thread::spawn(move || {
        let _ = started.send(());
        let _ = result.send(producer.try_push(vec![0], 1));
    });
    ready.recv_timeout(Duration::from_secs(2))?;
    let premature = received.recv_timeout(Duration::from_millis(50));
    drop(guard);
    let admitted = match premature {
        Ok(value) => value,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            received.recv_timeout(Duration::from_secs(2))?
        }
        Err(e) => return Err(e.into()),
    };
    worker.join().map_err(|_| anyhow::anyhow!("admission worker panicked"))?;
    assert_eq!(admitted, Admission::Queued);
    assert!(matches!(queue.next(), Next::Frame(_)));
    assert_eq!(queue.inner.slot.load(Ordering::Acquire), EMPTY);
    Ok(())
}
#[test]
fn frame_limit_clamps_outside_both_boundaries() {
    for (input, expected) in [
        (0, 16),
        (1, 16),
        (15, 16),
        (16, 16),
        (256, 256),
        (257, 256),
        (1000, 256),
        (usize::MAX, 256),
    ] {
        let (closed, _) = tokio::sync::watch::channel(false);
        let q = PushQueue::new(input, closed);
        assert_eq!(q.inner.limit, expected);
    }
}
#[tokio::test]
async fn oversized_legacy_frame_is_unhandled_without_retiring_registration() -> anyhow::Result<()> {
    let hub = Arc::new(crate::GatewaySessionHub::default());
    let (send, frames) = crate::session_push::tests::support::sink();
    hub.register("target".into(), "session".into(), send).await?;
    let mut envelope = crate::session::tests::test_envelope();
    envelope.target_delivery_id = "target".into();
    envelope.ext.ext.insert("oversized".into(), serde_json::json!("x".repeat(BYTE_CAP)));
    let frame = ramflux_node_core::GatewayServerFrame::Deliver {
        entry: ramflux_node_core::InboxEntry {
            target_delivery_id: "target".into(),
            inbox_seq: 1,
            envelope,
        },
    };
    assert!(!hub.send_to("target", &frame).await);
    hub.flushed("target").await?;
    assert!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.is_empty());
    assert!(
        hub.send_to("target", &ramflux_node_core::GatewayServerFrame::Heartbeat { now: 7 }).await
    );
    hub.flushed("target").await?;
    assert_eq!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.len(), 1);
    Ok(())
}
