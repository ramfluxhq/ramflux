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
