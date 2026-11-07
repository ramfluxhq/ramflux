// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Measured heap of the D3 replay set at the 65,536-entry cap.
//!
//! A counting global allocator is required to observe HashMap/BTreeSet layout;
//! the workspace denies `unsafe_code` except this dedicated test binary.

#![allow(unsafe_code)]

use ramflux_node_core::{
    EPHEMERAL_REPLAY_BOUND, EPHEMERAL_REPLAY_BUDGET_BYTES, EphemeralReplayAdmit, RouterCore,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct CountingAlloc {
    live: AtomicUsize,
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc { live: AtomicUsize::new(0) };

// SAFETY: every allocation is forwarded to `System`; `live` tracks the outstanding size.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is the caller-supplied allocation layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            self.live.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.live.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `ptr` was produced by `alloc` with this `layout`.
        unsafe { System.dealloc(ptr, layout) };
    }
}

fn live_bytes() -> usize {
    ALLOC.live.load(Ordering::Relaxed)
}

fn digest(n: u32) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[28..].copy_from_slice(&n.to_be_bytes());
    out
}

#[test]
fn ephemeral_replay_heap_budget() -> TestResult {
    const NOW_MS: u64 = 1_000_000;
    const BASE_DEADLINE: u64 = 2_000;
    assert_eq!(EPHEMERAL_REPLAY_BUDGET_BYTES, 8_388_608);
    let router = RouterCore::new();
    let before = live_bytes();
    for n in 0..EPHEMERAL_REPLAY_BOUND {
        let n = u32::try_from(n)?;
        let deadline = BASE_DEADLINE.saturating_add(u64::from(n));
        assert_eq!(
            router.admit_ephemeral_replay(digest(n), deadline, NOW_MS),
            EphemeralReplayAdmit::Fresh
        );
    }
    let allocated = live_bytes().saturating_sub(before);
    assert!(
        allocated <= EPHEMERAL_REPLAY_BUDGET_BYTES,
        "replay-set heap {allocated} exceeds {EPHEMERAL_REPLAY_BUDGET_BYTES}"
    );
    let overflow = u32::try_from(EPHEMERAL_REPLAY_BOUND)?;
    assert_eq!(
        router.admit_ephemeral_replay(
            digest(overflow),
            BASE_DEADLINE.saturating_add(u64::from(overflow)),
            NOW_MS
        ),
        EphemeralReplayAdmit::RateLimited
    );
    assert_eq!(
        router.admit_ephemeral_replay(digest(0), BASE_DEADLINE, NOW_MS),
        EphemeralReplayAdmit::Replayed
    );
    Ok(())
}
