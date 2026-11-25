// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lock-free PCM bridge between host audio callbacks and the engine workers (C0 bounds).
//!
//! One process-wide slot: the audio reservation already admits one in-process session at a
//! time. Storage is static: 5 capture frames and 10 render frames of atomic samples
//! (28,800 bytes), so the callbacks never allocate. Callbacks use only atomics: no lock, no
//! registry lookup, no logging, no I/O, no waiting. Publish, bind and drain run on the
//! account writer under `CONTROL`, never from a callback.
//!
//! Decision (checkpoint 2): a full render ring drops the newest decoded frame instead of the
//! oldest. A lock-free single-producer, single-consumer ring cannot evict its head without
//! racing the host read; the ring bound (200 ms) keeps latency bounded either way.

use crate::client::call::media_contract::PCM_FRAME_SAMPLES;
use ramflux_media::codec::Frame;
use ramflux_media::{Capture, Playback};
use std::sync::atomic::{AtomicBool, AtomicI16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const FRAME: usize = PCM_FRAME_SAMPLES;
const CAPTURE_FRAMES: usize = 5;
const RENDER_FRAMES: usize = 10;
/// Recent closed tokens remembered per process; older tokens read as unknown.
const RECEIPT_CAP: usize = 128;

/// Callback refusal codes. The numeric values are the C ABI codes (C0 results).
#[cfg(feature = "c-abi")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub(crate) enum PcmError {
    /// Stale generation, foreign token or client, or unknown token.
    InvalidArgument = 1,
    /// Valid session whose SDK authority or OS audio gate is closed.
    PermissionDenied = 12,
    /// Capture ring full: the new frame was dropped.
    RateLimited = 15,
    /// Retired token or client.
    Closed = 26,
}

/// Single-producer, single-consumer ring of whole frames over shared atomic samples. Each
/// frame carries the fence epoch current when it was queued; stale epochs are discarded.
struct Ring<const F: usize> {
    head: AtomicUsize,
    tail: AtomicUsize,
}

/// Sample atomics and per-frame epoch tags of one ring.
#[derive(Clone, Copy)]
struct Storage<'a> {
    samples: &'a [AtomicI16],
    tags: &'a [AtomicU64],
}

impl<const F: usize> Ring<F> {
    const fn new() -> Self {
        Self { head: AtomicUsize::new(0), tail: AtomicUsize::new(0) }
    }

    /// Producer only. Returns `false` when the ring is full or the shape is wrong.
    fn push(&self, storage: Storage<'_>, tag: u64, frame: &[i16]) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail.wrapping_sub(self.head.load(Ordering::Acquire)) >= F || frame.len() != FRAME {
            return false;
        }
        let index = tail % F;
        let base = index * FRAME;
        let Some(window) = storage.samples.get(base..base + FRAME) else { return false };
        let Some(slot_tag) = storage.tags.get(index) else { return false };
        for (slot, sample) in window.iter().zip(frame) {
            slot.store(*sample, Ordering::Relaxed);
        }
        slot_tag.store(tag, Ordering::Relaxed);
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Consumer only. Copies the oldest frame into `out` and returns its epoch tag.
    fn pop(&self, storage: Storage<'_>, out: &mut [i16]) -> Option<u64> {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) || out.len() != FRAME {
            return None;
        }
        let index = head % F;
        let base = index * FRAME;
        let window = storage.samples.get(base..base + FRAME)?;
        let tag = storage.tags.get(index)?.load(Ordering::Relaxed);
        for (sample, slot) in out.iter_mut().zip(window) {
            *sample = slot.load(Ordering::Relaxed);
        }
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(tag)
    }

    /// Empty the ring and zero its storage. Only after both endpoints have stopped.
    fn reset(&self, storage: Storage<'_>) {
        self.head.store(0, Ordering::SeqCst);
        self.tail.store(0, Ordering::SeqCst);
        for sample in storage.samples {
            sample.store(0, Ordering::Relaxed);
        }
        for tag in storage.tags {
            tag.store(0, Ordering::Relaxed);
        }
    }
}

struct Slot {
    published: AtomicBool,
    open: AtomicBool,
    token: AtomicU64,
    client: AtomicU64,
    generation: AtomicU64,
    /// Callbacks currently inside the bridge; drain waits for zero.
    guards: AtomicUsize,
    /// Fence epoch: bumped once per generation change, after in-flight callbacks drain.
    epoch: AtomicU64,
    /// Generation whose epoch fence has completed; activation requires it.
    fenced: AtomicU64,
    captured: AtomicU64,
    capture_drops: AtomicU64,
    render_underruns: AtomicU64,
    render_drops: AtomicU64,
    capture: Ring<CAPTURE_FRAMES>,
    render: Ring<RENDER_FRAMES>,
    capture_samples: [AtomicI16; CAPTURE_FRAMES * FRAME],
    capture_tags: [AtomicU64; CAPTURE_FRAMES],
    render_samples: [AtomicI16; RENDER_FRAMES * FRAME],
    render_tags: [AtomicU64; RENDER_FRAMES],
}

static SLOT: Slot = Slot {
    published: AtomicBool::new(false),
    open: AtomicBool::new(false),
    token: AtomicU64::new(0),
    client: AtomicU64::new(0),
    generation: AtomicU64::new(0),
    epoch: AtomicU64::new(1),
    fenced: AtomicU64::new(0),
    guards: AtomicUsize::new(0),
    captured: AtomicU64::new(0),
    capture_drops: AtomicU64::new(0),
    render_underruns: AtomicU64::new(0),
    render_drops: AtomicU64::new(0),
    capture: Ring::new(),
    render: Ring::new(),
    capture_samples: [const { AtomicI16::new(0) }; CAPTURE_FRAMES * FRAME],
    capture_tags: [const { AtomicU64::new(0) }; CAPTURE_FRAMES],
    render_samples: [const { AtomicI16::new(0) }; RENDER_FRAMES * FRAME],
    render_tags: [const { AtomicU64::new(0) }; RENDER_FRAMES],
};

fn capture_storage() -> Storage<'static> {
    Storage { samples: &SLOT.capture_samples, tags: &SLOT.capture_tags }
}

fn render_storage() -> Storage<'static> {
    Storage { samples: &SLOT.render_samples, tags: &SLOT.render_tags }
}

static RECEIPTS: [AtomicU64; RECEIPT_CAP] = [const { AtomicU64::new(0) }; RECEIPT_CAP];
static RECEIPT_NEXT: AtomicUsize = AtomicUsize::new(0);

/// Serializes publish, bind, retire and drain. Callbacks never take it.
static CONTROL: Mutex<()> = Mutex::new(());

/// Drain deadline for the writer. A deadline is not proof of drain: storage stays live.
pub(crate) const DRAIN_DEADLINE: Duration = Duration::from_secs(5);

/// Proof that one callback is inside the bridge. Dropping it releases the guard.
#[cfg(feature = "c-abi")]
struct Guard;

#[cfg(feature = "c-abi")]
impl Drop for Guard {
    fn drop(&mut self) {
        SLOT.guards.fetch_sub(1, Ordering::SeqCst);
    }
}

fn control() -> std::sync::MutexGuard<'static, ()> {
    CONTROL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Enter the bridge for one callback. Counts the guard before reading the published fields,
/// so a concurrent retire either sees this guard or this call sees the retired state.
#[cfg(feature = "c-abi")]
fn enter(client: u64, token: u64, generation: u64) -> Result<Guard, PcmError> {
    SLOT.guards.fetch_add(1, Ordering::SeqCst);
    let guard = Guard;
    if SLOT.published.load(Ordering::SeqCst)
        && SLOT.token.load(Ordering::SeqCst) == token
        && SLOT.client.load(Ordering::SeqCst) == client
    {
        if SLOT.generation.load(Ordering::SeqCst) != generation {
            return Err(PcmError::InvalidArgument);
        }
        return if SLOT.open.load(Ordering::SeqCst) {
            Ok(guard)
        } else {
            Err(PcmError::PermissionDenied)
        };
    }
    if RECEIPTS.iter().any(|receipt| receipt.load(Ordering::SeqCst) == token) {
        return Err(PcmError::Closed);
    }
    Err(PcmError::InvalidArgument)
}

/// Capture callback body: one 960-sample frame into the capture ring (producer side).
/// Touches: slot atomics, the capture ring and its atomics, capture counters. Nothing else.
#[cfg(feature = "c-abi")]
pub(crate) fn capture_frame(
    client: u64,
    token: u64,
    generation: u64,
    frame: &[i16],
) -> Result<(), PcmError> {
    let _guard = enter(client, token, generation)?;
    let epoch = SLOT.epoch.load(Ordering::SeqCst);
    if SLOT.capture.push(capture_storage(), epoch, frame) {
        SLOT.captured.fetch_add(1, Ordering::Relaxed);
        Ok(())
    } else {
        SLOT.capture_drops.fetch_add(1, Ordering::Relaxed);
        Err(PcmError::RateLimited)
    }
}

/// Render callback body: one 960-sample frame from the render ring (consumer side).
/// Touches: slot atomics, the render ring and its atomics, render counters. On every
/// failure the valid buffer is zeroed; underrun is zero-filled success.
/// Touches: slot atomics, render ring atomics, `out` (the host buffer). Nothing else.
#[cfg(feature = "c-abi")]
pub(crate) fn render_frame(
    client: u64,
    token: u64,
    generation: u64,
    out: &mut [i16],
) -> Result<(), PcmError> {
    let _guard = match enter(client, token, generation) {
        Ok(guard) => guard,
        Err(error) => {
            out.fill(0);
            return Err(error);
        }
    };
    let epoch = SLOT.epoch.load(Ordering::SeqCst);
    // Frames queued before the last generation fence are stale: discard them, bounded.
    for _ in 0..=RENDER_FRAMES {
        match SLOT.render.pop(render_storage(), out) {
            Some(tag) if tag == epoch => return Ok(()),
            Some(_) => continue,
            None => break,
        }
    }
    SLOT.render_underruns.fetch_add(1, Ordering::Relaxed);
    out.fill(0);
    Ok(())
}

/// Make a fresh, closed slot callable for `token`. Refuses while another token is live.
pub(crate) fn publish(token: u64, generation: u64) -> Result<(), crate::SdkError> {
    let _control = control();
    if SLOT.published.load(Ordering::SeqCst) || SLOT.guards.load(Ordering::SeqCst) != 0 {
        return Err(crate::SdkError::LocalBus("voice call: audio bridge busy".into()));
    }
    SLOT.open.store(false, Ordering::SeqCst);
    SLOT.client.store(0, Ordering::SeqCst);
    SLOT.token.store(token, Ordering::SeqCst);
    SLOT.generation.store(generation, Ordering::SeqCst);
    SLOT.capture.reset(capture_storage());
    SLOT.render.reset(render_storage());
    SLOT.fenced.store(generation, Ordering::SeqCst);
    SLOT.published.store(true, Ordering::SeqCst);
    Ok(())
}

/// Bind the C client handle that opened `token`. Returns `false` for any other token.
#[cfg(feature = "c-abi")]
pub(crate) fn bind_client(token: u64, client: u64) -> bool {
    let _control = control();
    if !SLOT.published.load(Ordering::SeqCst) || SLOT.token.load(Ordering::SeqCst) != token {
        return false;
    }
    SLOT.client.store(client, Ordering::SeqCst);
    true
}

/// Open or close the callbacks for `token` from the engine's authority and OS gate.
pub(crate) fn set_open(token: u64, open: bool) {
    let _control = control();
    if SLOT.published.load(Ordering::SeqCst) && SLOT.token.load(Ordering::SeqCst) == token {
        SLOT.open.store(open, Ordering::SeqCst);
    }
}

/// Unpublish first: no new callback passes after this returns. Then remember the token.
pub(crate) fn retire(token: u64) {
    let _control = control();
    if !SLOT.published.load(Ordering::SeqCst) || SLOT.token.load(Ordering::SeqCst) != token {
        return;
    }
    SLOT.published.store(false, Ordering::SeqCst);
    SLOT.open.store(false, Ordering::SeqCst);
    let index = RECEIPT_NEXT.fetch_add(1, Ordering::SeqCst) % RECEIPT_CAP;
    if let Some(receipt) = RECEIPTS.get(index) {
        receipt.store(token, Ordering::SeqCst);
    }
}

/// Wait for in-flight callbacks, then wipe the rings and identity. Call only after the
/// engine that uses the rings has stopped. Returns `false` at the deadline, keeping storage.
pub(crate) fn drain(token: u64, deadline: Duration) -> bool {
    let _control = control();
    if SLOT.token.load(Ordering::SeqCst) != token {
        return true;
    }
    let started = Instant::now();
    while SLOT.guards.load(Ordering::SeqCst) != 0 {
        if started.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    SLOT.capture.reset(capture_storage());
    SLOT.render.reset(render_storage());
    SLOT.client.store(0, Ordering::SeqCst);
    SLOT.generation.store(0, Ordering::SeqCst);
    SLOT.token.store(0, Ordering::SeqCst);
    true
}

/// Engine-side capture: the sender worker takes frames from the capture ring.
pub(crate) struct PcmCapture;

impl Capture for PcmCapture {
    fn next_frame(&mut self, timeout: Duration) -> Option<Frame> {
        let deadline = Instant::now().checked_add(timeout)?;
        let mut frame = [0_i16; FRAME];
        loop {
            if let Some(tag) = SLOT.capture.pop(capture_storage(), &mut frame)
                && tag == SLOT.epoch.load(Ordering::SeqCst)
            {
                return Some(frame);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn discard_pending(&mut self) {
        let mut frame = [0_i16; FRAME];
        while SLOT.capture.pop(capture_storage(), &mut frame).is_some() {}
    }
}

/// Engine-side render: the playout worker feeds decoded frames to the render ring.
pub(crate) struct PcmPlayback;

impl Playback for PcmPlayback {
    fn play(&mut self, frame: &Frame) {
        let epoch = SLOT.epoch.load(Ordering::SeqCst);
        if !SLOT.render.push(render_storage(), epoch, frame) {
            SLOT.render_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Move the slot to `generation` after an I/O generation change. Stores the new generation
/// (callbacks of the old one now refuse), waits for in-flight callbacks, then advances the
/// epoch so frames queued before the change are discarded. Returns `false` at the deadline;
/// activation stays refused until a later call completes the fence.
pub(crate) fn set_generation(token: u64, generation: u64) -> bool {
    let _control = control();
    if SLOT.token.load(Ordering::SeqCst) != token {
        return false;
    }
    SLOT.generation.store(generation, Ordering::SeqCst);
    SLOT.open.store(false, Ordering::SeqCst);
    if SLOT.fenced.load(Ordering::SeqCst) == generation {
        return true;
    }
    let started = Instant::now();
    while SLOT.guards.load(Ordering::SeqCst) != 0 {
        if started.elapsed() >= DRAIN_DEADLINE {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    SLOT.epoch.fetch_add(1, Ordering::SeqCst);
    SLOT.fenced.store(generation, Ordering::SeqCst);
    true
}

/// Whether the epoch fence of `generation` has completed for `token`.
pub(crate) fn fenced(token: u64, generation: u64) -> bool {
    SLOT.token.load(Ordering::SeqCst) == token && SLOT.fenced.load(Ordering::SeqCst) == generation
}

/// Public counters for the status row: `(captured, capture_drops, render_underruns)`.
pub(crate) fn counters() -> (u64, u64, u64) {
    (
        SLOT.captured.load(Ordering::Relaxed),
        SLOT.capture_drops.load(Ordering::Relaxed),
        SLOT.render_underruns.load(Ordering::Relaxed),
    )
}
