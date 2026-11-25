// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The Apple continuous-time calls of the app-lock clock. The continuous clock counts through
//! system sleep, which `std::time::Instant` may not. Only this private FFI boundary permits unsafe.
#![allow(unsafe_code)]

use std::time::Duration;

#[repr(C)]
struct Timebase {
    numerator: u32,
    denominator: u32,
}

unsafe extern "C" {
    fn mach_continuous_time() -> u64;
    fn mach_timebase_info(info: *mut Timebase) -> i32;
}

/// Time since boot, including time spent asleep. `None` when the OS refuses the timebase, the
/// timebase is zero, or the value does not fit a `Duration`.
pub(super) fn continuous_time() -> Option<Duration> {
    let mut scale = Timebase { numerator: 0, denominator: 0 };
    // SAFETY: the pointer refers to a live, initialized, correctly laid out `Timebase` that outlives
    // the call; the OS only writes into it.
    let status = unsafe { mach_timebase_info(&raw mut scale) };
    if status != 0 || scale.numerator == 0 || scale.denominator == 0 {
        return None;
    }
    // SAFETY: `mach_continuous_time` takes no arguments and only reads the kernel clock.
    let ticks = unsafe { mach_continuous_time() };
    let nanos = u128::from(ticks) * u128::from(scale.numerator) / u128::from(scale.denominator);
    Some(Duration::new(
        u64::try_from(nanos / 1_000_000_000).ok()?,
        u32::try_from(nanos % 1_000_000_000).ok()?,
    ))
}
