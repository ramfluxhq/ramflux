// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Suspend-aware monotonic time. Wall time never participates in app-lock authority.

use crate::SdkError;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

// Platform implementations share one fallible, suspend-aware sampling contract.
trait MonotonicClock {
    fn now() -> Result<Duration, SdkError>;
}
struct SystemClock;

#[derive(Clone)]
pub(crate) struct Deadline {
    started: Duration,
    until: Duration,
    expired: Arc<AtomicBool>,
}

impl Deadline {
    pub(crate) fn new(timeout_ms: u64) -> Result<Self, SdkError> {
        Self::from_start(SystemClock::now()?, timeout_ms)
    }

    fn from_start(started: Duration, timeout_ms: u64) -> Result<Self, SdkError> {
        let until =
            started.checked_add(Duration::from_millis(timeout_ms)).ok_or_else(unavailable)?;
        Ok(Self { started, until, expired: Arc::new(AtomicBool::new(false)) })
    }

    pub(crate) fn reconfigure(&self, timeout_ms: u64) -> Result<Self, SdkError> {
        Self::from_start(self.started, timeout_ms)
    }

    pub(crate) fn remaining(&self) -> Duration {
        if self.expired.load(Ordering::Acquire) {
            return Duration::ZERO;
        }
        // Clock failure or a backwards sample is uncertainty: fail closed.
        let remaining = match SystemClock::now() {
            Ok(now) if now >= self.started => self.until.saturating_sub(now),
            _ => Duration::ZERO,
        };
        if remaining.is_zero() {
            self.expired.store(true, Ordering::Release);
        }
        remaining
    }

    pub(crate) fn remaining_ms(&self) -> u64 {
        u64::try_from(self.remaining().as_nanos().div_ceil(1_000_000)).unwrap_or(0)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl MonotonicClock for SystemClock {
    fn now() -> Result<Duration, SdkError> {
        let time = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Boottime)
            .map_err(|_| unavailable())?;
        let seconds = u64::try_from(time.tv_sec).map_err(|_| unavailable())?;
        let nanos = u32::try_from(time.tv_nsec).map_err(|_| unavailable())?;
        if nanos >= 1_000_000_000 {
            return Err(unavailable());
        }
        Ok(Duration::new(seconds, nanos))
    }
}

#[cfg(target_vendor = "apple")]
impl MonotonicClock for SystemClock {
    fn now() -> Result<Duration, SdkError> {
        #[repr(C)]
        struct Timebase {
            numerator: u32,
            denominator: u32,
        }
        unsafe extern "C" {
            fn mach_continuous_time() -> u64;
            fn mach_timebase_info(info: *mut Timebase) -> i32;
        }
        let mut scale = Timebase { numerator: 0, denominator: 0 };
        // SAFETY: the OS writes the initialized, correctly laid out timebase structure.
        if unsafe { mach_timebase_info(&raw mut scale) } != 0
            || scale.denominator == 0
            || scale.numerator == 0
        {
            return Err(unavailable());
        }
        // SAFETY: this process-local OS clock takes no pointers and includes system sleep.
        let ticks = unsafe { mach_continuous_time() };
        let nanos = u128::from(ticks) * u128::from(scale.numerator) / u128::from(scale.denominator);
        Ok(Duration::new(
            u64::try_from(nanos / 1_000_000_000).map_err(|_| unavailable())?,
            u32::try_from(nanos % 1_000_000_000).map_err(|_| unavailable())?,
        ))
    }
}

#[cfg(windows)]
impl MonotonicClock for SystemClock {
    fn now() -> Result<Duration, SdkError> {
        // SAFETY: the OS clock takes no pointers and includes sleep and hibernation.
        let millis = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
        Ok(Duration::from_millis(millis))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
impl MonotonicClock for SystemClock {
    fn now() -> Result<Duration, SdkError> {
        Err(unavailable())
    }
}

fn unavailable() -> SdkError {
    crate::bus::app_lock_fence::locked()
}
