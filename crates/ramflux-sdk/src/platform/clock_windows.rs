// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The Windows tick-count call of the app-lock clock. It counts through system sleep and
//! hibernation, which `std::time::Instant` may not. Only this private FFI boundary permits
//! unsafe.
#![allow(unsafe_code)]

use windows_sys::Win32::System::SystemInformation::GetTickCount64;

/// Milliseconds since boot, including time spent asleep. The OS call takes no pointers.
pub(super) fn tick_count_ms() -> u64 {
    // SAFETY: GetTickCount64 has no arguments and no preconditions; it only reads the OS clock.
    unsafe { GetTickCount64() }
}
