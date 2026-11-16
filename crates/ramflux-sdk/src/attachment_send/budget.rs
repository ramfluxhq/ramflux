// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-wide 64 MiB staging budget. A charge that does not fit is `disk_full`
//! and copies nothing.

use super::codes::{CODE_DISK_FULL, Refusal};
use std::sync::atomic::{AtomicU64, Ordering};

const DEFAULT_CAP: u64 = 64 * 1024 * 1024;
static CHARGED: AtomicU64 = AtomicU64::new(0);
static CAP: AtomicU64 = AtomicU64::new(DEFAULT_CAP);

/// Reserve `bytes` before any plaintext or ciphertext copy.
/// # Errors
/// Returns `disk_full` when the process budget cannot hold `bytes`.
pub(crate) fn charge(bytes: u64) -> Result<(), Refusal> {
    if bytes == 0 {
        return Ok(());
    }
    let cap = CAP.load(Ordering::Relaxed);
    loop {
        let current = CHARGED.load(Ordering::Relaxed);
        let next = current.checked_add(bytes).ok_or(Refusal::new(CODE_DISK_FULL))?;
        if next > cap {
            return Err(Refusal::new(CODE_DISK_FULL));
        }
        if CHARGED.compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            return Ok(());
        }
    }
}

pub(crate) fn release(bytes: u64) {
    if bytes == 0 {
        return;
    }
    CHARGED.fetch_sub(bytes, Ordering::AcqRel);
}

#[cfg(test)]
pub(crate) fn charged() -> u64 {
    CHARGED.load(Ordering::Relaxed)
}

pub(crate) fn staging_bytes(plaintext: u64) -> Result<u64, Refusal> {
    let segments = plaintext.div_ceil(524_288).max(1);
    let cipher =
        plaintext.checked_add(segments.saturating_mul(16)).ok_or(Refusal::new(CODE_DISK_FULL))?;
    cipher.checked_add(16 * 1024 + 1024 * 1024).ok_or(Refusal::new(CODE_DISK_FULL))
}

/// Bytes to charge when the accepted log grows from `before` to `after`.
/// # Errors
/// Returns `disk_full` when either side overflows the staging formula.
pub(crate) fn growth(before: u64, after: u64) -> Result<u64, Refusal> {
    let next = staging_bytes(after)?;
    let prev = if before == 0 { 0 } else { staging_bytes(before)? };
    Ok(next.saturating_sub(prev))
}
