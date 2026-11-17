// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Two separate process-wide resources. Memory is the 64 MiB the streaming workers may hold
//! in buffers; it is charged before an allocation and released by a guard, so a panic or an
//! early return cannot leak or underflow it. Disk is the plaintext snapshot, the ciphertext,
//! the thumbnail workspace and the safety margin; it is reserved against the free space of
//! the data directory before any copy starts, and is rebuilt from the durable rows after a
//! restart. A charge that does not fit is `disk_full` and copies nothing.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use super::codes::{CODE_DISK_FULL, Refusal};

/// Bytes the streaming workers may hold in buffers at once.
pub(crate) const MEMORY_CAP: u64 = 64 * 1024 * 1024;
/// Thumbnail workspace and the safety margin of one prepare.
const THUMBNAIL_WORKSPACE: u64 = 16 * 1024;
const SAFETY_MARGIN: u64 = 1024 * 1024;
const SEGMENT: u64 = 524_288;

static MEMORY: AtomicU64 = AtomicU64::new(0);
static DISK: AtomicU64 = AtomicU64::new(0);
/// Free-space overrides, scoped to one directory so parallel tests never see each other's.
#[cfg(test)]
static FREE_OVERRIDE: std::sync::Mutex<Vec<(std::path::PathBuf, u64)>> =
    std::sync::Mutex::new(Vec::new());

/// Per-job record of the buffer bytes held and the most ever held at once, so a test can
/// prove the working set does not grow with the file.
#[derive(Debug, Default)]
pub(crate) struct Meter {
    held: AtomicU64,
    peak: AtomicU64,
}

impl Meter {
    /// Largest buffer total this job held at one time.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn peak(&self) -> u64 {
        self.peak.load(Ordering::Acquire)
    }
}

/// Buffer bytes held by one worker step. Dropping the permit releases exactly what it took.
#[derive(Debug)]
pub(crate) struct MemoryPermit<'a> {
    bytes: u64,
    meter: Option<&'a Meter>,
}

impl Drop for MemoryPermit<'_> {
    fn drop(&mut self) {
        sub(&MEMORY, self.bytes);
        if let Some(meter) = self.meter {
            sub(&meter.held, self.bytes);
        }
    }
}

/// Charges `bytes` of buffer memory before the allocation.
/// # Errors
/// Returns `disk_full` (the scheduler's backpressure code) when the 64 MiB budget is held.
pub(crate) fn memory(bytes: u64) -> Result<MemoryPermit<'static>, Refusal> {
    add(&MEMORY, bytes, MEMORY_CAP)?;
    Ok(MemoryPermit { bytes, meter: None })
}

/// As [`memory`], and records the hold on `meter`.
/// # Errors
/// Returns `disk_full` when the 64 MiB budget is held.
pub(crate) fn memory_metered(bytes: u64, meter: &Meter) -> Result<MemoryPermit<'_>, Refusal> {
    add(&MEMORY, bytes, MEMORY_CAP)?;
    let now = meter.held.fetch_add(bytes, Ordering::AcqRel).saturating_add(bytes);
    meter.peak.fetch_max(now, Ordering::AcqRel);
    Ok(MemoryPermit { bytes, meter: Some(meter) })
}

/// Reserves `bytes` of disk for one prepare or import against the free space under `root`.
/// # Errors
/// Returns `disk_full` when the free space minus the reservations already held cannot hold it.
pub(crate) fn reserve_disk(root: &Path, bytes: u64) -> Result<(), Refusal> {
    if bytes == 0 {
        return Ok(());
    }
    let free = free_bytes(root);
    add(&DISK, bytes, free)
}

/// Returns a reservation. Releasing more than is held floors at zero instead of wrapping.
pub(crate) fn release_disk(bytes: u64) {
    sub(&DISK, bytes);
}

/// Adds the reservations of the durable rows after a restart. Called once per account root
/// and process; no cap check, because those bytes are already on disk.
pub(crate) fn adopt_disk(bytes: u64) {
    DISK.fetch_add(bytes, Ordering::AcqRel);
}

fn add(counter: &AtomicU64, bytes: u64, cap: u64) -> Result<(), Refusal> {
    loop {
        let current = counter.load(Ordering::Acquire);
        let next = current.checked_add(bytes).ok_or(Refusal::new(CODE_DISK_FULL))?;
        if next > cap {
            return Err(Refusal::new(CODE_DISK_FULL));
        }
        if counter.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return Ok(());
        }
    }
}

fn sub(counter: &AtomicU64, bytes: u64) {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.saturating_sub(bytes);
        match counter.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(seen) => current = seen,
        }
    }
}

/// Disk one prepare needs once its plaintext length is known: the snapshot, the ciphertext
/// (plaintext plus one 16-byte tag per 512 KiB network chunk), the thumbnail workspace and
/// the margin.
/// # Errors
/// Returns `disk_full` when the size overflows.
pub(crate) fn prepare_bytes(plaintext: u64) -> Result<u64, Refusal> {
    let chunks = plaintext.div_ceil(SEGMENT).max(1);
    let cipher =
        plaintext.checked_add(chunks.saturating_mul(16)).ok_or(Refusal::new(CODE_DISK_FULL))?;
    plaintext
        .checked_add(cipher)
        .and_then(|sum| sum.checked_add(THUMBNAIL_WORKSPACE + SAFETY_MARGIN))
        .ok_or(Refusal::new(CODE_DISK_FULL))
}

/// Disk one import needs: the staged plaintext and the margin.
/// # Errors
/// Returns `disk_full` when the size overflows.
pub(crate) fn import_bytes(plaintext: u64) -> Result<u64, Refusal> {
    plaintext.checked_add(SAFETY_MARGIN).ok_or(Refusal::new(CODE_DISK_FULL))
}

#[cfg(test)]
fn forced_free(root: &Path) -> Option<u64> {
    let rows = FREE_OVERRIDE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    rows.iter().find(|(scope, _)| root.starts_with(scope)).map(|(_, bytes)| *bytes)
}

#[cfg(unix)]
fn free_bytes(root: &Path) -> u64 {
    #[cfg(test)]
    if let Some(forced) = forced_free(root) {
        return forced;
    }
    let target = nearest_existing(root);
    match rustix::fs::statvfs(target) {
        Ok(stat) => stat.f_bavail.saturating_mul(stat.f_frsize),
        Err(_) => 0,
    }
}

#[cfg(not(unix))]
fn free_bytes(root: &Path) -> u64 {
    #[cfg(test)]
    if let Some(forced) = forced_free(root) {
        return forced;
    }
    let _ = root;
    u64::MAX
}

#[cfg(unix)]
fn nearest_existing(path: &Path) -> &Path {
    let mut current = path;
    while !current.exists() {
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }
    current
}

#[cfg(test)]
pub(crate) fn disk_reserved() -> u64 {
    DISK.load(Ordering::Acquire)
}

/// Forces the free space every reservation under `scope` sees.
#[cfg(test)]
pub(crate) fn force_free_bytes(scope: &Path, value: u64) {
    let mut rows = FREE_OVERRIDE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    rows.retain(|(path, _)| path != scope);
    rows.push((scope.to_path_buf(), value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_charge_over_the_cap_is_disk_full_and_leaves_the_counter() {
        let counter = AtomicU64::new(0);
        assert!(add(&counter, 60, 100).is_ok(), "the first charge fits");
        assert_eq!(add(&counter, 41, 100), Err(Refusal::new(CODE_DISK_FULL)));
        assert_eq!(counter.load(Ordering::Acquire), 60, "a refused charge changes nothing");
        assert_eq!(add(&counter, u64::MAX, 100), Err(Refusal::new(CODE_DISK_FULL)), "overflow");
    }

    #[test]
    fn releasing_more_than_held_floors_at_zero() {
        let counter = AtomicU64::new(10);
        sub(&counter, 25);
        assert_eq!(counter.load(Ordering::Acquire), 0, "a double release cannot underflow");
    }

    #[test]
    fn a_dropped_permit_returns_its_bytes() -> Result<(), Refusal> {
        let meter = Meter::default();
        let permit = memory_metered(1024, &meter)?;
        assert_eq!(meter.held.load(Ordering::Acquire), 1024, "the permit is counted");
        drop(permit);
        assert_eq!(meter.held.load(Ordering::Acquire), 0, "dropping returns exactly what it took");
        assert_eq!(meter.peak(), 1024);
        Ok(())
    }

    #[test]
    fn prepare_bytes_cover_snapshot_ciphertext_thumbnail_and_margin() -> Result<(), Refusal> {
        let need = prepare_bytes(1_000_000)?;
        assert!(need > 2_000_000, "plaintext and ciphertext are both charged: {need}");
        assert_eq!(prepare_bytes(u64::MAX), Err(Refusal::new(CODE_DISK_FULL)));
        Ok(())
    }

    #[test]
    fn reserving_more_than_the_scoped_free_space_is_disk_full() -> Result<(), Refusal> {
        let scope = std::env::temp_dir().join("rf-attach-budget-scope");
        force_free_bytes(&scope, 10_000);
        let before = disk_reserved();
        assert_eq!(reserve_disk(&scope, 20_000), Err(Refusal::new(CODE_DISK_FULL)));
        assert_eq!(disk_reserved(), before, "a refused reservation holds nothing");
        Ok(())
    }
}
