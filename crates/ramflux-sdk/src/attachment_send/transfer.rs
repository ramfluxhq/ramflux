// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-process control of a running upload: the pause gate checked before each slice, and the
//! unique byte count that `attachment.transfer.list` reports. The durable record stays the
//! ACK journal; nothing here is persisted, and a process restart simply finds no running entry.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use super::codes::{CODE_CANCELLED, CODE_NOT_READY, CODE_UPLOAD_REJECTED, Refusal};

/// `(account id, prepare id)`: a prepare id is only meaningful inside its account.
type Key = (String, String);

/// How often a paused worker re-checks its flag. Bounded so a cancelled entry is noticed.
const PAUSE_POLL: Duration = Duration::from_millis(250);

#[derive(Default)]
struct Control {
    paused: bool,
    total_bytes: u64,
    unique_bytes: u64,
}

/// One row per upload that is running in this process.
struct Registry {
    running: Mutex<BTreeMap<Key, Control>>,
    changed: Condvar,
}

static REGISTRY: Registry =
    Registry { running: Mutex::new(BTreeMap::new()), changed: Condvar::new() };

/// Holds one running entry; dropping it removes the entry and wakes any paused worker.
pub(crate) struct Live(Key);

impl Drop for Live {
    fn drop(&mut self) {
        if let Ok(mut running) = REGISTRY.running.lock() {
            running.remove(&self.0);
        }
        REGISTRY.changed.notify_all();
    }
}

/// A snapshot of one running upload, for `attachment.transfer.list`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub prepare_id: String,
    pub paused: bool,
    pub total_bytes: u64,
    pub unique_bytes: u64,
}

fn lock() -> Result<std::sync::MutexGuard<'static, BTreeMap<Key, Control>>, Refusal> {
    REGISTRY.running.lock().map_err(|_| Refusal::new(CODE_CANCELLED))
}

fn key(account: &str, prepare_id: &str) -> Key {
    (account.to_owned(), prepare_id.to_owned())
}

/// Registers the upload of one prepare. A second upload of the same prepare in this process is
/// refused, so two workers never race on one set of ACKs.
/// # Errors
/// Returns `upload_rejected` when the prepare already has a running upload here.
pub(crate) fn enter(account: &str, prepare_id: &str, total_bytes: u64) -> Result<Live, Refusal> {
    let mut running = lock()?;
    let id = key(account, prepare_id);
    if running.contains_key(&id) {
        return Err(Refusal::new(CODE_UPLOAD_REJECTED));
    }
    running.insert(id.clone(), Control { paused: false, total_bytes, unique_bytes: 0 });
    Ok(Live(id))
}

/// Blocks while the upload is paused. Returns `cancelled` when the entry has gone away.
/// # Errors
/// Returns `cancelled` when the upload is no longer registered.
pub(crate) fn gate(account: &str, prepare_id: &str) -> Result<(), Refusal> {
    let id = key(account, prepare_id);
    let mut running = lock()?;
    loop {
        match running.get(&id) {
            None => return Err(Refusal::new(CODE_CANCELLED)),
            Some(control) if !control.paused => return Ok(()),
            Some(_) => {}
        }
        let (guard, _) = REGISTRY
            .changed
            .wait_timeout(running, PAUSE_POLL)
            .map_err(|_| Refusal::new(CODE_CANCELLED))?;
        running = guard;
    }
}

/// Adds confirmed bytes to the unique count. The caller credits a slice once, when its ACK is
/// first set in this run; a replayed ACK is never credited twice.
pub(crate) fn credit(account: &str, prepare_id: &str, bytes: u64) {
    if let Ok(mut running) = REGISTRY.running.lock()
        && let Some(control) = running.get_mut(&key(account, prepare_id))
    {
        control.unique_bytes = control.unique_bytes.saturating_add(bytes);
    }
}

/// Pauses or resumes a running upload. The worker stops before its next slice.
/// # Errors
/// Returns `not_ready` when no upload of this prepare is running in this process.
pub(crate) fn set_paused(account: &str, prepare_id: &str, paused: bool) -> Result<(), Refusal> {
    let mut running = lock()?;
    let control =
        running.get_mut(&key(account, prepare_id)).ok_or_else(|| Refusal::new(CODE_NOT_READY))?;
    control.paused = paused;
    REGISTRY.changed.notify_all();
    Ok(())
}

/// Every running upload of one account, ordered by prepare id.
pub(crate) fn snapshot(account: &str) -> Vec<Snapshot> {
    let Ok(running) = REGISTRY.running.lock() else { return Vec::new() };
    running
        .iter()
        .filter(|((owner, _), _)| owner == account)
        .map(|((_, prepare_id), control)| Snapshot {
            prepare_id: prepare_id.clone(),
            paused: control.paused,
            total_bytes: control.total_bytes,
            unique_bytes: control.unique_bytes,
        })
        .collect()
}

/// Name of the durable progress record kept beside each prepare's segments.
pub(crate) const PROGRESS_FILE: &str = "progress.json";
/// Bounds the scan of one account's prepares and the size of each record read.
const PROGRESS_SCAN_CAP: usize = 256;
const PROGRESS_BYTES_CAP: u64 = 4096;

/// The non-secret counts written at each ACK checkpoint. Keys and paths never appear here.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ProgressRecord {
    pub prepare_id: String,
    pub total_bytes: u64,
    pub unique_bytes: u64,
}

/// Uploads that were in progress when this process last wrote their record. Read-only and
/// bounded; a record whose name does not match its directory is ignored.
pub(crate) fn durable(prepares_root: &std::path::Path) -> Vec<Snapshot> {
    let Ok(entries) = std::fs::read_dir(prepares_root) else { return Vec::new() };
    let mut rows = Vec::new();
    for entry in entries.take(PROGRESS_SCAN_CAP).flatten() {
        let dir = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
        let Ok(file) = std::fs::File::open(dir.join(PROGRESS_FILE)) else { continue };
        let mut bytes = Vec::new();
        if std::io::Read::take(file, PROGRESS_BYTES_CAP + 1).read_to_end(&mut bytes).is_err()
            || u64::try_from(bytes.len()).is_ok_and(|len| len > PROGRESS_BYTES_CAP)
        {
            continue;
        }
        let Ok(record) = serde_json::from_slice::<ProgressRecord>(&bytes) else { continue };
        if record.prepare_id != name {
            continue;
        }
        rows.push(Snapshot {
            prepare_id: record.prepare_id,
            paused: false,
            total_bytes: record.total_bytes,
            unique_bytes: record.unique_bytes,
        });
    }
    rows.sort_by(|left, right| left.prepare_id.cmp(&right.prepare_id));
    rows
}

/// Running uploads first; a durable record of a prepare that is not running here is listed too.
pub(crate) fn listed(account: &str, prepares_root: &std::path::Path) -> Vec<Snapshot> {
    let mut rows = snapshot(account);
    for row in durable(prepares_root) {
        if !rows.iter().any(|running| running.prepare_id == row.prepare_id) {
            rows.push(row);
        }
    }
    rows.sort_by(|left, right| left.prepare_id.cmp(&right.prepare_id));
    rows
}
