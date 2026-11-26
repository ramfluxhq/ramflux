// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `sync.stats` hand-off between notify (which counts) and federation (the centre session).
//!
//! Both processes share the push state directory; no socket carries these counters. Notify
//! writes `policy-stats.json` with the newest completed, unacknowledged hour. Federation adds
//! it to the next `sync` and, after an `ok` reply, writes `policy-stats-ack.json` holding that
//! hour's `from_ms`. Notify takes the ack, marks the hour acknowledged, and publishes the next
//! pending hour. Resend is allowed: the centre replaces an hour's counters.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::NodeCoreError;
use crate::notify::PolicyStatsHour;

/// File notify writes beside the push state file.
pub const POLICY_STATS_FILE: &str = "policy-stats.json";
/// File federation writes after an `ok` reply that carried the stats.
pub const POLICY_STATS_ACK_FILE: &str = "policy-stats-ack.json";

/// The `stats` member of `sync`: exactly these six closed members (A7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStats {
    pub from: u64,
    pub to: u64,
    pub held_sent: u64,
    pub held_dropped: u64,
    pub muted: u64,
    pub clears_conn: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AckFile {
    from_ms: u64,
}

impl From<&PolicyStatsHour> for SyncStats {
    fn from(hour: &PolicyStatsHour) -> Self {
        Self {
            from: hour.from_ms,
            to: hour.to_ms,
            held_sent: hour.held_sent,
            held_dropped: hour.held_dropped,
            muted: hour.muted,
            clears_conn: hour.clears_conn,
        }
    }
}

/// Path of the stats file for a push state file.
#[must_use]
pub fn stats_path(state_file: &Path) -> PathBuf {
    state_file.with_file_name(POLICY_STATS_FILE)
}

/// Path of the ack file for a push state file.
#[must_use]
pub fn ack_path(state_file: &Path) -> PathBuf {
    state_file.with_file_name(POLICY_STATS_ACK_FILE)
}

fn io_error(context: &str, error: &dyn std::fmt::Display) -> NodeCoreError {
    NodeCoreError::InvalidConfiguration(format!("{context}: {error}"))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), NodeCoreError> {
    let tmp = path.with_extension("tmp");
    let result = (|| -> std::io::Result<()> {
        let mut file =
            std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    result.map_err(|error| io_error("policy stats file", &error))
}

/// Writes the pending stats hour (notify side). `None` removes the file.
///
/// # Errors
/// Returns an error when the file cannot be written or removed.
pub fn write_pending_stats(
    state_file: &Path,
    hour: Option<&PolicyStatsHour>,
) -> Result<(), NodeCoreError> {
    let path = stats_path(state_file);
    match hour {
        Some(hour) => {
            let bytes = serde_json::to_vec(&SyncStats::from(hour))
                .map_err(|error| io_error("encode policy stats", &std::io::Error::other(error)))?;
            write_atomic(&path, &bytes)
        }
        None => match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error("remove policy stats file", &error)),
        },
    }
}

/// Reads the pending stats hour (federation side). A missing file is `None`.
///
/// # Errors
/// Returns an error when the file exists but is not a valid stats object.
pub fn read_pending_stats(state_file: &Path) -> Result<Option<SyncStats>, NodeCoreError> {
    match std::fs::read(stats_path(state_file)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| io_error("decode policy stats", &std::io::Error::other(error))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error("read policy stats file", &error)),
    }
}

/// Records that the centre acknowledged the hour starting at `from_ms` (federation side).
///
/// # Errors
/// Returns an error when the ack file cannot be written.
pub fn write_stats_ack(state_file: &Path, from_ms: u64) -> Result<(), NodeCoreError> {
    let bytes = serde_json::to_vec(&AckFile { from_ms })
        .map_err(|error| io_error("encode policy ack", &std::io::Error::other(error)))?;
    write_atomic(&ack_path(state_file), &bytes)
}

/// Takes the pending ack, removing the file (notify side). `None` when there is none.
///
/// # Errors
/// Returns an error when the file exists but cannot be read or decoded.
pub fn take_stats_ack(state_file: &Path) -> Result<Option<u64>, NodeCoreError> {
    let path = ack_path(state_file);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("read policy ack file", &error)),
    };
    let _ = std::fs::remove_file(&path);
    let ack: AckFile = serde_json::from_slice(&bytes)
        .map_err(|error| io_error("decode policy ack", &std::io::Error::other(error)))?;
    Ok(Some(ack.from_ms))
}
