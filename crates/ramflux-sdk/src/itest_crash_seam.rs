// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T25-A5 (OBJ-IPC-01) itest-only crash seam for the object-IPC upload/download crash-resume test
//! (`mvp_s69`).
//!
//! This module is compiled ONLY under the `object-ipc-crash-seam` feature and is never present in
//! default/release SDK or `rf` binaries (so `strings` on a production binary finds none of the env
//! names, mode strings, or abort code below, and the identifier count in non-feature-gated prod paths
//! is zero — marker=0). Even when compiled it is inert until the runtime env
//! `RAMFLUX_SDK_ITEST_CRASH_SEAM_MODE` selects a mode — a double gate.
//!
//! Each seam `abort()`s the process at exactly one crash-safety boundary so the test can prove
//! recovery from a real crash (not a graceful shutdown):
//!   * upload: AFTER the chunk's durable spool fsync + durable journal fsync, BEFORE the ack (the
//!     d->e boundary in `object_put_chunk_apply`) — a restart must RESUME from the durable journal
//!     offset.
//!   * download: AFTER the whole download spool is written + fsynced, BEFORE any read is served (so a
//!     partial can never be verify-then-rename'd into place) — a restart re-begins from offset 0.
//!
//! A best-effort fsync'd marker is written just before the abort so the test observes the crash point
//! deterministically without a timing guess.

use std::io::Write as _;

const MODE_ENV: &str = "RAMFLUX_SDK_ITEST_CRASH_SEAM_MODE";
const MARKER_ENV: &str = "RAMFLUX_SDK_ITEST_CRASH_SEAM_MARKER";
const AFTER_BYTES_ENV: &str = "RAMFLUX_SDK_ITEST_CRASH_SEAM_AFTER_BYTES";

/// The crash boundary the process is armed to abort at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Off,
    /// Abort a mid-upload after a chunk's durable spool + journal fsync, before the ack.
    UploadChunkBeforeAck,
    /// Abort a mid-download after the spool is written + fsynced, before any read is served.
    DownloadAfterWrite,
}

/// Pure mapping from the raw env value to a [`Mode`]; any unknown/absent value is [`Mode::Off`].
pub(crate) fn parse_mode(raw: Option<&str>) -> Mode {
    match raw {
        Some("upload-chunk-before-ack") => Mode::UploadChunkBeforeAck,
        Some("download-after-write") => Mode::DownloadAfterWrite,
        _ => Mode::Off,
    }
}

fn mode() -> Mode {
    parse_mode(std::env::var(MODE_ENV).ok().as_deref())
}

/// The armed durable-offset threshold (in bytes) for the upload seam; defaults to 0 (fire on the
/// first journaled chunk). The test sets this to ~half the object so the crash lands mid-upload.
fn after_bytes() -> usize {
    std::env::var(AFTER_BYTES_ENV).ok().and_then(|value| value.parse().ok()).unwrap_or(0)
}

/// Best-effort fsync'd marker so the test observes the exact crash point without a timing guess. The
/// process is about to `abort()`, so a failure here is intentionally ignored.
fn write_marker() {
    if let Some(path) = std::env::var_os(MARKER_ENV)
        && let Ok(mut file) = std::fs::File::create(&path)
    {
        let _ = file.write_all(b"crash-seam-fired\n");
        let _ = file.sync_all();
    }
}

/// Upload seam: `abort()` after the durable spool fsync + durable journal fsync, before the ack, once
/// the durable `written` offset reaches the armed threshold. No-op unless armed.
pub(crate) fn maybe_abort_upload_before_ack(written: usize) {
    if mode() != Mode::UploadChunkBeforeAck || written < after_bytes() {
        return;
    }
    write_marker();
    std::process::abort();
}

/// Download seam: `abort()` after the whole download spool is written + fsynced, before any read is
/// served. No-op unless armed.
pub(crate) fn maybe_abort_download_after_write() {
    if mode() != Mode::DownloadAfterWrite {
        return;
    }
    write_marker();
    std::process::abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_maps_known_values_and_defaults_off() {
        assert_eq!(parse_mode(Some("upload-chunk-before-ack")), Mode::UploadChunkBeforeAck);
        assert_eq!(parse_mode(Some("download-after-write")), Mode::DownloadAfterWrite);
        assert_eq!(parse_mode(Some("unknown")), Mode::Off);
        assert_eq!(parse_mode(None), Mode::Off);
    }

    #[test]
    fn unarmed_seams_never_abort() {
        // With no mode env set both seams are inert (this test would abort the process otherwise).
        maybe_abort_upload_before_ack(usize::MAX);
        maybe_abort_download_after_write();
    }
}
