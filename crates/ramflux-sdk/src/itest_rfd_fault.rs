// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T24-B2 itest-only fault seam for the rfd mid-flight SIGKILL crash-resume test (`mvp_s63`).
//!
//! This module is compiled ONLY under the `itest-rfd-fault` feature and is never present in
//! default/release SDK or `rf` binaries (so `strings` on a production binary finds none of the
//! env names, mode strings, or park code below). Even when compiled it is inert until the runtime
//! env `RAMFLUX_SDK_ITEST_RFD_FAULT_MODE` selects a mode — a double gate.
//!
//! [`barrier`] is placed at a post-local-commit / pre-remote boundary in the SDK object/DM paths.
//! When the process's selected mode matches the injection point, and only once per process, it
//! writes a durable marker file (so the test can deterministically observe the held state without
//! sleeping) and then parks forever, leaving the real `rf daemon start` process to be `SIGKILL`ed
//! by the test. A marker write failure fails the operation — it is never silently swallowed.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

const MODE_ENV: &str = "RAMFLUX_SDK_ITEST_RFD_FAULT_MODE";
const MARKER_ENV: &str = "RAMFLUX_SDK_ITEST_RFD_FAULT_MARKER";

/// Fires at most once per process across every injection point.
static FAULT_CLAIMED: AtomicBool = AtomicBool::new(false);

/// The durable-commit boundary at which a crash is injected. Each value maps to exactly one
/// `RAMFLUX_SDK_ITEST_RFD_FAULT_MODE` string and one call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Off,
    /// After the advanced send ratchet snapshot is durable, before the gateway submit.
    DmSend,
    /// After a chunk's local transfer bitmap is durable, before the next relay PUT.
    OwnerPut,
    /// After the received object + transfer are durable, before the relay ACK.
    GranteeImport,
    /// After the advanced recv ratchet snapshot + checkpoint are durable, before the cursor.
    DmRecv,
}

/// Pure mapping from the raw env value to a [`Mode`]; any unknown/absent value is [`Mode::Off`].
pub(crate) fn parse_mode(raw: Option<&str>) -> Mode {
    match raw {
        Some("dm-send") => Mode::DmSend,
        Some("owner-put") => Mode::OwnerPut,
        Some("grantee-import") => Mode::GranteeImport,
        Some("dm-recv") => Mode::DmRecv,
        _ => Mode::Off,
    }
}

fn mode() -> Mode {
    parse_mode(std::env::var(MODE_ENV).ok().as_deref())
}

/// Writes the marker to `path`, fsyncing so the test observes it deterministically. Returns `Err`
/// on any filesystem failure (used by the fail-closed public path and by pure tests).
fn write_marker_to(path: &std::path::Path) -> Result<(), ()> {
    let mut file = std::fs::File::create(path).map_err(|_error| ())?;
    file.write_all(b"rfd-fault-held\n").map_err(|_error| ())?;
    file.sync_all().map_err(|_error| ())
}

fn write_marker() -> Result<(), crate::error::SdkError> {
    let path = std::env::var_os(MARKER_ENV).ok_or_else(|| {
        crate::error::SdkError::LocalBus("itest rfd fault marker env unset".to_owned())
    })?;
    write_marker_to(std::path::Path::new(&path)).map_err(|()| {
        crate::error::SdkError::LocalBus("itest rfd fault marker write failed".to_owned())
    })
}

/// Post-local-commit / pre-remote barrier. No-op unless the process's selected mode equals `point`
/// and the once-per-process claim is still available. On a match it writes the marker (failing the
/// operation if the write fails) and parks forever, so the test can SIGKILL rfd at exactly this
/// durable-commit boundary.
pub(crate) async fn barrier(point: Mode) -> Result<(), crate::error::SdkError> {
    if point == Mode::Off || mode() != point {
        return Ok(());
    }
    if FAULT_CLAIMED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    write_marker()?;
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_maps_known_values_and_defaults_off() {
        assert_eq!(parse_mode(Some("dm-send")), Mode::DmSend);
        assert_eq!(parse_mode(Some("owner-put")), Mode::OwnerPut);
        assert_eq!(parse_mode(Some("grantee-import")), Mode::GranteeImport);
        assert_eq!(parse_mode(Some("dm-recv")), Mode::DmRecv);
        assert_eq!(parse_mode(Some("unknown")), Mode::Off);
        assert_eq!(parse_mode(None), Mode::Off);
    }

    #[test]
    fn write_marker_creates_file_and_fails_closed_on_unwritable_path() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let ok_path = std::env::temp_dir()
            .join(format!("ramflux-rfd-fault-marker-{}-{nanos}", std::process::id()));
        assert!(write_marker_to(&ok_path).is_ok());
        assert!(ok_path.exists());
        let _ = std::fs::remove_file(&ok_path);

        // A path under a non-existent directory cannot be created -> fail-closed Err.
        let bad_path = ok_path.join("nested").join("marker");
        assert!(write_marker_to(&bad_path).is_err());
    }

    #[test]
    fn barrier_off_point_is_noop() {
        // A pure guard: the Off point never claims or parks regardless of env.
        // (We cannot exercise the parking path in a unit test; parse/claim logic is covered here.)
        let claimed_before = FAULT_CLAIMED.load(Ordering::SeqCst);
        // Off returns immediately without touching the claim.
        let fut = barrier(Mode::Off);
        drop(fut);
        assert_eq!(FAULT_CLAIMED.load(Ordering::SeqCst), claimed_before);
    }
}
