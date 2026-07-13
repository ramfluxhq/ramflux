// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T25-A2 (OBJ-IPC-01) P0-2 itest-only local-bus RESPONSE-LOSS seam (`mvp_s66`).
//!
//! This module is compiled ONLY under the `itest-bus-fault` feature and is never present in
//! default/release SDK or `rf` binaries (so `strings` on a production binary finds none of the env
//! names, mode strings, or drop code below). Even when compiled it is inert until the runtime env
//! `RAMFLUX_SDK_ITEST_BUS_FAULT_MODE` selects a mode — a double gate, marker=0 in production.
//!
//! Unlike the relay's response seam (which drops the *relay* reply), this seam models the loss of
//! the LOCAL-BUS response byte-stream: after an `object.put` operation is durably `Committed` AND
//! the dispatch has returned Ok, but BEFORE the daemon writes the response frame, the daemon drops
//! the response (closes the connection). The CLI's response read then fails and it must reconnect
//! and reconcile via `object.put.status` — proving the operation committed exactly once even though
//! the caller never saw the reply. A marker-write failure fails closed (never silently swallowed).

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

const MODE_ENV: &str = "RAMFLUX_SDK_ITEST_BUS_FAULT_MODE";
const MARKER_ENV: &str = "RAMFLUX_SDK_ITEST_BUS_FAULT_MARKER";

/// Fires at most once per process.
static FAULT_CLAIMED: AtomicBool = AtomicBool::new(false);

/// The local-bus response boundary at which a response is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Off,
    /// Drop the `object.put` response after the operation is durably `Committed`.
    ObjectPutResponse,
}

/// Pure mapping from the raw env value to a [`Mode`]; any unknown/absent value is [`Mode::Off`].
pub(crate) fn parse_mode(raw: Option<&str>) -> Mode {
    match raw {
        Some("object-put-response") => Mode::ObjectPutResponse,
        _ => Mode::Off,
    }
}

fn mode() -> Mode {
    parse_mode(std::env::var(MODE_ENV).ok().as_deref())
}

fn write_marker_to(path: &std::path::Path) -> Result<(), ()> {
    let mut file = std::fs::File::create(path).map_err(|_error| ())?;
    file.write_all(b"bus-fault-dropped\n").map_err(|_error| ())?;
    file.sync_all().map_err(|_error| ())
}

fn write_marker() -> Result<(), crate::error::SdkError> {
    let path = std::env::var_os(MARKER_ENV).ok_or_else(|| {
        crate::error::SdkError::LocalBus("itest bus fault marker env unset".to_owned())
    })?;
    write_marker_to(std::path::Path::new(&path)).map_err(|()| {
        crate::error::SdkError::LocalBus("itest bus fault marker write failed".to_owned())
    })
}

/// Returns `Ok(true)` exactly once per process when the response for `method` must be dropped
/// (the selected mode targets `object.put`). Writes a durable fsync'd marker on the claim so the
/// test observes the drop deterministically; a marker-write failure returns `Err` (fail closed).
/// Any non-matching method / unarmed process returns `Ok(false)`.
pub(crate) fn should_drop_response(method: &str) -> Result<bool, crate::error::SdkError> {
    if mode() != Mode::ObjectPutResponse || method != "object.put" {
        return Ok(false);
    }
    if FAULT_CLAIMED.swap(true, Ordering::SeqCst) {
        return Ok(false);
    }
    write_marker()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_maps_known_values_and_defaults_off() {
        assert_eq!(parse_mode(Some("object-put-response")), Mode::ObjectPutResponse);
        assert_eq!(parse_mode(Some("unknown")), Mode::Off);
        assert_eq!(parse_mode(None), Mode::Off);
    }

    #[test]
    fn write_marker_creates_file_and_fails_closed_on_unwritable_path() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let ok_path = std::env::temp_dir()
            .join(format!("ramflux-bus-fault-marker-{}-{nanos}", std::process::id()));
        assert!(write_marker_to(&ok_path).is_ok());
        assert!(ok_path.exists());
        let _ = std::fs::remove_file(&ok_path);
        let bad_path = ok_path.join("nested").join("marker");
        assert!(write_marker_to(&bad_path).is_err());
    }

    #[test]
    fn unarmed_process_never_drops() {
        // With no mode env set the seam is inert for every method.
        assert_eq!(should_drop_response("object.put").ok(), Some(false));
        assert_eq!(should_drop_response("object.get").ok(), Some(false));
    }
}
