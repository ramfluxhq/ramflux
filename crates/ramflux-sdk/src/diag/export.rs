// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `diag.export` and `diag.snapshot` (C-10): the SDK part of a diagnostics bundle.
//! Reads only the sink's own files under `<data_root>/diag/`; never account content.
use super::{events, logging};
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Core facts for the bundle manifest. `RAMFLUX_CORE_COMMIT` is set at build time by real-run builds.
fn manifest() -> Value {
    let registry =
        super::logging::fields::REGISTRY.iter().fold(String::new(), |mut out, (key, kind)| {
            out.push_str(key);
            out.push(':');
            out.push_str(kind);
            out.push('\n');
            out
        });
    json!({
        "schema": "ramflux.diag.bundle.v1",
        "core_commit": option_env!("RAMFLUX_CORE_COMMIT").unwrap_or("unset"),
        "header_hash": blake3::hash(registry.as_bytes()).to_hex().to_string(),
        "log_schema": "ramflux.diag.v1",
        "key_epoch": logging::active().map_or(0, |session| session.epoch()),
    })
}

/// Lists the sink files modified at or after `since_ms`, as `diag/<name>` paths.
fn files(data_root: &Path, since_ms: Option<u64>) -> Vec<String> {
    let dir = data_root.join("diag");
    let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { return false };
            if !name.ends_with(".ndjson") {
                return false;
            }
            let Some(since) = since_ms else { return true };
            let modified = entry.metadata().and_then(|meta| meta.modified()).ok();
            let cutoff = SystemTime::UNIX_EPOCH + Duration::from_millis(since);
            modified.is_some_and(|modified| modified >= cutoff)
        })
        .filter_map(|entry| entry.file_name().to_str().map(|name| format!("diag/{name}")))
        .collect();
    names.sort();
    names
}

/// Flushes the sink, then describes the bundle: files, failures and manifest facts.
pub(crate) fn export(data_root: &Path, since_ms: Option<u64>) -> Value {
    events::flush();
    json!({
        "files": files(data_root, since_ms),
        "errors": events::error_table(since_ms).into_iter().take(200).collect::<Vec<_>>(),
        "manifest": manifest(),
    })
}

/// Counters of the sink itself. Per-account counters are not yet collected (see the report).
pub(crate) fn snapshot(data_root: &Path) -> Value {
    let (process, level, dropped) = logging::active().map_or_else(
        || ("none".to_owned(), "none".to_owned(), 0_u64),
        |session| (session.process().to_owned(), session.level().to_owned(), session.dropped()),
    );
    json!({
        "process": process,
        "level": level,
        "sink_dropped": dropped,
        "errors_recorded": events::error_table(None).len(),
        "files": files(data_root, None).len(),
        "manifest": manifest(),
    })
}
