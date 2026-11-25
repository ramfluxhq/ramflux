// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Request paths for default-level logs. Several routes carry a principal, device or delivery id
//! as their last segment, so logs keep the route shape and hide that segment.

/// Longest path, in bytes, that a default-level log line carries.
const LOG_PATH_MAX_BYTES: usize = 128;

/// Returns the path without its query, with the last segment replaced by `*` when the path has
/// more than two segments (for example `/mvp1/inbox/<id>` becomes `/mvp1/inbox/*`), truncated to
/// 128 bytes. Only the last segment is hidden: an identifier in a middle segment is NOT redacted,
/// so every route must keep its id last.
#[must_use]
pub fn log_path(path: &str) -> String {
    let base = path.split('?').next().unwrap_or_default();
    let segments: Vec<&str> = base.split('/').collect();
    let redacted = match segments.split_last() {
        Some((_, head)) if segments.len() > 3 => {
            let mut redacted = head.join("/");
            redacted.push_str("/*");
            redacted
        }
        _ => base.to_owned(),
    };
    let mut end = redacted.len().min(LOG_PATH_MAX_BYTES);
    while !redacted.is_char_boundary(end) {
        end -= 1;
    }
    redacted.get(..end).unwrap_or_default().to_owned()
}
