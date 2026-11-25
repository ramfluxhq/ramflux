// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Request paths for default-level logs. Several routes carry a principal, device or delivery id
//! as their last segment, so logs keep the route shape and hide that segment.

/// Returns the path without its query, with the last segment replaced by `*` when the path has
/// more than two segments (for example `/mvp1/inbox/<id>` becomes `/mvp1/inbox/*`).
#[must_use]
pub fn log_path(path: &str) -> String {
    let base = path.split('?').next().unwrap_or_default();
    let segments: Vec<&str> = base.split('/').collect();
    if segments.len() > 3 {
        let mut redacted = segments[..segments.len() - 1].join("/");
        redacted.push_str("/*");
        redacted
    } else {
        base.to_owned()
    }
}
