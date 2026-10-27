// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Startup validation for public and private HTTP request budgets.
use ramflux_node_core::{HttpRequestLimits, NodeCoreError};
use std::time::Duration;

pub(crate) fn defaults(public: bool) -> HttpRequestLimits {
    HttpRequestLimits {
        max_header_bytes: if public { 8192 } else { 65536 },
        max_body_bytes: if public { 65536 } else { 1024 * 1024 },
        request_timeout: Duration::from_secs(if public { 10 } else { 30 }),
        ..HttpRequestLimits::default()
    }
}
pub(crate) fn configured(public: bool) -> Result<HttpRequestLimits, NodeCoreError> {
    let mut limits = defaults(public);
    let prefix = if public { "RAMFLUX_FEDERATION_PUBLIC" } else { "RAMFLUX_FEDERATION_ADMIN" };
    limits.max_header_bytes =
        setting(&format!("{prefix}_MAX_HEADER_BYTES"), limits.max_header_bytes, 65536)?;
    limits.max_body_bytes =
        setting(&format!("{prefix}_MAX_BODY_BYTES"), limits.max_body_bytes, 64 * 1024 * 1024)?;
    limits.request_timeout = Duration::from_secs(
        u64::try_from(setting(
            &format!("{prefix}_REQUEST_TIMEOUT_SECONDS"),
            usize::try_from(limits.request_timeout.as_secs()).unwrap_or(30),
            3600,
        )?)
        .unwrap_or(30),
    );
    Ok(limits)
}
fn setting(key: &str, default: usize, maximum: usize) -> Result<usize, NodeCoreError> {
    let Some(value) = ramflux_node_core::environment::var_os(key) else { return Ok(default) };
    value
        .to_str()
        .and_then(|value| value.parse().ok())
        .filter(|value| (1..=maximum).contains(value))
        .ok_or_else(|| NodeCoreError::ItestHttp(format!("{key} must be 1..{maximum}")))
}
pub(crate) fn rejection(error: &NodeCoreError) -> Option<&'static str> {
    if let NodeCoreError::HttpRequestRejected { status } = error { Some(status) } else { None }
}
