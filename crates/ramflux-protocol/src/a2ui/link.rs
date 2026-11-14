// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit-time link validation. Browser handoff belongs to host modules.
use super::Reject;
/// The serialized URL is the one string that may later be displayed and opened.
/// # Errors
/// Rejects non-HTTPS, userinfo, IP/local hosts, controls/bidi and URLs over 2048 bytes.
pub fn validate_url(input: &str) -> Result<String, Reject> {
    if input.chars().any(|c| c.is_control() || crate::text_safety::is_bidi_control(c)) {
        return Err(Reject::Expression);
    }
    let url = url::Url::parse(input).map_err(|_| Reject::Expression)?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(Reject::Expression);
    }
    let Some(url::Host::Domain(host)) = url.host() else {
        return Err(Reject::Expression);
    };
    let host = host.trim_end_matches('.');
    if !host.contains('.')
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Reject::Expression);
    }
    let serialized = url.to_string();
    if serialized.len() > 2048 {
        return Err(Reject::Limit);
    }
    Ok(serialized)
}
