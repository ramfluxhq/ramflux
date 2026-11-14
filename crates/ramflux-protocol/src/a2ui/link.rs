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
    let authority = input
        .trim()
        .split_once(':')
        .map(|(_, rest)| {
            rest.trim_start_matches(['/', '\\']).split(['/', '\\', '?', '#']).next().unwrap_or("")
        })
        .ok_or(Reject::Expression)?;
    if authority.contains('@') {
        return Err(Reject::Expression);
    }
    let url = url::Url::parse(input).map_err(|_| Reject::Expression)?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(Reject::Expression);
    }
    let Some(url::Host::Domain(host)) = url.host() else {
        return Err(Reject::Expression);
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.len() > 253
        || !host.contains('.')
        || matches!(host.rsplit('.').next(), Some("localhost" | "local"))
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_link_validation_refuses_credentials_local_hosts_and_oversized_urls()
    -> Result<(), Box<dyn std::error::Error>> {
        for url in [
            "http://example.com/",
            "https://user@example.com/",
            "https://@example.com/",
            "https://user:secret@example.com/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://localhost/",
            "https://printer.local/",
            "https://single/",
            "https://example.com../",
            "https://example.com/\u{202e}hidden",
        ] {
            assert!(
                validate_url(url).is_err(),
                "unsafe browser destination must be refused: {url}"
            );
        }
        assert!(
            validate_url(&format!("https://example.com/{}", "x".repeat(2048))).is_err(),
            "the serialized URL must obey its byte cap"
        );
        assert_eq!(
            validate_url("HTTPS://EXAMPLE.COM:443/a/../b?q=value")?,
            "https://example.com/b?q=value",
            "host display and launch must share one WHATWG serialization"
        );
        Ok(())
    }
}
