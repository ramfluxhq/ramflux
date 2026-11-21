// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit-id selection shared by `build.rs` and its unit tests (`version.rs`).

/// Characters of the commit that every binary carries.
pub const SHA_LEN: usize = 12;

/// Lowercase hexadecimal of at least [`SHA_LEN`] characters (a full commit is 40), cut to 12.
pub fn normalize(raw: &str) -> Option<String> {
    let value = raw.trim();
    let valid =
        value.len() >= SHA_LEN && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    valid.then(|| value[..SHA_LEN].to_owned())
}

/// Picks the build commit. An explicit override must be valid (the error never carries the
/// rejected text); git metadata that is not a commit id falls back; no source gives `unknown`.
pub fn resolve(
    override_value: Option<&str>,
    git_head: Option<&str>,
) -> Result<String, &'static str> {
    if let Some(value) = override_value.filter(|v| !v.trim().is_empty()) {
        return normalize(value)
            .ok_or("RAMFLUX_GIT_SHA must be lowercase hexadecimal of at least 12 characters");
    }
    Ok(git_head.and_then(normalize).unwrap_or_else(|| "unknown".to_owned()))
}
