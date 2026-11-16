// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The product version every binary reports: one `SemVer` line shared by all Ramflux repos,
//! plus the git commit the binary was built from.

/// Product `SemVer` from `[workspace.package]`, for example `0.2.0`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// First 12 characters of the build commit, or `unknown` when the source had no git metadata.
pub const GIT_SHA: &str = env!("RAMFLUX_GIT_SHA");

/// `0.2.0 (abcdef123456)`: the form carried in discovery records and probe output.
pub const VERSION_SHA: &str =
    concat!(env!("CARGO_PKG_VERSION"), " (", env!("RAMFLUX_GIT_SHA"), ")");

/// `ramflux 0.2.0 (abcdef123456)`: the form printed by `rf --version` and logged at startup.
pub const BANNER: &str =
    concat!("ramflux ", env!("CARGO_PKG_VERSION"), " (", env!("RAMFLUX_GIT_SHA"), ")");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_is_version_then_twelve_char_sha_or_unknown() {
        assert_eq!(BANNER, format!("ramflux {VERSION_SHA}"));
        assert_eq!(VERSION_SHA, format!("{VERSION} ({GIT_SHA})"));
        assert!(
            GIT_SHA == "unknown"
                || (GIT_SHA.len() == 12 && GIT_SHA.bytes().all(|b| b.is_ascii_hexdigit()))
        );
        let mut parts = VERSION.split('.');
        for _ in 0..3 {
            assert!(parts.next().is_some_and(|p| p.parse::<u32>().is_ok()));
        }
    }
}
