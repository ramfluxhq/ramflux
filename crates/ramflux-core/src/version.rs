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
#[path = "../build_sha.rs"]
mod build_sha;

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn banner_is_version_then_twelve_char_sha_or_unknown() {
        assert_eq!(
            BANNER,
            format!("ramflux {VERSION_SHA}"),
            "banner must be 'ramflux ' + VERSION_SHA"
        );
        assert_eq!(
            VERSION_SHA,
            format!("{VERSION} ({GIT_SHA})"),
            "VERSION_SHA must join version and sha"
        );
        assert!(
            GIT_SHA == "unknown"
                || (GIT_SHA.len() == 12 && GIT_SHA.bytes().all(|b| b.is_ascii_hexdigit())),
            "GIT_SHA must be 12 hex characters or 'unknown', got {GIT_SHA}"
        );
        let mut parts = VERSION.split('.');
        for _ in 0..3 {
            assert!(
                parts.next().is_some_and(|p| p.parse::<u32>().is_ok()),
                "VERSION must be numeric X.Y.Z, got {VERSION}"
            );
        }
    }

    #[test]
    fn valid_overrides_are_cut_to_twelve_characters() {
        assert_eq!(
            build_sha::resolve(Some(FULL), None),
            Ok("0123456789ab".to_owned()),
            "a full commit is cut to 12"
        );
        assert_eq!(
            build_sha::resolve(Some("abcdef012345"), Some(FULL)),
            Ok("abcdef012345".to_owned()),
            "override beats git"
        );
    }

    #[test]
    fn malformed_overrides_fail_without_echoing_the_input() {
        for bad in [
            "abc",
            "ABCDEF012345",
            "0123456789ag",
            "secret-token-value",
            "abcdef0123
45",
        ] {
            let error = build_sha::resolve(Some(bad), Some(FULL))
                .expect_err("test: malformed override must be refused");
            assert!(!error.contains(bad), "the refusal must not echo the rejected value");
        }
    }

    #[test]
    fn missing_or_unusable_metadata_falls_back_to_unknown() {
        assert_eq!(
            build_sha::resolve(None, None),
            Ok("unknown".to_owned()),
            "no git and no override"
        );
        assert_eq!(
            build_sha::resolve(Some("  "), None),
            Ok("unknown".to_owned()),
            "blank override is unset"
        );
        assert_eq!(
            build_sha::resolve(None, Some("not-a-commit")),
            Ok("unknown".to_owned()),
            "non-hex git output"
        );
        assert_eq!(
            build_sha::resolve(None, Some(FULL)),
            Ok("0123456789ab".to_owned()),
            "git head is used"
        );
    }
}
