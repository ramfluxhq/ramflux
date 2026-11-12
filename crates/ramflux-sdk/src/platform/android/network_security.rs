// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Checker for the host application's network security configuration.
//!
//! The gateway session is pinned by the node's certificate authority inside the SDK and
//! does not use the platform trust store. The platform configuration still has to stay
//! strict for every other HTTP client in the application: no cleartext, and no trust in
//! user-installed certificate authorities in a release build. A debug build may trust user
//! authorities, but only inside `<debug-overrides>`, which the platform ignores unless the
//! application is debuggable.

/// What is wrong with a `network_security_config.xml`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkSecurityDefect {
    /// `cleartextTrafficPermitted="true"` appears somewhere.
    CleartextPermitted,
    /// The base configuration does not state `cleartextTrafficPermitted="false"`.
    CleartextNotDenied,
    /// User certificate authorities are trusted outside `<debug-overrides>`.
    UserCertificatesTrusted,
    /// A release configuration contains `<debug-overrides>` at all.
    DebugOverridesInRelease,
}

/// Which source set the file ships in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildKind {
    Release,
    Debug,
}

fn without_debug_overrides(compact: &str) -> String {
    let mut rest = compact;
    let mut kept = String::with_capacity(compact.len());
    while let Some(open) = rest.find("<debug-overrides") {
        kept.push_str(&rest[..open]);
        let after = &rest[open..];
        match after.find("</debug-overrides>") {
            Some(close) => rest = &after[close + "</debug-overrides>".len()..],
            // An unterminated or self-closed element: drop the remainder of the element tag.
            None => {
                rest = after.find('>').map_or("", |end| &after[end + 1..]);
            }
        }
    }
    kept.push_str(rest);
    kept
}

/// Check a network security configuration for the given source set.
///
/// # Errors
/// The first defect found.
pub fn check_network_security_config(
    xml: &str,
    build: BuildKind,
) -> Result<(), NetworkSecurityDefect> {
    let compact: String = xml.chars().filter(|character| !character.is_whitespace()).collect();
    if compact.contains("cleartextTrafficPermitted=\"true\"") {
        return Err(NetworkSecurityDefect::CleartextPermitted);
    }
    if !compact.contains("<base-configcleartextTrafficPermitted=\"false\"") {
        return Err(NetworkSecurityDefect::CleartextNotDenied);
    }
    if build == BuildKind::Release && compact.contains("<debug-overrides") {
        return Err(NetworkSecurityDefect::DebugOverridesInRelease);
    }
    if without_debug_overrides(&compact).contains("<certificatessrc=\"user\"") {
        return Err(NetworkSecurityDefect::UserCertificatesTrusted);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>"#;

    const DEBUG: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>"#;

    #[test]
    fn strict_release_and_debug_configurations_pass() {
        assert_eq!(check_network_security_config(RELEASE, BuildKind::Release), Ok(()));
        assert_eq!(check_network_security_config(RELEASE, BuildKind::Debug), Ok(()));
        assert_eq!(check_network_security_config(DEBUG, BuildKind::Debug), Ok(()));
    }

    #[test]
    fn debug_override_in_the_release_source_set_is_a_defect() {
        assert_eq!(
            check_network_security_config(DEBUG, BuildKind::Release),
            Err(NetworkSecurityDefect::DebugOverridesInRelease)
        );
    }

    #[test]
    fn user_certificates_outside_debug_overrides_are_a_defect() {
        let trusting = RELEASE.replace(
            "<certificates src=\"system\" />",
            "<certificates src=\"system\" /><certificates src=\"user\" />",
        );
        for build in [BuildKind::Release, BuildKind::Debug] {
            assert_eq!(
                check_network_security_config(&trusting, build),
                Err(NetworkSecurityDefect::UserCertificatesTrusted)
            );
        }
    }

    #[test]
    fn cleartext_is_refused_wherever_it_appears() {
        let permitted = RELEASE.replace("=\"false\"", "=\"true\"");
        assert_eq!(
            check_network_security_config(&permitted, BuildKind::Release),
            Err(NetworkSecurityDefect::CleartextPermitted)
        );
        let domain = RELEASE.replace(
            "</network-security-config>",
            "<domain-config cleartextTrafficPermitted=\"true\"><domain>example.org</domain></domain-config></network-security-config>",
        );
        assert_eq!(
            check_network_security_config(&domain, BuildKind::Release),
            Err(NetworkSecurityDefect::CleartextPermitted)
        );
        let silent = RELEASE.replace(" cleartextTrafficPermitted=\"false\"", "");
        assert_eq!(
            check_network_security_config(&silent, BuildKind::Release),
            Err(NetworkSecurityDefect::CleartextNotDenied)
        );
    }
}
