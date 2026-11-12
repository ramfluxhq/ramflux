// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Binding API version and descriptor fingerprint negotiation.
//!
//! Rule: a host generated against minor N works with a core of the same major and minor N or
//! newer. Any other pair is `UnsupportedVersion` (code 3). The descriptor fingerprint travels
//! in the handshake; a mismatch inside a compatible version is reported, not refused, because
//! unknown content is a typed successful row.

use crate::error::{CoreError, code};
use crate::types::{ApiVersion, HostHandshake, Negotiated};

/// Major version of the binding API. Bumped when a numeric error code or the request/update
/// frame set changes incompatibly; independent of the message schema generation.
pub const BINDING_API_MAJOR: u32 = 1;
/// Minor version of the binding API. Bumped for additive changes.
pub const BINDING_API_MINOR: u32 = 0;

/// Capabilities this core offers, sorted.
pub const CAPABILITIES: &[&str] = &["execute.v1", "lifecycle.v1", "network.v1", "subscribe.credit.v1"];

/// Domain separation of the descriptor fingerprint.
const FINGERPRINT_CONTEXT: &str = "ramflux.core_api.descriptor_fingerprint.v1";

/// Binding API version compiled into this library.
#[uniffi::export]
#[must_use]
pub fn binding_api_version() -> ApiVersion {
    ApiVersion { major: BINDING_API_MAJOR, minor: BINDING_API_MINOR }
}

/// Lower-case hex fingerprint of the message descriptor compiled into this library. The
/// generator writes the same value into generated host models.
#[uniffi::export]
#[must_use]
pub fn descriptor_fingerprint() -> String {
    let mut hasher = blake3::Hasher::new_derive_key(FINGERPRINT_CONTEXT);
    hasher.update(ramflux_protocol::message::FILE_DESCRIPTOR_SET);
    hasher.finalize().to_hex().to_string()
}

/// Negotiate against the version compiled into this library.
///
/// # Errors
/// `UnsupportedVersion` when the majors differ or the host needs a newer minor.
pub fn negotiate(host: &HostHandshake) -> Result<Negotiated, CoreError> {
    negotiate_with(host, binding_api_version(), &descriptor_fingerprint())
}

/// Negotiation against an explicit core version, so every pair is testable.
///
/// # Errors
/// `UnsupportedVersion` when the majors differ or the host needs a newer minor.
pub fn negotiate_with(
    host: &HostHandshake,
    core: ApiVersion,
    core_fingerprint: &str,
) -> Result<Negotiated, CoreError> {
    if host.api.major != core.major {
        return Err(CoreError::plain(
            code::UNSUPPORTED_VERSION,
            format!(
                "host binding API major {} does not match core major {}",
                host.api.major, core.major
            ),
        ));
    }
    if host.api.minor > core.minor {
        return Err(CoreError::plain(
            code::UNSUPPORTED_VERSION,
            format!(
                "host binding API {}.{} needs a core of minor {} or newer; this core is {}.{}",
                host.api.major, host.api.minor, host.api.minor, core.major, core.minor
            ),
        ));
    }
    let mut capabilities: Vec<String> = host
        .capabilities
        .iter()
        .filter(|wanted| CAPABILITIES.contains(&wanted.as_str()))
        .cloned()
        .collect();
    capabilities.sort();
    capabilities.dedup();
    Ok(Negotiated {
        core_api: core,
        core_descriptor_fingerprint: core_fingerprint.to_owned(),
        descriptor_matches: host.descriptor_fingerprint.eq_ignore_ascii_case(core_fingerprint),
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::{code, negotiate_with};
    use crate::types::{ApiVersion, HostHandshake};

    fn host(major: u32, minor: u32, fingerprint: &str) -> HostHandshake {
        HostHandshake {
            api: ApiVersion { major, minor },
            descriptor_fingerprint: fingerprint.to_owned(),
            capabilities: vec!["subscribe.credit.v1".to_owned(), "not.offered".to_owned()],
        }
    }

    #[test]
    fn host_of_minor_n_accepts_core_of_minor_n_or_newer() {
        let core = ApiVersion { major: 1, minor: 3 };
        for minor in 0..=3 {
            assert!(negotiate_with(&host(1, minor, "ab"), core, "ab").is_ok());
        }
    }

    #[test]
    fn older_core_returns_unsupported_version_code_3() {
        let core = ApiVersion { major: 1, minor: 2 };
        let refused = negotiate_with(&host(1, 3, "ab"), core, "ab");
        assert_eq!(refused.map_err(|error| error.code()), Err(code::UNSUPPORTED_VERSION));
    }

    #[test]
    fn different_major_returns_unsupported_version_in_both_directions() {
        let core = ApiVersion { major: 2, minor: 0 };
        for major in [1, 3] {
            let refused = negotiate_with(&host(major, 0, "ab"), core, "ab");
            assert_eq!(refused.map_err(|error| error.code()), Err(code::UNSUPPORTED_VERSION));
        }
    }

    #[test]
    fn fingerprint_mismatch_is_reported_not_refused_and_unknown_capabilities_are_dropped() {
        let core = ApiVersion { major: 1, minor: 0 };
        let negotiated = negotiate_with(&host(1, 0, "AB"), core, "cd");
        assert_eq!(negotiated.as_ref().map(|done| done.descriptor_matches), Ok(false));
        assert_eq!(
            negotiated.map(|done| done.capabilities),
            Ok(vec!["subscribe.credit.v1".to_owned()])
        );
        let same = negotiate_with(&host(1, 0, "AB"), core, "ab");
        assert_eq!(same.map(|done| done.descriptor_matches), Ok(true));
    }
}
