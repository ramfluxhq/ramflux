// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compile-time proof that a browser build is a linked secondary device only.
//!
//! The rule is enforced by the build, not by convention:
//!
//! * the marker features below are a hard error on `target_family = "wasm"`;
//! * `FORBIDDEN_BUS_METHODS` is the closed list of local-bus methods that touch a primary seed,
//!   a recovery secret, home migration or device approval; the tab carrier refuses each of them
//!   before dispatch and the release script greps the linked module for their handlers;
//! * `scripts/check-web-role.sh` fails the build when the linked `.wasm` exports or names a
//!   symbol from the primary-authority code.

#[cfg(all(target_family = "wasm", feature = "primary-authority"))]
compile_error!("a browser build never holds primary authority: remove `primary-authority`");

#[cfg(all(target_family = "wasm", feature = "account-recovery"))]
compile_error!("a browser build never runs recovery: remove `account-recovery`");

/// Role string reported to the host and shown in the device list.
pub const WEB_DEVICE_ROLE: &str = "linked_secondary";

/// Local-bus methods that do not exist in a browser build. The carrier answers each with
/// `custody_vault_unavailable` without parsing the body.
pub const FORBIDDEN_BUS_METHODS: &[&str] = &[
    "account.backup.export",
    "account.backup.import",
    "account.create",
    "account.export_agent_credentials",
    "account.itest_legacy.create",
    "account.passphrase.rotate",
    "device.activate",
    "device.authorize",
    "device.migrate",
    "device.pair.approve",
    "device.pair.begin",
    "device.pair.confirm",
    "device.revoke",
    "device.sync.export",
];

/// Method-name prefixes refused as a whole family.
pub const FORBIDDEN_BUS_METHOD_PREFIXES: &[&str] = &["recovery.", "home_migration.", "guardian."];

/// Whether a local-bus method is absent from the browser build.
#[must_use]
pub fn is_forbidden_method(method: &str) -> bool {
    FORBIDDEN_BUS_METHODS.contains(&method)
        || FORBIDDEN_BUS_METHOD_PREFIXES.iter().any(|prefix| method.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_every_primary_authority_method() {
        for method in ["account.create", "recovery.initiate", "device.pair.approve"] {
            assert!(is_forbidden_method(method), "{method}");
        }
    }

    #[test]
    fn allows_the_joining_side_of_pairing_and_messaging() {
        for method in ["device.pair.join", "device.pair.status", "message.submit", "device.list"] {
            assert!(!is_forbidden_method(method), "{method}");
        }
    }
}
