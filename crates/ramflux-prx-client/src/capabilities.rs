// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `GET /api/capabilities` and the capability gate every agent route checks first.

use crate::client::PrxClient;
use crate::error::{PrxError, decode_ok, protocol};
use reqwest::Method;
use serde::Deserialize;
use std::collections::BTreeSet;

/// Advertised by every build that serves the capability and catalog routes.
pub const CAPABILITIES_V1: &str = "capabilities_v1";
/// The catalog route.
pub const AGENT_CATALOG_V1: &str = "agent_catalog_v1";
/// The agent routes: list, read, put, retire, targeted-agents switch and config reload.
pub const AGENT_CRUD_V1: &str = "agent_crud_v1";
/// `GET /api/agents/main`.
pub const AGENT_MAIN_READBACK_V1: &str = "agent_main_readback_v1";

/// The build identity PRX reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildCommit {
    /// The full git SHA the binary was built from.
    Sha(String),
    /// Built outside a git checkout without `PRX_BUILD_COMMIT`: not a release build.
    Unknown,
}

/// What the running daemon supports. Unknown tokens are kept and ignored by the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub prx_version: String,
    pub commit: BuildCommit,
    pub api: u32,
    /// Tokens effective in the running daemon.
    pub capabilities: BTreeSet<String>,
    /// Tokens present in this build but switched off or pending a restart.
    pub available: BTreeSet<String>,
}

impl Capabilities {
    /// True when the running daemon advertises `token`.
    #[must_use]
    pub fn has(&self, token: &str) -> bool {
        self.capabilities.contains(token)
    }

    /// True when `token` is present in the build but not effective.
    #[must_use]
    pub fn is_available_but_off(&self, token: &str) -> bool {
        !self.has(token) && self.available.contains(token)
    }

    pub(crate) fn from_body(body: &[u8]) -> Result<Self, PrxError> {
        let wire: WireCapabilities = decode_ok(body)?;
        Ok(Self {
            prx_version: wire.prx_version,
            commit: parse_commit(&wire.commit)?,
            api: wire.api,
            capabilities: wire.capabilities,
            available: wire.available,
        })
    }
}

/// Refuses the call unless the running daemon advertises `token`.
///
/// # Errors
/// Returns `PrxError::Unsupported` when the token is not effective.
pub fn require(caps: &Capabilities, token: &str) -> Result<(), PrxError> {
    if caps.has(token) {
        Ok(())
    } else {
        Err(PrxError::Unsupported {
            token: token.to_owned(),
            available_but_off: caps.is_available_but_off(token),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCapabilities {
    prx_version: String,
    commit: String,
    api: u32,
    capabilities: BTreeSet<String>,
    available: BTreeSet<String>,
}

fn parse_commit(raw: &str) -> Result<BuildCommit, PrxError> {
    if raw == "unknown" {
        return Ok(BuildCommit::Unknown);
    }
    let is_sha = raw.len() == 40 && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if is_sha {
        Ok(BuildCommit::Sha(raw.to_owned()))
    } else {
        Err(protocol("commit is neither a 40-hex SHA nor unknown"))
    }
}

impl PrxClient {
    /// Reads what the daemon supports. Needs no capability.
    ///
    /// # Errors
    /// Returns the transport, API or contract error of the call.
    pub async fn capabilities(&self) -> Result<Capabilities, PrxError> {
        let raw = self.transport.call(Method::GET, "/api/capabilities", None, None).await?;
        Capabilities::from_body(&raw.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "67c5274ef9ee0eefa1521e45bdf9100ef8719fba";

    fn body(commit: &str, extra: &str) -> String {
        format!(
            r#"{{"prx_version":"0.8.171","commit":"{commit}","api":1,"capabilities":["agent_catalog_v1","capabilities_v1","zz_future_v9"],"available":["agent_crud_v1"]{extra}}}"#
        )
    }

    #[test]
    fn decodes_a_release_build_and_keeps_unknown_tokens() {
        let caps = Capabilities::from_body(body(SHA, "").as_bytes())
            .expect("test: documented shape decodes");
        assert_eq!(caps.commit, BuildCommit::Sha(SHA.to_owned()));
        assert_eq!(caps.api, 1);
        assert!(caps.has("capabilities_v1"));
        assert!(caps.has("zz_future_v9"), "unknown tokens are kept");
    }

    #[test]
    fn unknown_commit_is_not_a_sha() {
        let caps = Capabilities::from_body(body("unknown", "").as_bytes())
            .expect("test: unknown commit decodes");
        assert_eq!(caps.commit, BuildCommit::Unknown);
    }

    #[test]
    fn malformed_commit_and_extra_fields_fail_closed() {
        for bad in [
            body("EAF91764C566267EB579436C82C5CD3B445DD7BF", ""),
            body("eaf9176", ""),
            body(SHA, r#","limits":{}"#),
        ] {
            assert!(
                matches!(Capabilities::from_body(bad.as_bytes()), Err(PrxError::Protocol { .. })),
                "malformed capabilities body must be refused: {bad}"
            );
        }
    }

    #[test]
    fn gate_distinguishes_absent_from_available_but_off() {
        let caps = Capabilities::from_body(body(SHA, "").as_bytes()).expect("test: decodes");
        assert!(require(&caps, AGENT_CATALOG_V1).is_ok());
        assert!(!caps.is_available_but_off(AGENT_CATALOG_V1), "advertised tokens are not 'off'");
        match require(&caps, AGENT_CRUD_V1) {
            Err(PrxError::Unsupported { token, available_but_off }) => {
                assert_eq!(token, AGENT_CRUD_V1);
                assert!(available_but_off, "agent_crud_v1 is in available but not effective");
            }
            other => panic!("test: expected Unsupported, got {other:?}"),
        }
        match require(&caps, AGENT_MAIN_READBACK_V1) {
            Err(PrxError::Unsupported { available_but_off, .. }) => {
                assert!(!available_but_off, "absent token is not reported as available-but-off");
            }
            other => panic!("test: expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn null_capabilities_fields_are_refused() {
        let literal = body(SHA, "");
        for pointer in ["/commit", "/api", "/capabilities", "/available", "/prx_version"] {
            crate::test_support::assert_null_refused(&literal, pointer, Capabilities::from_body);
        }
    }
}
