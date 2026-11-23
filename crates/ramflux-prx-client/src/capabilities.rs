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
/// `POST /api/sessions` with a caller-chosen `session_key`.
pub const SESSION_KEY_V1: &str = "session_key_v1";
/// The rf message route accepts a target together with caller context.
pub const MESSAGE_TARGET_V1: &str = "message_target_v1";
/// The rf message route delivers caller context (`deliver`: `turn` or `context`).
pub const MESSAGE_CONTEXT_DELIVERY_V1: &str = "message_context_delivery_v1";
/// `GET /api/owner`: one stable install owner id for every paired bearer.
pub const OWNER_ID_STABLE_V1: &str = "owner_id_stable_v1";
/// Replay answers (`replayed:true`), the crash-retry attempt fields and cancel by run id on the
/// message route.
pub const MESSAGE_IDEMPOTENCY_V1: &str = "message_idempotency_v1";
/// Per-agent partitioned reads: the message history carries `agent` and filters by it.
pub const TARGETED_AGENTS_V1: &str = "targeted_agents_v1";
/// `POST .../messages/{id}/delete`, `.../messages/delete` and `.../runs/{run_id}/reply/delete`: tombstone
/// deletes of a message, a batch, or one run's reply. A deleted key replays `409 message_deleted`.
pub const MESSAGE_DELETE_V1: &str = "message_delete_v1";
/// The three delete routes accept `"forget_writes": true` and also forget the memories and
/// documents the deleted runs wrote. Sending the field without this token is refused.
pub const MESSAGE_FORGET_WRITES_V1: &str = "message_forget_writes_v1";
/// `limits` on an agent `PUT`: `max_concurrent_turns` and `max_cost_per_day_cents`.
pub const AGENT_LIMITS_V1: &str = "agent_limits_v1";
/// `DELETE /api/sessions/{id}/agents/{name}/history`, including `main`.
pub const HISTORY_ERASE_V1: &str = "history_erase_v1";
/// `POST /api/agents/{name}/purge` after the agent has been retired.
pub const AGENT_MEMORY_PURGE_V1: &str = "agent_memory_purge_v1";
/// `GET /api/sync/snapshot`. Advertised when the daemon's store publishes the journal.
pub const SYNC_SNAPSHOT_V1: &str = "sync_snapshot_v1";
/// `GET /api/sync/ws`. Advertised together with `sync_snapshot_v1`.
pub const SYNC_WS_V1: &str = "sync_ws_v1";
/// Ephemeral per-run stream frames on the sync socket (`typing`, `tool_status`, `delta`).
pub const STREAM_FRAMES_V1: &str = "stream_frames_v1";
/// `POST /api/sessions/{id}/approvals/{approval_id}`.
pub const RUN_APPROVALS_V1: &str = "run_approvals_v1";
/// Non-interactive host install. Advertised at the pin. This client does not call those routes.
pub const HOST_BOOTSTRAP_V1: &str = "host_bootstrap_v1";

/// The build identity PRX reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildCommit {
    /// The full git SHA the binary was built from.
    Sha(String),
    /// Built outside a git checkout without `PRX_BUILD_COMMIT`: not a release build.
    Unknown,
}

/// Spawn and live-child caps from `GET /api/capabilities`. `None` means the daemon sets no cap.
/// This client records the caps and does not enforce them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsFacts {
    /// Maximum children one spawn batch may start.
    pub spawn_batch_max: Option<u64>,
    /// Maximum live children of one agent.
    pub live_children_per_agent_max: Option<u64>,
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
    /// Spawn caps reported beside the token list.
    pub limits_facts: LimitsFacts,
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
            limits_facts: wire.limits_facts,
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
    #[serde(default)]
    limits_facts: LimitsFacts,
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

    const SHA: &str = "f6ff62bff51877992c99afca3439b3fdee10a260";

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
