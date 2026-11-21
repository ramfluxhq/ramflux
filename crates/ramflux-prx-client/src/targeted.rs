// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Targeted-agents switch and config reload (both under `agent_crud_v1`).

use crate::capabilities::{AGENT_CRUD_V1, Capabilities, require};
use crate::client::PrxClient;
use crate::error::{PrxError, decode_ok, protocol};
use crate::revision::ConfigRevision;
use reqwest::Method;
use serde::Deserialize;
use serde_json::json;

const TARGETED_PATH: &str = "/api/gateway/targeted-agents";

/// The targeted-agents switch. `restart_required` stays true until the daemon restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetedAgents {
    /// Config revision.
    pub revision: ConfigRevision,
    pub configured: bool,
    pub effective: bool,
    pub restart_required: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTargeted {
    revision: ConfigRevision,
    configured: bool,
    effective: bool,
    restart_required: bool,
}

/// The answer of `POST /api/config/reload`: the typed part of PRX's report.
///
/// PRX sends the report as a JSON text inside `message`. The client decodes only `status` and
/// `rebuilt` (the report's other fields are not in the token document); a report that does not
/// decode fails closed. After a credential is stored, a reload that rebuilds the turn runtime
/// lists `gateway_turn_runtime` in `rebuilt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadReport {
    pub status: ReloadStatus,
    /// Runtime objects PRX rebuilt by this reload, by name.
    pub rebuilt: Vec<String>,
}

/// The report's `status`, as PRX's configuration reload defines it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadStatus {
    Unchanged,
    Applied,
    AppliedWithRestartRequired,
    RestartRequired,
}

impl ReloadStatus {
    fn from_wire(status: &str) -> Result<Self, PrxError> {
        match status {
            "unchanged" => Ok(Self::Unchanged),
            "applied" => Ok(Self::Applied),
            "applied_with_restart_required" => Ok(Self::AppliedWithRestartRequired),
            "restart_required" => Ok(Self::RestartRequired),
            _ => Err(protocol("config reload reports an unknown status")),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReload {
    success: bool,
    message: String,
}

#[derive(Deserialize)]
struct WireReloadReport {
    status: String,
    rebuilt: Vec<String>,
}

impl TargetedAgents {
    pub(crate) fn from_body(body: &[u8]) -> Result<Self, PrxError> {
        let wire: WireTargeted = decode_ok(body)?;
        Ok(Self {
            revision: wire.revision,
            configured: wire.configured,
            effective: wire.effective,
            restart_required: wire.restart_required,
        })
    }
}

impl ReloadReport {
    pub(crate) fn from_body(body: &[u8]) -> Result<Self, PrxError> {
        let wire: WireReload = decode_ok(body)?;
        if !wire.success {
            return Err(protocol("config reload reports success false"));
        }
        let report: WireReloadReport = decode_ok(wire.message.as_bytes())?;
        Ok(Self { status: ReloadStatus::from_wire(&report.status)?, rebuilt: report.rebuilt })
    }
}

impl PrxClient {
    /// Reads the targeted-agents switch. Needs `agent_crud_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, the API error, or a transport or contract error.
    pub async fn targeted_agents(&self, caps: &Capabilities) -> Result<TargetedAgents, PrxError> {
        require(caps, AGENT_CRUD_V1)?;
        let raw = self.transport.call(Method::GET, TARGETED_PATH, None, None).await?;
        TargetedAgents::from_body(&raw.body)
    }

    /// Turns the switch on or off. Takes effect at the next daemon restart. Needs `agent_crud_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, the API error (for example `revision_conflict`), or a transport
    /// or contract error.
    pub async fn set_targeted_agents(
        &self,
        caps: &Capabilities,
        enabled: bool,
        revision: &ConfigRevision,
    ) -> Result<TargetedAgents, PrxError> {
        require(caps, AGENT_CRUD_V1)?;
        let body = json!({ "enabled": enabled });
        let raw = self
            .transport
            .call(Method::PUT, TARGETED_PATH, Some(revision.as_str()), Some(&body))
            .await?;
        TargetedAgents::from_body(&raw.body)
    }

    /// Reloads the configuration files (owner bearer only; not gated by Main's autonomy).
    /// Needs `agent_crud_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, the API error, or a transport or contract error.
    pub async fn reload_config(&self, caps: &Capabilities) -> Result<ReloadReport, PrxError> {
        require(caps, AGENT_CRUD_V1)?;
        let raw = self.transport.call(Method::POST, "/api/config/reload", None, None).await?;
        ReloadReport::from_body(&raw.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5";

    #[test]
    fn decodes_documented_targeted_shape() {
        let body = format!(
            r#"{{"revision":"{HEX}","configured":true,"effective":true,"restart_required":false}}"#
        );
        let parsed =
            TargetedAgents::from_body(body.as_bytes()).expect("test: documented shape decodes");
        assert!(parsed.configured && parsed.effective && !parsed.restart_required);
    }

    #[test]
    fn extra_or_string_fields_fail_closed() {
        let extra = format!(
            r#"{{"revision":"{HEX}","configured":true,"effective":true,"restart_required":false,"x":1}}"#
        );
        let string_bool = format!(
            r#"{{"revision":"{HEX}","configured":"true","effective":true,"restart_required":false}}"#
        );
        assert!(matches!(
            TargetedAgents::from_body(extra.as_bytes()),
            Err(PrxError::Protocol { .. })
        ));
        assert!(matches!(
            TargetedAgents::from_body(string_bool.as_bytes()),
            Err(PrxError::Protocol { .. })
        ));
    }

    const RELOAD_APPLIED: &str = r#"{"success":true,"message":"{\n  \"status\": \"applied\",\n  \"active_generation\": 7,\n  \"changed\": [],\n  \"rebuilt\": [\"gateway_turn_runtime\"]\n}"}"#;

    #[test]
    fn reload_documented_report_decodes_status_and_rebuilt() {
        let report = ReloadReport::from_body(RELOAD_APPLIED.as_bytes())
            .expect("test: documented reload report decodes");
        assert_eq!(report.status, ReloadStatus::Applied);
        assert_eq!(report.rebuilt, vec!["gateway_turn_runtime".to_owned()]);
    }

    #[test]
    fn reload_needs_success_true_and_a_known_status() {
        assert!(matches!(
            ReloadReport::from_body(br#"{"success":false,"message":"failed"}"#),
            Err(PrxError::Protocol { .. })
        ));
        let unknown = r#"{"success":true,"message":"{\"status\":\"maybe\",\"rebuilt\":[]}"}"#;
        assert!(matches!(
            ReloadReport::from_body(unknown.as_bytes()),
            Err(PrxError::Protocol { .. })
        ));
        let not_json = r#"{"success":true,"message":"reloaded"}"#;
        assert!(matches!(
            ReloadReport::from_body(not_json.as_bytes()),
            Err(PrxError::Protocol { .. })
        ));
    }

    #[test]
    fn reload_refuses_unknown_outer_field() {
        let body = r#"{"success":true,"message":"{}","extra":1}"#;
        assert!(matches!(ReloadReport::from_body(body.as_bytes()), Err(PrxError::Protocol { .. })));
    }

    #[test]
    fn null_targeted_fields_are_refused() {
        let literal =
            r#"{"revision":"HEX","configured":true,"effective":true,"restart_required":false}"#
                .replace("HEX", HEX);
        for pointer in ["/configured", "/effective", "/restart_required", "/revision"] {
            crate::test_support::assert_null_refused(&literal, pointer, TargetedAgents::from_body);
        }
    }

    #[test]
    fn null_reload_success_is_refused() {
        crate::test_support::assert_null_refused(
            RELOAD_APPLIED,
            "/success",
            ReloadReport::from_body,
        );
    }
}
