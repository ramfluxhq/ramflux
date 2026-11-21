// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Plan-bound agent decision approval for Linux integration fixtures (AGENT-IDENTITY-01 C3c).

use crate::prelude::*;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveOnce {
    plan_hash: String,
}

pub(crate) fn approve_once(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: ApproveOnce = serde_json::from_value(request.body.clone())?;
    if !valid_hash(&body.plan_hash) {
        return Err(SdkError::CustodySetupInvalid);
    }
    let vault = state.config.custody_vault.as_ref().ok_or_else(unavailable)?;
    vault.approve_agent_decision_once_for_test(&body.plan_hash)?;
    Ok(local_bus_ok(serde_json::json!({
        "plan_hash": body.plan_hash,
        "approved_once": true,
    })))
}

fn valid_hash(value: &str) -> bool {
    ramflux_protocol::decode_base64url(value)
        .is_ok_and(|bytes| bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == value)
}

fn unavailable() -> SdkError {
    SdkError::LocalBusRefused {
        code: "AgentApprovalUnavailable".into(),
        message: "agent approval fixture requires daemon opt-in".into(),
        body: Box::new(serde_json::json!({
            "reason_code": "agent_approval_unavailable"
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(
        vault: Option<std::sync::Arc<crate::custody::MemoryPrimaryVault>>,
    ) -> LocalBusDaemonState {
        let mut config = LocalBusConfig::new("bus.sock", "data");
        config.custody_vault = vault
            .map(|vault| vault as std::sync::Arc<dyn crate::custody::PrimaryVault + Send + Sync>);
        LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            config,
            accounts: BTreeMap::new(),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        }
    }

    fn request(plan_hash: &str) -> LocalBusFrame {
        LocalBusFrame::request(
            "approve",
            None,
            "itest",
            "itest.agent.approve_once",
            serde_json::json!({ "plan_hash": plan_hash }),
        )
    }

    #[test]
    fn approve_once_requires_daemon_opt_in_and_refuses_a_second_arm() -> Result<(), SdkError> {
        let hash = ramflux_protocol::encode_base64url([1; 32]);
        assert!(matches!(
            approve_once(&request(&hash), &state(None)),
            Err(SdkError::LocalBusRefused { code, .. }) if code == "AgentApprovalUnavailable"
        ));
        let vault = std::sync::Arc::new(crate::custody::MemoryPrimaryVault::default());
        let daemon = state(Some(vault));
        assert_eq!(approve_once(&request(&hash), &daemon)?.response_body["approved_once"], true);
        let second = ramflux_protocol::encode_base64url([2; 32]);
        assert!(
            matches!(
                approve_once(&request(&second), &daemon),
                Err(SdkError::LocalBusRefused { code, .. }) if code == "AgentDecisionApprovalAlreadyArmed"
            ),
            "a second plan hash cannot be armed while one approval is pending"
        );
        assert!(
            matches!(
                approve_once(&request(&hash), &daemon),
                Err(SdkError::LocalBusRefused { code, .. }) if code == "AgentDecisionApprovalAlreadyArmed"
                    || code == "AgentDecisionApprovalConsumed"
            ),
            "the same plan hash cannot be armed twice"
        );
        assert!(
            approve_once(&request("not-a-hash"), &daemon).is_err(),
            "a malformed plan hash is refused before the vault"
        );
        Ok(())
    }
}
