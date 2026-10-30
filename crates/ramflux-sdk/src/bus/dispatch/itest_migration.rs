// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Request-bound migration approval for Linux integration fixtures.

use crate::prelude::*;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveOnce {
    account: String,
    request_id: String,
}

pub(crate) fn approve_once(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: ApproveOnce = serde_json::from_value(request.body.clone())?;
    if request.account_id.as_deref() != Some(body.account.as_str())
        || !valid_account(&body.account)
        || !valid_request_id(&body.request_id)
    {
        return Err(SdkError::CustodySetupInvalid);
    }
    let vault = state.config.custody_vault.as_ref().ok_or_else(unavailable)?;
    vault.approve_migration_once_for_test(&body.account, &body.request_id)?;
    Ok(local_bus_ok(serde_json::json!({
        "account": body.account,
        "request_id": body.request_id,
        "approved_once": true,
    })))
}

fn valid_account(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

fn valid_request_id(value: &str) -> bool {
    ramflux_protocol::decode_base64url(value)
        .is_ok_and(|bytes| bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == value)
}

fn unavailable() -> SdkError {
    SdkError::LocalBusRefused {
        code: "MigrationApprovalUnavailable".into(),
        message: "migration fixture approval requires daemon opt-in".into(),
        body: Box::new(serde_json::json!({
            "reason_code": "migration_approval_unavailable"
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

    fn request(request_id: &str) -> LocalBusFrame {
        LocalBusFrame::request(
            "approve",
            Some("human".into()),
            "itest",
            "itest.migration.approve_once",
            serde_json::json!({
                "account": "human",
                "request_id": request_id,
            }),
        )
    }

    #[test]
    fn approve_once_requires_daemon_opt_in_and_refuses_every_second_arm_with_a_typed_error()
    -> Result<(), SdkError> {
        let id = ramflux_protocol::encode_base64url([1; 32]);
        assert!(matches!(
            approve_once(&request(&id), &state(None)),
            Err(SdkError::LocalBusRefused { code, .. }) if code == "MigrationApprovalUnavailable"
        ));
        let vault = std::sync::Arc::new(crate::custody::MemoryPrimaryVault::default());
        let daemon = state(Some(vault));
        assert_eq!(approve_once(&request(&id), &daemon)?.response_body["approved_once"], true);
        for next in [&id, &ramflux_protocol::encode_base64url([2; 32])] {
            assert!(matches!(
                approve_once(&request(next), &daemon),
                Err(SdkError::LocalBusRefused { code, .. })
                    if code == "MigrationApprovalAlreadyArmed"
            ));
        }
        Ok(())
    }
}
