// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Completed approvals cannot reuse a single-use grant identity after the pending queue empties.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, atomic::AtomicBool};
#[test]
fn completed_approval_ids_are_not_reused_for_new_single_use_grants() -> Result<(), SdkError> {
    let root = runtime_tests::root("mcp-approval-identity");
    let mut account =
        runtime_tests::account(&root, "human", None, Arc::new(AtomicBool::new(false)))?;
    let manifest = McpToolManifest {
        server_id: "shell".into(),
        tool_name: "run".into(),
        capability: McpCapability::RunShell,
        tool_scope: None,
        declared_risk: RiskLevel::High,
        manifest_version: 1,
    };
    let first = mcp_create_approval(
        &mut account,
        &manifest,
        false,
        None,
        false,
        &serde_json::json!({"command":"echo first"}),
    )?;
    account.mcp_pending_approvals.clear();
    let second = mcp_create_approval(
        &mut account,
        &manifest,
        false,
        None,
        false,
        &serde_json::json!({"command":"echo second"}),
    )?;
    assert_ne!(first.approval_id, second.approval_id);
    assert_ne!(
        mcp_grant_signing_body(&account, &first)?.grant_id,
        mcp_grant_signing_body(&account, &second)?.grant_id
    );
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
