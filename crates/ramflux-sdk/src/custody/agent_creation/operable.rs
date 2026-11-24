// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local operability of an agent account.
//!
//! This is the daemon-side mirror of `RouterCore::require_agent_operable`
//! (`custody_authority/agent_fence.rs` `require_operable`). The daemon has no
//! router store. Both checks refuse with the single token `agent_retired`:
//! a retirement row, or a host desktop / approving primary that is no longer
//! an active device. A human account is not an agent and passes.

use crate::SdkError;
use std::path::Path;

/// Refuse a new local operation from an agent that is retired, or whose
/// custodian has acknowledged that this host branch is revoked.
///
/// A human account (no custodian pointer and no retired creation record)
/// returns `Ok(())`. Nothing is written.
///
/// # Errors
/// `AgentCreationRefused("agent_retired")` when the agent must not publish.
/// Store and id errors pass through.
pub(crate) fn require_agent_operable(root: &Path, account_id: &str) -> Result<(), SdkError> {
    if super::delete::is_retired_agent_account(root, account_id)? {
        return Err(SdkError::AgentCreationRefused("agent_retired"));
    }
    let Some(custodian) = crate::custody::stored_custodian_id(root, account_id)? else {
        return Ok(());
    };
    if super::host_revoked::host_branch_marked(root, &custodian) {
        return Err(SdkError::AgentCreationRefused("agent_retired"));
    }
    Ok(())
}
