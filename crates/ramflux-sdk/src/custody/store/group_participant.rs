// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Hosted-agent admission for group-operation signing.
//!
//! The node fence remains the session and delivery refusal. This check applies the
//! same active-device test as `agent_fence::require_operable` to the custodian
//! record the caller fetched from the current directory. The desktop's stored human
//! file is not that record. A missing host directory is a refusal and is not created.

use super::BornAccount;
use crate::SdkError;
use crate::custody::agent_creation::{
    AgentCreationStore, host_branch_marked, is_retired_agent_account,
};
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::DeviceSetStatus;
use ramflux_protocol::custody::{DeviceRef, decode_register_plan};
use std::path::Path;

pub(super) fn admit(account: &BornAccount, host: Option<&VerifiedRecord>) -> Result<(), SdkError> {
    if !account.hosts_agent_locally()? {
        return Ok(());
    }
    refuse_retired(account)?;
    if host_desktop_marked(account)? {
        return Err(retired());
    }
    host_still_active(account, host.ok_or_else(retired)?)
}

/// Account anchor of the custodian, when this device hosts the agent. `None` for a human.
pub(super) fn hosted_human_anchor(account: &BornAccount) -> Result<Option<String>, SdkError> {
    if !account.hosts_agent_locally()? {
        return Ok(None);
    }
    let root = data_root(account)?;
    let human_id = account.custodian_account_id().ok_or_else(retired)?;
    let plan = publishing_plan(root, human_id, account.local_account_id())?;
    Ok(Some(plan.human_primary.account_anchor))
}

fn refuse_retired(account: &BornAccount) -> Result<(), SdkError> {
    if account
        .stored
        .networking_reason
        .as_ref()
        .is_some_and(crate::AccountNetworkingReason::agent_retired)
    {
        return Err(retired());
    }
    let root = data_root(account)?;
    if is_retired_agent_account(root, account.local_account_id())? {
        return Err(retired());
    }
    Ok(())
}

fn host_desktop_marked(account: &BornAccount) -> Result<bool, SdkError> {
    let Some(human_id) = account.custodian_account_id() else {
        return Ok(false);
    };
    Ok(host_branch_marked(data_root(account)?, human_id))
}

/// Same comparison as `agent_fence::require_operable`: the stored primary must still
/// be the human record's primary, and both that primary and the host desktop must be
/// active devices of the record the caller supplied.
fn host_still_active(account: &BornAccount, human: &VerifiedRecord) -> Result<(), SdkError> {
    let root = data_root(account)?;
    let human_id = account.custodian_account_id().ok_or_else(retired)?;
    let plan = publishing_plan(root, human_id, account.local_account_id())?;
    let body = &human.envelope().body;
    if body.account_anchor != plan.human_primary.account_anchor {
        return Err(retired());
    }
    let current = &body.master_certificate.body.primary_device_ref;
    if &plan.human_primary != current
        || !device_active(human, current)
        || !device_active(human, &plan.desktop)
    {
        return Err(retired());
    }
    Ok(())
}

/// Same active-device test as the node agent fence: the reference belongs to this
/// record, is not revoked, and names an active device that still holds a branch.
fn device_active(human: &VerifiedRecord, reference: &DeviceRef) -> bool {
    let body = &human.envelope().body;
    reference.account_anchor == body.account_anchor
        && !human.revoked_ids().contains(&reference.device_id)
        && body.devices.iter().any(|device| {
            device.device_id == reference.device_id
                && device.device_epoch == reference.device_epoch
                && device.status == DeviceSetStatus::Active
                && device.branch_certificate.is_some()
        })
}

fn publishing_plan(
    root: &Path,
    human_id: &str,
    agent_account: &str,
) -> Result<ramflux_protocol::custody::RegisterPlan, SdkError> {
    crate::custody::valid_id(human_id)?;
    crate::custody::valid_id(agent_account)?;
    let dir = root.join("custody_accounts").join(human_id).join("agent_creation");
    if !dir.is_dir() {
        return Err(retired());
    }
    let store = AgentCreationStore::open(root, human_id)?;
    let record = store.find_by_account(agent_account)?.ok_or_else(retired)?;
    decode_register_plan(&record.plan_bytes()?).map_err(|_| SdkError::CustodySetupInvalid)
}

fn data_root(account: &BornAccount) -> Result<&Path, SdkError> {
    account.networking_path.parent().and_then(Path::parent).ok_or(SdkError::CustodySetupInvalid)
}

fn retired() -> SdkError {
    SdkError::AgentCreationRefused("agent_retired")
}
