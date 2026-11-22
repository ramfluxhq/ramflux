// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An agent may act only while the approving primary and the host desktop are both
//! active devices of the custodian's current record. Lease expiry is not a suspend.

use super::CustodyPublication;
use crate::router_store::agent_host::{AgentHostBinding, AgentRetirement};
use crate::{IdentityRegistry, NodeCoreError, RouterCore, RouterRedbStore};
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::custody::{CustodyRefusal, DeviceRef};
use ramflux_protocol::{DeviceSetStatus, PrincipalKind};

fn refused(code: CustodyRefusal) -> NodeCoreError {
    NodeCoreError::AgentPublishRefused(code)
}

fn device_active(record: &VerifiedRecord, reference: &DeviceRef) -> bool {
    let body = &record.envelope().body;
    if reference.account_anchor != body.account_anchor
        || record.revoked_ids().contains(&reference.device_id)
    {
        return false;
    }
    body.devices.iter().any(|device| {
        device.device_id == reference.device_id
            && device.device_epoch == reference.device_epoch
            && device.status == DeviceSetStatus::Active
            && device.branch_certificate.is_some()
    })
}

fn current_human(
    registry: &IdentityRegistry,
    owner: &str,
    now: u64,
) -> Result<VerifiedRecord, NodeCoreError> {
    let stored =
        registry.custody.records.get(owner).ok_or_else(|| refused(CustodyRefusal::AgentRetired))?;
    let verified =
        registry.verify_custody(stored, now).map_err(|_| refused(CustodyRefusal::AgentRetired))?;
    registry
        .custody
        .require_current(&verified)
        .map_err(|_| refused(CustodyRefusal::AgentRetired))?;
    Ok(verified)
}

/// Headless publish, register, open and session use. A retirement row or a missing
/// host row refuses. The stored primary must still be the human record's primary.
pub(super) fn require_operable(
    registry: &IdentityRegistry,
    store: &RouterRedbStore,
    agent_anchor: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if store.agent_retirement(agent_anchor)?.is_some() {
        return Err(refused(CustodyRefusal::AgentRetired));
    }
    let Some(binding) = store.agent_host(agent_anchor)? else {
        return Err(refused(CustodyRefusal::AgentRetired));
    };
    let human = current_human(registry, &binding.owner_anchor, now)?;
    let primary = &human.envelope().body.master_certificate.body.primary_device_ref;
    if &binding.primary != primary
        || !device_active(&human, primary)
        || !device_active(&human, &binding.desktop)
    {
        return Err(refused(CustodyRefusal::AgentRetired));
    }
    Ok(())
}

fn is_current_primary(
    registry: &IdentityRegistry,
    owner: &str,
    device: &DeviceRef,
    now: u64,
) -> Result<bool, NodeCoreError> {
    let human = match current_human(registry, owner, now) {
        Ok(human) => human,
        Err(NodeCoreError::AgentPublishRefused(CustodyRefusal::AgentRetired)) => return Ok(false),
        Err(error) => return Err(error),
    };
    let primary = &human.envelope().body.master_certificate.body.primary_device_ref;
    Ok(device == primary && device_active(&human, primary))
}

fn is_agent_device(prover: &CustodyPublication, device: &DeviceRef, agent_anchor: &str) -> bool {
    let body = &prover.record.body;
    body.principal_kind == PrincipalKind::HeadlessAi
        && body.account_anchor == agent_anchor
        && device.account_anchor == agent_anchor
        && body.devices.iter().any(|entry| {
            entry.device_id == device.device_id && entry.device_epoch == device.device_epoch
        })
}

fn empty_binding(owner: &str, agent_anchor: &str) -> AgentHostBinding {
    let blank = |account: &str| DeviceRef {
        account_anchor: account.to_owned(),
        device_id: String::new(),
        device_epoch: 0,
    };
    AgentHostBinding {
        owner_anchor: owner.to_owned(),
        desktop: blank(owner),
        primary: blank(owner),
        agent_device: blank(agent_anchor),
    }
}

fn owner_of(
    host: Option<&AgentHostBinding>,
    retired: Option<&AgentRetirement>,
) -> Result<String, NodeCoreError> {
    host.map(|row| row.owner_anchor.clone())
        .or_else(|| retired.map(|row| row.owner_anchor.clone()))
        .ok_or_else(|| refused(CustodyRefusal::BindingRefused))
}

/// Admit `AgentRetire` and store the row. Already retired is success for the same callers.
pub(super) fn retire_agent(
    registry: &IdentityRegistry,
    store: &RouterRedbStore,
    prover: &CustodyPublication,
    device: &DeviceRef,
    agent_anchor: &str,
    now: u64,
) -> Result<AgentHostBinding, NodeCoreError> {
    let host = store.agent_host(agent_anchor)?;
    let retired = store.agent_retirement(agent_anchor)?;
    let owner = owner_of(host.as_ref(), retired.as_ref())?;
    let primary = is_current_primary(registry, &owner, device, now)?;
    let agent = is_agent_device(prover, device, agent_anchor);
    if retired.is_some() {
        if primary || agent {
            return Ok(host.unwrap_or_else(|| empty_binding(&owner, agent_anchor)));
        }
        return Err(refused(CustodyRefusal::BindingRefused));
    }
    let host = host.ok_or_else(|| refused(CustodyRefusal::BindingRefused))?;
    let allowed = if primary {
        true
    } else if agent {
        require_operable(registry, store, agent_anchor, now)?;
        true
    } else {
        false
    };
    if !allowed {
        return Err(refused(CustodyRefusal::BindingRefused));
    }
    store.record_agent_retirement(
        agent_anchor,
        &AgentRetirement { owner_anchor: owner, retired_by: device.clone(), retired_at: now },
    )?;
    Ok(host)
}

impl RouterCore {
    pub(crate) fn require_agent_operable(
        &self,
        store: &RouterRedbStore,
        agent_anchor: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        require_operable(&control.mvp1_identities, store, agent_anchor, now)
    }

    pub(crate) fn admit_agent_retire(
        &self,
        store: &RouterRedbStore,
        prover: &CustodyPublication,
        device: &DeviceRef,
        agent_anchor: &str,
        now: u64,
    ) -> Result<AgentHostBinding, NodeCoreError> {
        let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        retire_agent(&control.mvp1_identities, store, prover, device, agent_anchor, now)
    }
}
