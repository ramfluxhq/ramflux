// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An agent may act only while the approving primary and the host desktop are both
//! active devices of the custodian's current record. Lease expiry is not a suspend.

use super::CustodyPublication;
use crate::router_store::agent_host::{AgentHostBinding, AgentRetirement};
use crate::{
    IdentityRegistry, NodeCoreError, RouterCore, RouterRedbStore, RouterSubmitOutcome,
    SessionDescriptor,
};
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

/// Desktop delete of this anchor's stored host device. A sibling agent, or another device of
/// the same headless account, is not this device.
fn retires_own_host(
    prover: &CustodyPublication,
    device: &DeviceRef,
    agent_anchor: &str,
    host: Option<&AgentHostBinding>,
) -> bool {
    host.is_some_and(|row| &row.agent_device == device)
        && is_agent_device(prover, device, agent_anchor)
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

/// Admit `AgentRetire` and store the row.
///
/// The current primary may retire any agent of that owner. An agent device may retire only
/// the stored host device of this same anchor, and only while that agent is still operable.
/// Already retired is success for those callers and does not rewrite the row.
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
    let self_device = retires_own_host(prover, device, agent_anchor, host.as_ref());
    if !primary && !self_device {
        return Err(refused(CustodyRefusal::BindingRefused));
    }
    if retired.is_some() {
        return Ok(host.unwrap_or_else(|| empty_binding(&owner, agent_anchor)));
    }
    let host = host.ok_or_else(|| refused(CustodyRefusal::BindingRefused))?;
    if !primary {
        require_operable(registry, store, agent_anchor, now)?;
    }
    store.record_agent_retirement(
        agent_anchor,
        &AgentRetirement { owner_anchor: owner, retired_by: device.clone(), retired_at: now },
    )?;
    Ok(host)
}

fn account_anchor(target: &str) -> Option<String> {
    ramflux_protocol::parse_qualified_device_id(target).ok().flatten().map(|(anchor, _)| anchor)
}

impl RouterCore {
    /// Whether `anchor` is an agent whose host desktop or approving primary is inactive,
    /// or whose retirement row exists. An account with neither row is not an agent.
    ///
    /// # Errors
    /// Returns an error when the host or retirement row cannot be read.
    pub fn agent_anchor_fenced(
        &self,
        store: &RouterRedbStore,
        anchor: &str,
        now: u64,
    ) -> Result<bool, NodeCoreError> {
        if store.agent_host(anchor)?.is_none() && store.agent_retirement(anchor)?.is_none() {
            return Ok(false);
        }
        match self.require_agent_operable(store, anchor, now) {
            Ok(()) => Ok(false),
            Err(NodeCoreError::Redb(message)) => Err(NodeCoreError::Redb(message)),
            Err(_) => Ok(true),
        }
    }

    /// Whether this envelope is to or from an agent that [`Self::agent_anchor_fenced`] refuses.
    ///
    /// # Errors
    /// Returns an error when an agent row cannot be read.
    pub fn envelope_reaches_fenced_agent(
        &self,
        store: &RouterRedbStore,
        envelope: &ramflux_protocol::Envelope,
        now: u64,
    ) -> Result<bool, NodeCoreError> {
        if let Some(anchor) = account_anchor(&envelope.target_delivery_id)
            && self.agent_anchor_fenced(store, &anchor, now)?
        {
            return Ok(true);
        }
        if let Some(anchor) =
            envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
            && self.agent_anchor_fenced(store, anchor, now)?
        {
            return Ok(true);
        }
        Ok(false)
    }

    /// Shared submit admission. `Some` must not be retried, accepted, or queued.
    ///
    /// `submit_envelope_at` cannot see this store, and an already assigned retry returns
    /// before that call. Callers invoke this first.
    ///
    /// # Errors
    /// Returns an error when an agent row cannot be read. Callers fail closed.
    pub fn fenced_submit_outcome(
        &self,
        store: &RouterRedbStore,
        envelope: &ramflux_protocol::Envelope,
        now: u64,
    ) -> Result<Option<RouterSubmitOutcome>, NodeCoreError> {
        if !self.envelope_reaches_fenced_agent(store, envelope, now)? {
            return Ok(None);
        }
        Ok(Some(RouterSubmitOutcome::RejectedSecurity {
            target_delivery_id: envelope.target_delivery_id.clone(),
            reason: "recipient unreachable".to_owned(),
        }))
    }

    /// Upsert one gateway session. A fenced agent target is refused and left unchanged.
    ///
    /// # Errors
    /// Returns [`NodeCoreError::AgentPublishRefused`] when the target agent is fenced, and
    /// a storage or session error when the upsert cannot be recorded.
    pub fn open_gateway_session(
        &self,
        store: &RouterRedbStore,
        descriptor: SessionDescriptor,
        now: u64,
    ) -> Result<SessionDescriptor, NodeCoreError> {
        let target = descriptor.target_delivery_id.clone();
        if let Some(anchor) = account_anchor(&target)
            && self.agent_anchor_fenced(store, &anchor, now)?
        {
            return Err(NodeCoreError::AgentPublishRefused(CustodyRefusal::AgentRetired));
        }
        self.clear_ephemeral_capability(&target);
        self.upsert_session(descriptor)?;
        self.mark_live(&target)?;
        let session =
            self.session(&target).ok_or_else(|| NodeCoreError::SessionNotFound(target.clone()))?;
        store.record_session_entry(&session)?;
        Ok(session)
    }

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
