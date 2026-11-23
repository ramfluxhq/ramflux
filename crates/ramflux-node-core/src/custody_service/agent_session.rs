// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Close an agent's custody leases and router sessions when its host fence fails.
//! The router session is marked closed so the gateway drops that live channel, and
//! later submits to or from the agent are refused as unreachable.

use super::CustodyService;
use crate::{CustodyPublication, NodeCoreError, RouterCore, RouterRedbStore};
use ramflux_protocol::PrincipalKind;
use ramflux_protocol::custody::{CustodyRefusal, CustodyServerFrame, CustodySession, DeviceRef};

fn refusal_of(error: NodeCoreError) -> CustodyRefusal {
    match error {
        NodeCoreError::AgentPublishRefused(code) => code,
        NodeCoreError::Redb(_) => CustodyRefusal::PersistenceUnavailable,
        _ => CustodyRefusal::AgentRetired,
    }
}

pub(super) struct FenceCall<'a> {
    pub router: &'a RouterCore,
    pub store: &'a RouterRedbStore,
    pub now: u64,
}

pub(super) fn guard_headless(
    call: &FenceCall<'_>,
    publication: &CustodyPublication,
) -> Result<(), super::ProofFailure> {
    if publication.record.body.principal_kind != PrincipalKind::HeadlessAi {
        return Ok(());
    }
    call.router
        .require_agent_operable(call.store, &publication.record.body.account_anchor, call.now)
        .map_err(super::publication_failure)?;
    Ok(())
}

impl CustodyService {
    pub(super) fn finish_agent_retire(
        &self,
        call: &FenceCall<'_>,
        prover: &CustodyPublication,
        device: &DeviceRef,
        agent_anchor: &str,
    ) -> Result<CustodyServerFrame, super::ProofFailure> {
        let host = call
            .router
            .admit_agent_retire(call.store, prover, device, agent_anchor, call.now)
            .map_err(super::publication_failure)?;
        self.close_agent_account(call.router, agent_anchor, &host.agent_device, call.now);
        Ok(CustodyServerFrame::AgentRetired { agent_anchor: agent_anchor.to_owned() })
    }

    /// After a human publication, close agents of that owner whose fence no longer passes.
    pub(super) fn suspend_owner_agents(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        owner: &str,
        now: u64,
    ) -> Result<(), super::ProofFailure> {
        let hosts = store
            .agent_hosts_of(owner)
            .map_err(|error| -> super::ProofFailure { super::persistence(error).into() })?;
        for (anchor, host) in hosts {
            match router.require_agent_operable(store, &anchor, now) {
                Ok(()) => {}
                Err(NodeCoreError::Redb(message)) => {
                    return Err(super::ProofFailure::from(super::persistence(message)));
                }
                Err(_) => self.close_agent_account(router, &anchor, &host.agent_device, now),
            }
        }
        Ok(())
    }

    /// A headless session whose fence has failed is closed, then refused.
    pub(super) fn refuse_suspended_session(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        session: &CustodySession,
        publication: &CustodyPublication,
        now: u64,
    ) -> Result<(), CustodyRefusal> {
        if publication.record.body.principal_kind != PrincipalKind::HeadlessAi {
            return Ok(());
        }
        let anchor = &session.device_ref.account_anchor;
        match router.require_agent_operable(store, anchor, now) {
            Ok(()) => Ok(()),
            Err(error) => {
                let code = refusal_of(error);
                if code == CustodyRefusal::AgentRetired {
                    self.close_agent_account(router, anchor, &session.device_ref, now);
                }
                Err(code)
            }
        }
    }

    fn close_agent_account(
        &self,
        router: &RouterCore,
        anchor: &str,
        fallback: &DeviceRef,
        now: u64,
    ) {
        self.leases().close_account(anchor);
        let loaded = router.custody_record(anchor, now).ok().flatten();
        let mut closed = false;
        if let Some(publication) = loaded.as_ref() {
            for device in &publication.record.body.devices {
                let Ok(id) = ramflux_protocol::qualified_device_id(anchor, &device.device_id)
                else {
                    continue;
                };
                let _ = router.close_session(&id);
                closed = true;
            }
        }
        if closed || fallback.device_id.is_empty() {
            return;
        }
        if let Ok(id) =
            ramflux_protocol::qualified_device_id(&fallback.account_anchor, &fallback.device_id)
        {
            let _ = router.close_session(&id);
        }
    }
}
