// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-session cost authorization ends before the configured federation RPC begins.
use super::{ReachOwner, ReachService, Result, refuse, store};
use crate::RouterRedbStore;
use ramflux_protocol::contact_reach::{self as wire, Operation, OperationResult, Reason, Request};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub trait ReachCostTransport: Send + Sync {
    /// Call the statically configured own federation service, never a requester-supplied URL.
    /// # Errors
    /// Returns transport, deadline, closed-result or correlation failures.
    fn cost(
        &self,
        request: &wire::SourceCostRequest,
        deadline: Instant,
    ) -> Result<wire::SourceCostResponse>;
}
impl ReachService {
    #[must_use]
    pub fn with_cost_transport(mut self, transport: Arc<dyn ReachCostTransport>) -> Self {
        self.cost_transport = Some(transport);
        self
    }
    pub(super) fn cost_owner(
        &self,
        store: &RouterRedbStore,
        owner: ReachOwner<'_>,
        request: &Request,
        now: u64,
    ) -> Result<OperationResult> {
        let Operation::Cost { request: challenge, target_node_id } = &request.operation else {
            return Err(refuse(Reason::ForeignInvalidFrame));
        };
        if !wire::enabled() {
            return Err(refuse(Reason::FeatureDisabled));
        }
        if challenge.source_root != owner.actor.account_anchor {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(request.remaining_ms))
            .ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        {
            let (tx, now) = store.begin_reach_write(now)?;
            let authority = store::authority(&tx, &challenge.source_root, now)?;
            authority.authorize(owner.actor, "message", now)?;
            if store::home(&tx, &challenge.source_root)?.record.home()
                != (self.node.node_id(), self.node.public_key())
            {
                return Err(refuse(Reason::ForeignReadRefused));
            }
            tx.commit()?;
        }
        remaining(deadline)?;
        if target_node_id == self.node.node_id() {
            return Ok(OperationResult::Challenge {
                challenge: store.reach_issue_cost(
                    &self.node,
                    &super::CostIssuerPeer::local(self.node.node_id()),
                    challenge,
                    now,
                )?,
            });
        }
        let transport =
            self.cost_transport.as_ref().ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let call = wire::SourceCostRequest {
            kind: wire::SourceCostKind::Cost,
            request_id: request.request_id.clone(),
            remaining_ms: remaining(deadline)?,
            target_node_id: target_node_id.clone(),
            request: challenge.clone(),
        };
        call.validate()?;
        let response = transport.cost(&call, deadline).map_err(|error| match error {
            super::ReachError::Refused(reason) if wire::cost_error_reason(reason) => refuse(reason),
            _ => refuse(Reason::ForeignUnavailable),
        })?;
        call.validate_response(&response).map_err(|_| refuse(Reason::ForeignUnavailable))?;
        Ok(response.result)
    }

    pub(crate) fn issue_cost_from_proxy(
        &self,
        store: &RouterRedbStore,
        request: &wire::CostRequest,
        now: u64,
    ) -> Result<OperationResult> {
        request.validate()?;
        if !wire::enabled() {
            return Err(refuse(Reason::FeatureDisabled));
        }
        Ok(OperationResult::Challenge {
            challenge: store.reach_issue_cost(
                &self.node,
                &super::CostIssuerPeer::budgeted_proxy(self.node.node_id()),
                &request.request,
                now,
            )?,
        })
    }
}
fn remaining(deadline: Instant) -> Result<u64> {
    deadline
        .checked_duration_since(Instant::now())
        .and_then(|left| u64::try_from(left.as_millis()).ok())
        .filter(|ms| (1..=10_000).contains(ms))
        .ok_or_else(|| refuse(Reason::ForeignUnavailable))
}
