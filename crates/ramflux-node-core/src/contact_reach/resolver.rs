// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner queries cross only the configured own-federation proxy and retain candidate correlation.
use super::{ReachOwner, ReachService, Result, refuse};
use crate::RouterRedbStore;
use ramflux_protocol::contact_reach::{
    self as wire, Operation, OperationResult, PeerQueryKind, PeerQueryRequest, PeerQueryResponse,
    PeerQueryResult, Reason, Request,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Trusted own-node adapter. Its mutual-TLS federation hop independently verifies public
/// `WebPKI` discovery, the advertised node key and the peer's node-scoped TLS identity.
/// An owner Reply or arbitrary URL must never implement this transport fact.
pub trait ReachPeerResolver: Send + Sync {
    /// # Errors
    /// Refuses exhausted budgets, unconfigured transport and invalid own-service responses.
    fn query(&self, request: &PeerQueryRequest, deadline: Instant) -> Result<PeerQueryResponse>;
}
impl ReachService {
    /// Install the statically configured own-federation adapter, never an owner endpoint.
    #[must_use]
    pub fn with_peer_resolver(mut self, resolver: Arc<dyn ReachPeerResolver>) -> Self {
        self.peer_resolver = Some(resolver);
        self
    }
    pub(super) fn resolve_owner_query(
        &self,
        store: &RouterRedbStore,
        owner: ReachOwner<'_>,
        owner_request: &Request,
        now: u64,
    ) -> Result<OperationResult> {
        let Operation::Query { query } = &owner_request.operation else {
            return Err(refuse(Reason::ForeignInvalidFrame));
        };
        if !wire::enabled() {
            return Err(refuse(Reason::FeatureDisabled));
        }
        if query.source_node != self.node.node_id() {
            return Err(refuse(Reason::AnchorMismatch));
        }
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(owner_request.remaining_ms))
            .ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let resolver =
            self.peer_resolver.as_ref().ok_or_else(|| refuse(Reason::ForeignCapabilityMissing))?;
        let base = store.reach_peer_checkpoint(owner, &query.account_anchor, now)?;
        store.reach_remember_query(owner, query, now)?;
        let remaining_ms = deadline
            .checked_duration_since(Instant::now())
            .and_then(|left| u64::try_from(left.as_millis()).ok())
            .filter(|ms| *ms > 0)
            .ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let request = PeerQueryRequest {
            kind: PeerQueryKind::Query,
            request_id: owner_request.request_id.clone(),
            remaining_ms,
            query: (**query).clone(),
        };
        let response = resolver.query(&request, deadline)?;
        request.validate_response(&response)?;
        let reply = match response.result {
            PeerQueryResult::Query { reply } => reply,
            PeerQueryResult::Error { reason, retry_after_ms, current_revision } => {
                return Ok(OperationResult::Error { reason, retry_after_ms, current_revision });
            }
        };
        // The key below is authenticated by the own-federation adapter, not selected by an
        // owner-provided Reply. This independent full verification supplies account authority.
        let now = now
            .checked_add(started.elapsed().as_secs())
            .ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let peer = ramflux_crypto::contact_reach::verify_peer_reply(
            &reply,
            query,
            &reply.payload.discovery.client.node_public_key,
            base.as_ref(),
            now,
        )?;
        if Instant::now() >= deadline {
            return Err(refuse(Reason::ForeignUnavailable));
        }
        store.reach_remember_verified_reply(owner, query, &peer, now)?;
        Ok(OperationResult::Query { reply })
    }
}
