// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The own federation relay enters the same current-source and receiving-home admission barrier.
use super::{ReachClass, ReachForward, ReachService, Result, refuse};
use crate::RouterRedbStore;
use ramflux_protocol::contact_reach::{self as wire, OperationResult, Reason};
use std::time::{Duration, Instant};

impl ReachService {
    /// Receive only after the listener authenticates this node's own federation service.
    /// That service has authenticated the first-hop TLS peer against the unchanged forward.
    /// # Errors
    /// Refuses malformed source/home evidence before admission; storage failures remain uncertain.
    pub fn forward_from_proxy(
        &self,
        store: &RouterRedbStore,
        forward: &ReachForward,
        now: u64,
        received: Instant,
    ) -> Result<OperationResult> {
        if !wire::enabled() {
            return Err(refuse(Reason::FeatureDisabled));
        }
        if forward.target_node_id != self.node.node_id()
            || forward.submission.envelope.delivery_class
                != ramflux_protocol::DeliveryClass::Message
        {
            return Err(refuse(Reason::ReachRouteInvalid));
        }
        let deadline = received
            .checked_add(Duration::from_secs(10))
            .ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let (peer, now, deadline) = self.receiving_source(
            store,
            &forward.source_node_id,
            &forward.submission,
            now,
            deadline,
        )?;
        // The configured own proxy attests the first hop. No caller-selected peer field exists.
        let identity = crate::parse_mesh_spiffe_uri(&format!(
            "spiffe://{}/ramflux-federation",
            forward.source_node_id,
        ))?;
        forward.verify(&identity, &peer, self.node.node_id(), now)?;
        self.admit_received(store, &forward.submission, &peer, now, deadline)
    }

    pub(super) fn receive_local_submission(
        &self,
        store: &RouterRedbStore,
        submission: &wire::Submission,
        now: u64,
        deadline: Instant,
    ) -> OperationResult {
        let result = (|| {
            let (peer, now, deadline) =
                self.receiving_source(store, self.node.node_id(), submission, now, deadline)?;
            self.admit_received(store, submission, &peer, now, deadline)
        })();
        result.unwrap_or_else(|error| receiving_error(&submission.envelope.envelope_id, &error))
    }

    fn receiving_source(
        &self,
        store: &RouterRedbStore,
        source_node: &str,
        submission: &wire::Submission,
        now: u64,
        deadline: Instant,
    ) -> Result<(ramflux_crypto::contact_reach::VerifiedPeer, u64, Instant)> {
        let started = Instant::now();
        let now = store.reach_fenced_now(now)?;
        let source = &submission.route.body.source.account_anchor;
        let recipient = &submission.route.body.recipient_root;
        let base = store.ingress_peer_checkpoint(&self.node, recipient, source, now)?;
        let nonce = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        let base_selector = base
            .as_ref()
            .map(|evidence| {
                ramflux_protocol::home_migration::record_hash(&evidence.record)
                    .map(|hash| wire::HomeBase { epoch: evidence.record.epoch(), hash })
            })
            .transpose()?;
        let query = wire::PeerQueryRequest {
            kind: wire::PeerQueryKind::Query,
            request_id: nonce.clone(),
            remaining_ms: remaining(deadline)?,
            query: wire::Query {
                version: 1,
                source_node: self.node.node_id().into(),
                target_node: source_node.into(),
                account_anchor: source.clone(),
                card_hash: None,
                nonce,
                base: base_selector,
                device_ref: None,
            },
        };
        let resolver =
            self.peer_resolver.as_ref().ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let response = resolver.query(&query, deadline)?;
        query.validate_response(&response)?;
        let wire::PeerQueryResult::Query { reply } = response.result else {
            return Err(refuse(Reason::ForeignPolicyDenied));
        };
        let now = store.reach_fenced_now(
            now.checked_add(started.elapsed().as_secs())
                .ok_or_else(|| refuse(Reason::ForeignUnavailable))?,
        )?;
        let peer = ramflux_crypto::contact_reach::verify_peer_reply(
            &reply,
            &query.query,
            &reply.payload.discovery.client.node_public_key,
            base.as_ref(),
            now,
        )?;
        if source_node == self.node.node_id() && peer.node_key() != self.node.public_key() {
            return Err(refuse(Reason::ForeignPolicyDenied));
        }
        remaining(deadline)?;
        Ok((peer, now, deadline))
    }

    fn admit_received(
        &self,
        store: &RouterRedbStore,
        submission: &wire::Submission,
        peer: &ramflux_crypto::contact_reach::VerifiedPeer,
        now: u64,
        deadline: Instant,
    ) -> Result<OperationResult> {
        remaining(deadline)?;
        let admitted = store.reach_admit(&self.node, peer, submission, now)?;
        Ok(staged_result(&submission.envelope.envelope_id, &admitted))
    }
}
fn remaining(deadline: Instant) -> Result<u64> {
    deadline
        .checked_duration_since(Instant::now())
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .filter(|left| (1..=10_000).contains(left))
        .ok_or_else(|| refuse(Reason::ForeignUnavailable))
}
fn staged_result(envelope_id: &str, admitted: &super::ReachIngress) -> OperationResult {
    // Accepted entries await ordinary publication. A staging commit alone cannot acknowledge it,
    // including on duplicate retries. Unsolicited entries use the dedicated Strangers transfer.
    let outcome = if admitted.class != ReachClass::Unsolicited {
        wire::SubmitOutcome::Unknown
    } else if admitted.duplicate {
        wire::SubmitOutcome::Duplicate
    } else {
        match admitted.placement {
            wire::Placement::Direct => wire::SubmitOutcome::Submitted,
            wire::Placement::Strangers => wire::SubmitOutcome::Quarantined,
        }
    };
    OperationResult::Submit { envelope_id: envelope_id.into(), outcome, reason: None }
}

/// Preserve closed receiving results without claiming definite non-admission on storage faults.
pub(crate) fn proxy_error(forward: &ReachForward, error: &super::ReachError) -> OperationResult {
    receiving_error(&forward.submission.envelope.envelope_id, error)
}
fn receiving_error(envelope_id: &str, error: &super::ReachError) -> OperationResult {
    let envelope_id = envelope_id.to_owned();
    if matches!(error, super::ReachError::Storage(_)) {
        return OperationResult::Submit {
            envelope_id,
            outcome: wire::SubmitOutcome::Unknown,
            reason: None,
        };
    }
    let reason = match error {
        super::ReachError::Refused(reason) => *reason,
        _ => Reason::ForeignReadRefused,
    };
    let refused = OperationResult::Submit {
        envelope_id: envelope_id.clone(),
        outcome: wire::SubmitOutcome::Refused,
        reason: Some(reason),
    };
    if wire::validate_receiving_result(&refused).is_ok() {
        return refused;
    }
    let error = OperationResult::Error {
        reason,
        retry_after_ms: (reason == Reason::ForeignRateLimited).then_some(1000),
        current_revision: None,
    };
    if wire::validate_receiving_result(&error).is_ok() {
        return error;
    }
    OperationResult::Submit {
        envelope_id,
        outcome: wire::SubmitOutcome::Refused,
        reason: Some(Reason::ForeignReadRefused),
    }
}

#[cfg(test)]
mod tests;
