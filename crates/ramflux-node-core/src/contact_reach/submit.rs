// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner submissions cross the configured source federation service without changing sealed bytes.
use super::{ReachOwner, ReachService, Result, refuse, store};
use crate::RouterRedbStore;
use ramflux_protocol::contact_reach::{
    self as wire, Operation, OperationResult, Reason, Request, SourceSubmitKind,
    SourceSubmitRequest, SourceSubmitResponse,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Own-node transport, statically configured and authenticated as the federation service.
pub trait ReachSourceSubmitter: Send + Sync {
    /// Send the complete frozen submission through the internal foreign Submit carrier.
    /// # Errors
    /// Once dispatch starts, a transport/decode failure leaves the outcome unknown.
    fn submit(
        &self,
        request: &SourceSubmitRequest,
        deadline: Instant,
    ) -> Result<SourceSubmitResponse>;
}

impl ReachService {
    /// Configure this node's authenticated federation Submit adapter.
    #[must_use]
    pub fn with_source_submitter(mut self, submitter: Arc<dyn ReachSourceSubmitter>) -> Self {
        self.source_submitter = Some(submitter);
        self
    }

    pub(super) fn submit_owner(
        &self,
        store: &RouterRedbStore,
        owner: ReachOwner<'_>,
        request: &Request,
        now: u64,
    ) -> Result<OperationResult> {
        let Operation::Submit { target_node_id, submission } = &request.operation else {
            return Err(refuse(Reason::ForeignInvalidFrame));
        };
        if !wire::enabled() {
            return Err(refuse(Reason::FeatureDisabled));
        }
        if submission.envelope.delivery_class == ramflux_protocol::DeliveryClass::CallWake {
            return Err(refuse(Reason::ForeignCapabilityMissing));
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(request.remaining_ms))
            .ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let submitter =
            self.source_submitter.as_ref().ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let mut call = SourceSubmitRequest {
            kind: SourceSubmitKind::Submit,
            request_id: request.request_id.clone(),
            remaining_ms: request.remaining_ms,
            target_node_id: target_node_id.clone(),
            submission: *submission.clone(),
        };
        call.validate()?;
        crate::check_reach_entry_bound(submission)?;
        // No writer or account lock survives the network call. Verify the current local source,
        // including its original branch signature; an authenticated session alone is insufficient.
        {
            let (tx, now) = store.begin_reach_write(now)?;
            let source = &submission.route.body.source.account_anchor;
            if source != owner.recipient_root || source != &owner.actor.account_anchor {
                return Err(refuse(Reason::ForeignReadRefused));
            }
            let authority = store::authority(&tx, source, now)?;
            authority.authorize(owner.actor, "message", now)?;
            if store::home(&tx, source)?.record.home()
                != (self.node.node_id(), self.node.public_key())
            {
                return Err(refuse(Reason::ForeignReadRefused));
            }
            ramflux_crypto::contact_reach::verify_current_source_submission(
                submission, &authority, now,
            )?;
            let state = store::load(&tx, source)?;
            if matches!(
                submission.route.body.traffic,
                wire::Traffic::Dm
                    | wire::Traffic::ReceiptDelivered
                    | wire::Traffic::ReceiptRead
                    | wire::Traffic::Typing
            ) {
                store::provenance::require_ready(store, &tx, source, &state, now)?;
            }
            require_return_grant(&state, &submission.route.body, &authority, target_node_id, now)?;
            tx.commit()?;
        }
        call.remaining_ms = deadline
            .checked_duration_since(Instant::now())
            .and_then(|left| u64::try_from(left.as_millis()).ok())
            .filter(|ms| (1..=10_000).contains(ms))
            .ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        // The call may already have reached admission. Never convert an ambiguous transport
        // failure into an Error claiming that no forwarding took place.
        Ok(submitter
            .submit(&call, deadline)
            .map_or_else(|_| call.unknown_result(), |reply| call.owner_result(reply)))
    }
}

/// A source's open policy is not the explicit return grant required before starting a DM.
/// This is local authorization only; it cannot confer permission at the destination home.
pub(in crate::contact_reach) fn require_return_grant(
    state: &super::AccountReach,
    route: &wire::Route,
    authority: &ramflux_crypto::custody::VerifiedRecord,
    target_node: &str,
    now: u64,
) -> Result<()> {
    use wire::{StateRecord, Subject, Traffic};
    if !matches!(
        route.traffic,
        Traffic::Dm | Traffic::ReceiptDelivered | Traffic::ReceiptRead | Traffic::Typing
    ) {
        return Ok(());
    }
    if route.source.account_anchor != authority.envelope().body.account_anchor {
        return Err(refuse(Reason::ForeignReadRefused));
    }
    state.check_denials(&route.recipient_root, target_node, now)?;
    if !state.conflicts.is_empty() {
        return Err(refuse(Reason::ReachRevisionConflict));
    }
    ramflux_crypto::contact_reach::verify_retained_policy(
        state.policy.as_ref().ok_or_else(|| refuse(Reason::ReachPolicyRequired))?,
        authority,
        now,
    )?;
    let friendship = Subject::Friendship { root: route.recipient_root.clone() }.key()?;
    let conversation = Subject::Conversation {
        root: route.recipient_root.clone(),
        conversation_id: route.conversation_id.clone(),
    }
    .key()?;
    if state.blocks.contains_key(&conversation) {
        return Err(refuse(Reason::ForeignReadRefused));
    }
    for key in [&friendship, &conversation] {
        let Some(StateRecord::Grant { permissions, grant_until, update, .. }) =
            state.grants.get(key)
        else {
            continue;
        };
        if *grant_until != 0 && *grant_until <= now {
            continue;
        }
        ramflux_crypto::contact_reach::verify_retained_admission(update, authority, now)?;
        let allowed = match route.traffic {
            Traffic::Dm => true,
            Traffic::ReceiptDelivered => permissions.user_delivered,
            Traffic::ReceiptRead => permissions.read,
            Traffic::Typing => permissions.typing,
            _ => false,
        };
        return if allowed { Ok(()) } else { Err(refuse(Reason::ForeignReadRefused)) };
    }
    Err(refuse(Reason::ForeignReadRefused))
}
