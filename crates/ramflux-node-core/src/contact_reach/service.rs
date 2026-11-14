// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated owner dispatch. Session/account facts are supplied by the custody service.
use super::{ReachOwner, Result, refuse, snapshots::Snapshots};
use crate::{MigrationNode, RouterRedbStore};
use ramflux_protocol::{
    contact_reach::{Operation, OperationResult, Reason, Request, Response},
    custody::DeviceRef,
};

/// Identity and generation obtained from the live authenticated stream.
#[derive(Clone, Copy)]
pub struct ReachSession<'a> {
    pub actor: &'a DeviceRef,
    pub id: &'a str,
    pub generation: u64,
}

pub struct ReachService {
    pub(super) node: MigrationNode,
    snapshots: Snapshots,
    pub(super) cost_transport: Option<std::sync::Arc<dyn super::ReachCostTransport>>,
    pub(super) source_submitter: Option<std::sync::Arc<dyn super::submit::ReachSourceSubmitter>>,
    pub(super) peer_resolver: Option<std::sync::Arc<dyn super::resolver::ReachPeerResolver>>,
    pub(super) source_documents: Option<std::sync::Arc<dyn super::source::ReachSourceDocuments>>,
}
impl ReachService {
    /// Construct with configured node authority, never a request-provided signer.
    /// # Errors
    /// Returns private staging-key randomness failures.
    pub fn new(node: MigrationNode) -> Result<Self> {
        Ok(Self {
            node,
            snapshots: Snapshots::new()?,
            source_documents: None,
            cost_transport: None,
            peer_resolver: None,
            source_submitter: None,
        })
    }

    /// Execute one account-scoped operation and preserve exact session correlation on errors.
    #[must_use]
    pub fn owner(
        &self,
        store: &RouterRedbStore,
        session: ReachSession<'_>,
        request: &Request,
        now: u64,
    ) -> Response {
        let result = self
            .owner_inner(store, session, request, now)
            .unwrap_or_else(|error| super::owner_error(&error));
        Response {
            request_id: request.request_id.clone(),
            session_id: request.session_id.clone(),
            session_generation: request.session_generation,
            result,
        }
    }
    fn owner_inner(
        &self,
        store: &RouterRedbStore,
        session: ReachSession<'_>,
        request: &Request,
        now: u64,
    ) -> Result<OperationResult> {
        let ReachSession { actor, id: session, generation } = session;
        request.validate()?;
        if request.session_id != session || request.session_generation != generation {
            return Err(refuse(Reason::ForeignInvalidFrame));
        }
        let root = match &request.operation {
            Operation::GroupRoster { roster, .. } => roster.header.body.recipient_root.as_str(),
            Operation::Policy { update } => update.body.account_anchor.as_str(),
            Operation::ProfilePublish { update, .. } => update.body.account_anchor.as_str(),
            Operation::Admission { update, .. }
            | Operation::Start { update, .. }
            | Operation::Reply { update, .. } => update.body.recipient_root.as_str(),
            _ => actor.account_anchor.as_str(),
        };
        let owner = ReachOwner { recipient_root: root, actor };
        match &request.operation {
            Operation::Query { .. } => self.resolve_owner_query(store, owner, request, now),
            Operation::Submit { .. } => self.submit_owner(store, owner, request, now),
            Operation::GroupRoster { operation_id, roster } => {
                store.reach_group_roster(owner, operation_id, roster, now)
            }
            Operation::UsernameMutate { .. }
            | Operation::UsernameStatus { .. }
            | Operation::UsernameResolve { .. } => Err(refuse(Reason::FeatureDisabled)),
            Operation::ProfilePublish { operation_id, expected_epoch, update } => {
                store.reach_publish_profile(owner, operation_id, *expected_epoch, update, now)
            }
            Operation::Policy { .. }
            | Operation::Admission { .. }
            | Operation::Start { .. }
            | Operation::Reply { .. } => store.reach_owner_commit(owner, &request.operation, now),
            Operation::Strangers { after_seq, limit, ack_seqs } => {
                store.reach_pending_page(owner, *after_seq, *limit, ack_seqs, now)
            }
            Operation::ReachState { known_revision, snapshot_id, page } => self.snapshots.read(
                store,
                &self.node,
                super::snapshots::SnapshotRead {
                    owner,
                    session,
                    known: *known_revision,
                    id: snapshot_id.as_deref(),
                    page: *page,
                    now,
                    proof: None,
                },
            ),
            Operation::ReachProvenance { snapshot_id, proof_hash } => self.snapshots.read(
                store,
                &self.node,
                super::snapshots::SnapshotRead {
                    owner,
                    session,
                    known: 0,
                    id: Some(snapshot_id),
                    page: 0,
                    now,
                    proof: Some(proof_hash),
                },
            ),
            Operation::Cost { .. } => self.cost_owner(store, owner, request, now),
        }
    }
}
