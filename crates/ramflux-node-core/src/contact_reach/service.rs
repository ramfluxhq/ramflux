// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated owner dispatch. Session/account facts are supplied by the custody service.
use super::{ReachError, ReachOwner, Result, refuse, snapshots::Snapshots};
use crate::{MigrationNode, RouterRedbStore};
use ramflux_protocol::{contact_reach::*, custody::DeviceRef};

pub struct ReachService {
    node: MigrationNode,
    snapshots: Snapshots,
}
impl ReachService {
    /// Construct with configured node authority, never a request-provided signer.
    /// # Errors
    /// Returns private staging-key randomness failures.
    pub fn new(node: MigrationNode) -> Result<Self> {
        Ok(Self { node, snapshots: Snapshots::new()? })
    }

    /// Execute one account-scoped operation and preserve exact session correlation on errors.
    #[must_use]
    pub fn owner(
        &self,
        store: &RouterRedbStore,
        actor: &DeviceRef,
        session: &str,
        generation: u64,
        request: &Request,
        now: u64,
    ) -> Response {
        let result = self
            .owner_inner(store, actor, session, generation, request, now)
            .unwrap_or_else(|e| match e {
                ReachError::Revision(revision) => OperationResult::Error {
                    reason: Reason::ReachRevisionConflict,
                    retry_after_ms: None,
                    current_revision: Some(revision),
                },
                ReachError::Refused(reason) => {
                    OperationResult::Error { reason, retry_after_ms: None, current_revision: None }
                }
                ReachError::Storage(_) => OperationResult::Error {
                    reason: Reason::ForeignStorageUnavailable,
                    retry_after_ms: None,
                    current_revision: None,
                },
                _ => OperationResult::Error {
                    reason: Reason::CustodyRefused,
                    retry_after_ms: None,
                    current_revision: None,
                },
            });
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
        actor: &DeviceRef,
        session: &str,
        generation: u64,
        request: &Request,
        now: u64,
    ) -> Result<OperationResult> {
        request.validate()?;
        if request.session_id != session || request.session_generation != generation {
            return Err(refuse(Reason::ForeignInvalidFrame));
        }
        let root = match &request.operation {
            Operation::Policy { update } => update.body.account_anchor.as_str(),
            Operation::ProfilePublish { update, .. } => update.body.account_anchor.as_str(),
            Operation::Admission { update, .. }
            | Operation::Start { update, .. }
            | Operation::Reply { update, .. } => update.body.recipient_root.as_str(),
            _ => actor.account_anchor.as_str(),
        };
        let owner = ReachOwner { recipient_root: root, actor };
        match &request.operation {
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
                owner,
                session,
                *known_revision,
                snapshot_id.as_deref(),
                *page,
                now,
            ),
            Operation::Cost { request, target_node_id }
                if target_node_id == self.node.node_id() =>
            {
                if request.source_root != actor.account_anchor {
                    return Err(refuse(Reason::ForeignReadRefused));
                }
                Ok(OperationResult::Challenge {
                    challenge: store.reach_issue_cost(&self.node, request, now)?,
                })
            }
            _ => Err(refuse(Reason::ForeignCapabilityMissing)),
        }
    }
}
