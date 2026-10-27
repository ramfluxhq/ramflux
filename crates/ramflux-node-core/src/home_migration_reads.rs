// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private status checks current-home authority; public history never imports registry state.
use crate::{
    HomeMigrationService, MigrationPeerCall, MigrationPeerReply, MigrationRole, NodeCoreError,
    home_migration_reply::MigrationReply, home_migration_service::MigrationExecution,
};
use ramflux_crypto::home_migration as crypto;
use ramflux_protocol::home_migration::{
    Action, ActionPayload, HomeRecord, Refusal, Request, ResolvePayload, ResolveResult, Response,
    SKEW_SECONDS, record_hash,
};
fn failure(reason: Refusal) -> NodeCoreError {
    NodeCoreError::HomeMigration(reason)
}
fn wire(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
impl HomeMigrationService {
    pub(crate) fn execute_read(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
    ) -> Result<Option<Response>, NodeCoreError> {
        match &request.payload {
            ActionPayload::Resolve(payload) => {
                self.node.charge_migration_read(
                    &request.control.body.requester.account_anchor,
                    scope.now,
                )?;
                let result = self.latest_migration_home(
                    scope.store,
                    payload,
                    &request.control.body.migration_id,
                    scope.now,
                )?;
                MigrationReply { resolve_result: Some(result), ..MigrationReply::default() }
                    .sign(&self.node, &request.control, None, scope.now)
                    .map(Some)
            }
            ActionPayload::Operation(_) if request.control.body.action == Action::Status => {
                self.require_current_status_owner(scope, request)?;
                self.node.charge_migration_read(
                    &request.control.body.requester.account_anchor,
                    scope.now,
                )?;
                self.status_reply(scope, request).map(Some)
            }
            _ => Ok(None),
        }
    }
    fn status_reply(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
    ) -> Result<Response, NodeCoreError> {
        let c = &request.control.body;
        let anchor = &c.requester.account_anchor;
        for role in [MigrationRole::Destination, MigrationRole::Source] {
            if let Some(op) = scope.store.migration_operation(anchor, &c.migration_id, role)? {
                let progress = if role == MigrationRole::Source {
                    Some(scope.store.migration_backlog_progress(anchor, &c.migration_id, role)?)
                } else {
                    None
                };
                return MigrationReply {
                    commit_proof: op.proof.clone(),
                    noncommit_fence: op.fence.clone(),
                    backlog_progress: progress,
                    ..MigrationReply::default()
                }
                .sign(&self.node, &request.control, Some(&op), scope.now);
            }
        }
        if let Some(auth) = &request.evidence.authorization {
            if auth.body.account_anchor != *anchor || auth.body.migration_id != c.migration_id {
                return Err(failure(Refusal::IdempotencyConflict));
            }
            match scope.store.terminal_migration_authorization(auth)? {
                Some(crate::FenceOutcome::Committed(home)) => {
                    let HomeRecord::Committed { commit_proof, .. } = &home.record else {
                        return Err(failure(Refusal::EvidenceRequired));
                    };
                    return MigrationReply {
                        commit_proof: Some((**commit_proof).clone()),
                        resolve_result: Some(ResolveResult { home: *home, predecessors: vec![] }),
                        ..MigrationReply::default()
                    }
                    .sign(&self.node, &request.control, None, scope.now);
                }
                Some(crate::FenceOutcome::Fenced(fence)) => {
                    return MigrationReply {
                        noncommit_fence: Some(fence),
                        ..MigrationReply::default()
                    }
                    .sign(&self.node, &request.control, None, scope.now);
                }
                None => {}
            }
        }
        Err(failure(Refusal::EvidenceRequired))
    }
    fn require_current_status_owner(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
    ) -> Result<(), NodeCoreError> {
        let anchor = &request.control.body.requester.account_anchor;
        let head = scope.store.migration_home(anchor)?;
        if head
            .as_ref()
            .is_none_or(|h| h.record.home() == (self.node.node_id(), self.node.public_key()))
        {
            if scope.router.custody_record(anchor, scope.now)?.is_none() {
                return Err(failure(Refusal::EvidenceRequired));
            }
            return scope.router.with_migration_authority(anchor, scope.now, |authority, _| {
                crypto::verify_actor(&request.control, authority, scope.now)
                    .map_err(|_| failure(Refusal::AuthorityUpdateRequired))
            });
        }
        let latest = self.latest_migration_home(
            scope.store,
            &ResolvePayload {
                target_anchor: anchor.clone(),
                after_home_hash: None,
                limit: 64,
                old_node_hint: None,
            },
            &request.control.body.migration_id,
            scope.now,
        )?;
        let (current, pin) = latest.home.record.home();
        if self.mesh.peer_key(current)? != pin {
            return Err(failure(Refusal::PinMismatch));
        }
        let query = self.node.peer_read_call(current, request.control.clone(), scope.now)?;
        let MigrationPeerCall::AuthorizeRead { authentication, .. } = &query else {
            return Err(failure(Refusal::EvidenceRequired));
        };
        let proof = match self.mesh.exchange(current, &query)? {
            MigrationPeerReply::Authorized(proof) => proof,
            MigrationPeerReply::Refused(reason) => return Err(failure(reason)),
            _ => return Err(failure(Refusal::EvidenceRequired)),
        };
        crypto::verify_node(&proof, current, pin).map_err(|_| failure(Refusal::PinMismatch))?;
        let p = &proof.body;
        if p.account_anchor != *anchor
            || p.audience_node != self.node.node_id()
            || p.nonce != authentication.body.nonce
            || p.authority_record_hash != request.control.body.authority_record_hash
            || p.device_set_epoch != scope.authority.envelope().body.device_set_epoch
            || p.previous_home_hash != record_hash(&latest.home.record).map_err(wire)?
            || p.issued_at > scope.now.saturating_add(SKEW_SECONDS)
            || p.expires_at <= p.issued_at
            || p.expires_at - p.issued_at > 30
            || scope.now > p.expires_at
        {
            return Err(failure(Refusal::AuthorityUpdateRequired));
        }
        Ok(())
    }
}
