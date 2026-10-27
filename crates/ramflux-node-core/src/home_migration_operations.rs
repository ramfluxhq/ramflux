// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Custody management verbs use local durable reservations and immutable source outcomes.
use crate::{
    HomeMigrationService, MigrationOperation, MigrationPeerReply, MigrationRole, NodeCoreError,
    home_migration_reply::MigrationReply, home_migration_service::MigrationExecution,
};
use ramflux_crypto::home_migration as crypto;
use ramflux_protocol::{
    custody::{Publication, object_hash},
    home_migration::{
        Action, ActionPayload, HomeRecord, RecordEvidence, Refusal, Request, ResolveResult,
        Response, message_hash, record_hash,
    },
};
fn failure(reason: Refusal) -> NodeCoreError {
    NodeCoreError::HomeMigration(reason)
}
fn wire(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
impl HomeMigrationService {
    pub(crate) fn execute_operation(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
    ) -> Result<Option<Response>, NodeCoreError> {
        match &request.payload {
            ActionPayload::Seal(payload) => self.seal_owner(scope, request, payload).map(Some),
            ActionPayload::Commit(payload) => self.commit_owner(scope, request, payload).map(Some),
            ActionPayload::Activate(payload) => {
                self.activate_owner(scope, request, payload).map(Some)
            }
            ActionPayload::Fence(payload) => self.fence_owner(scope, request, payload).map(Some),
            ActionPayload::Operation(_) if request.control.body.action == Action::Abort => {
                self.abort_owner(scope, request).map(Some)
            }
            _ => Ok(None),
        }
    }
    fn seal_owner(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
        payload: &ramflux_protocol::home_migration::SealPayload,
    ) -> Result<Response, NodeCoreError> {
        require_local_control(scope, request)?;
        let op = operation(scope, request)?;
        let auth = request
            .evidence
            .authorization
            .as_ref()
            .or(op.authorization.as_ref())
            .ok_or_else(|| failure(Refusal::EvidenceRequired))?;
        if message_hash(auth).map_err(wire)? != payload.authorization_hash
            || message_hash(&op.offer).map_err(wire)? != payload.offer_hash
            || auth.body.account_anchor != request.control.body.requester.account_anchor
            || auth.body.migration_id != request.control.body.migration_id
        {
            return Err(failure(Refusal::IdempotencyConflict));
        }
        scope.router.seal_home_migration(scope.store, &self.node, auth, scope.now)?;
        self.operation_reply(scope, request, MigrationReply::default())
    }

    fn commit_owner(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
        payload: &ramflux_protocol::home_migration::CommitPayload,
    ) -> Result<Response, NodeCoreError> {
        require_local_control(scope, request)?;
        let op = operation(scope, request)?;
        let sealed = op.sealed_evidence()?;
        if message_hash(&sealed.authorization).map_err(wire)? != payload.authorization_hash
            || message_hash(&sealed.offer).map_err(wire)? != payload.offer_hash
            || message_hash(&sealed.seal).map_err(wire)? != payload.seal_hash
        {
            return Err(failure(Refusal::IdempotencyConflict));
        }
        // The client cannot replace B's stored seal with another transport receipt.
        // Every failed exchange leaves the seal/courier durable for restart recovery.
        if op.phase != ramflux_protocol::home_migration::Phase::Active {
            let reply = self.exchange_courier(&op, false, scope.now, scope.deadline)?;
            match reply {
                MigrationPeerReply::Committed(record) => scope.store.activate_home_migration(
                    &self.node,
                    &ResolveResult { home: *record, predecessors: vec![] },
                    scope.now,
                )?,
                MigrationPeerReply::Fenced(fence) => scope.store.accept_home_noncommit_fence(
                    &fence,
                    &sealed.authorization.body.account_anchor,
                    scope.now,
                )?,
                MigrationPeerReply::Refused(reason) => return Err(failure(reason)),
                _ => return Err(failure(Refusal::CommitOutcomeUnknown)),
            }
        }
        self.operation_reply(scope, request, MigrationReply::default())
    }

    fn activate_owner(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
        payload: &ramflux_protocol::home_migration::ActivatePayload,
    ) -> Result<Response, NodeCoreError> {
        require_local_control(scope, request)?;
        let op = operation(scope, request)?;
        let result = activation_evidence(scope, request, &op)?;
        let HomeRecord::Committed { commit_proof, .. } = &result.home.record else {
            return Err(failure(Refusal::EvidenceRequired));
        };
        if record_hash(&result.home.record).map_err(wire)? != payload.home_record_hash
            || message_hash(commit_proof).map_err(wire)? != payload.commit_proof_hash
        {
            return Err(failure(Refusal::IdempotencyConflict));
        }
        scope.store.activate_home_migration(&self.node, &result, scope.now)?;
        self.operation_reply(
            scope,
            request,
            MigrationReply { resolve_result: Some(result), ..MigrationReply::default() },
        )
    }

    fn fence_owner(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
        payload: &ramflux_protocol::home_migration::FencePayload,
    ) -> Result<Response, NodeCoreError> {
        require_local_control(scope, request)?;
        let op = operation(scope, request)?;
        let fence = request
            .evidence
            .noncommit_fence
            .as_ref()
            .or(op.fence.as_ref())
            .ok_or_else(|| failure(Refusal::EvidenceRequired))?;
        if message_hash(fence).map_err(wire)? != payload.noncommit_fence_hash {
            return Err(failure(Refusal::IdempotencyConflict));
        }
        scope.store.accept_home_noncommit_fence(
            fence,
            &request.control.body.requester.account_anchor,
            scope.now,
        )?;
        self.operation_reply(
            scope,
            request,
            MigrationReply { noncommit_fence: Some(fence.clone()), ..MigrationReply::default() },
        )
    }

    fn abort_owner(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
    ) -> Result<Response, NodeCoreError> {
        Ok({
            // An authorization-only source cancellation is handled separately from
            // aborting B's unsealed local reservation.
            if let Some(auth) = &request.evidence.authorization {
                match scope.router.fence_home_authorization(
                    scope.store,
                    &self.node,
                    auth,
                    scope.now,
                    Some(&request.control),
                )? {
                    crate::FenceOutcome::Fenced(fence) => {
                        MigrationReply { noncommit_fence: Some(fence), ..MigrationReply::default() }
                            .sign(&self.node, &request.control, None, scope.now)?
                    }
                    crate::FenceOutcome::Committed(record) => {
                        let HomeRecord::Committed { commit_proof, .. } = &record.record else {
                            return Err(failure(Refusal::EvidenceRequired));
                        };
                        MigrationReply {
                            commit_proof: Some((**commit_proof).clone()),
                            resolve_result: Some(ResolveResult {
                                home: *record,
                                predecessors: vec![],
                            }),
                            ..MigrationReply::default()
                        }
                        .sign(
                            &self.node,
                            &request.control,
                            None,
                            scope.now,
                        )?
                    }
                }
            } else {
                let op = scope.router.abort_prepared_home_migration(
                    scope.store,
                    &self.node,
                    &request.control,
                    scope.now,
                )?;
                MigrationReply::default().sign(
                    &self.node,
                    &request.control,
                    Some(&op),
                    scope.now,
                )?
            }
        })
    }
    fn operation_reply(
        &self,
        scope: &MigrationExecution<'_>,
        request: &Request,
        mut reply: MigrationReply,
    ) -> Result<Response, NodeCoreError> {
        let op = operation(scope, request)?;
        if reply.commit_proof.is_none() {
            reply.commit_proof.clone_from(&op.proof);
        }
        if reply.noncommit_fence.is_none() {
            reply.noncommit_fence.clone_from(&op.fence);
        }
        reply.sign(&self.node, &request.control, Some(&op), scope.now)
    }
}
fn require_local_control(
    scope: &MigrationExecution<'_>,
    request: &Request,
) -> Result<(), NodeCoreError> {
    scope.router.with_migration_authority(
        &request.control.body.requester.account_anchor,
        scope.now,
        |authority, _| {
            crypto::verify_actor(&request.control, authority, scope.now)
                .map_err(|_| failure(Refusal::AuthorityUpdateRequired))
        },
    )
}
fn operation(
    scope: &MigrationExecution<'_>,
    request: &Request,
) -> Result<MigrationOperation, NodeCoreError> {
    scope
        .store
        .migration_operation(
            &request.control.body.requester.account_anchor,
            &request.control.body.migration_id,
            MigrationRole::Destination,
        )?
        .ok_or_else(|| failure(Refusal::EvidenceRequired))
}
fn activation_evidence(
    scope: &MigrationExecution<'_>,
    request: &Request,
    op: &MigrationOperation,
) -> Result<ResolveResult, NodeCoreError> {
    let record =
        request.evidence.home_record.clone().ok_or_else(|| failure(Refusal::EvidenceRequired))?;
    let HomeRecord::Committed { authorization, commit_proof } = &record else {
        return Err(failure(Refusal::EvidenceRequired));
    };
    let authority = request.evidence.authority.clone().unwrap_or_else(|| Publication {
        record: scope.caller.publication.record.clone(),
        compacted_ids: scope.caller.publication.compacted_ids.clone(),
    });
    if object_hash(&authority.record).map_err(wire)? != authorization.body.authority_record_hash
        || request.evidence.authorization.as_ref().is_some_and(|a| a != authorization.as_ref())
        || request.evidence.commit_proof.as_ref().is_some_and(|p| p != commit_proof.as_ref())
    {
        return Err(failure(Refusal::AuthorityUpdateRequired));
    }
    let actor_certificate = authority
        .record
        .body
        .devices
        .iter()
        .find(|d| {
            d.device_id == authorization.body.actor.device_id
                && d.device_epoch == authorization.body.actor.device_epoch
        })
        .and_then(|d| d.branch_certificate.clone());
    let node_record = request
        .evidence
        .node_identity_record
        .clone()
        .or_else(|| {
            let (source, key) = op.base.record.home();
            (op.base.node_record.body.node_id == source
                && op.base.node_record.body.node_signing_public_key == key)
                .then(|| op.base.node_record.clone())
        })
        .ok_or_else(|| failure(Refusal::EvidenceRequired))?;
    Ok(ResolveResult {
        home: RecordEvidence {
            management_certificate_chain: vec![authority.record.body.master_certificate.clone()],
            authority,
            record,
            actor_certificate,
            node_record,
        },
        predecessors: request.evidence.predecessors.clone().unwrap_or_default(),
    })
}
