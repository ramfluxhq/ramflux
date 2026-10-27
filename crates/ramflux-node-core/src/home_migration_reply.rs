// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh signed receipts bind immutable outcomes to the current owner control and nonce.
use crate::{MigrationNode, MigrationOperation, NodeCoreError};
use ramflux_crypto::home_migration as crypto;
use ramflux_protocol::home_migration::{
    BacklogProgress, CommitProof, Control, HomeAttestation, NoncommitFence, Offer, Phase, Receipt,
    ResolveResult, Response, Signed, message_hash, record_hash,
};
use serde::Serialize;
#[derive(Default, Serialize)]
pub(crate) struct MigrationReply {
    pub offer: Option<Signed<Offer>>,
    pub commit_proof: Option<Signed<CommitProof>>,
    pub noncommit_fence: Option<Signed<NoncommitFence>>,
    pub resolve_result: Option<ResolveResult>,
    pub backlog_progress: Option<BacklogProgress>,
    pub attestation: Option<Signed<HomeAttestation>>,
}
impl MigrationReply {
    pub fn sign(
        self,
        node: &MigrationNode,
        control: &Signed<Control>,
        operation: Option<&MigrationOperation>,
        now: u64,
    ) -> Result<Response, NodeCoreError> {
        let c = &control.body;
        let home = self
            .resolve_result
            .as_ref()
            .map(|r| record_hash(&r.home.record))
            .transpose()
            .map_err(wire)?;
        let seal = operation.and_then(|o| o.seal.as_ref());
        let terminal_phase = if self.commit_proof.is_some() {
            Phase::Committed
        } else if self.noncommit_fence.is_some() {
            Phase::Expired
        } else {
            Phase::Prepared
        };
        let authorization_hash = operation
            .and_then(|op| op.authorization.as_ref())
            .map(message_hash)
            .transpose()
            .map_err(wire)?
            .or_else(|| {
                self.noncommit_fence.as_ref().map(|fence| fence.body.authorization_hash.clone())
            })
            .or_else(|| {
                self.commit_proof.as_ref().map(|proof| proof.body.authorization_hash.clone())
            });
        let seal_hash = seal
            .map(message_hash)
            .transpose()
            .map_err(wire)?
            .or_else(|| self.commit_proof.as_ref().map(|proof| proof.body.seal_hash.clone()));
        let receipt = crypto::sign_node(
            Receipt {
                version: 1,
                action: c.action,
                migration_id: c.migration_id.clone(),
                account_anchor: c.requester.account_anchor.clone(),
                node_id: node.node_id().into(),
                request_hash: message_hash(control).map_err(wire)?,
                request_nonce: c.nonce.clone(),
                authorization_hash,
                seal_hash,
                home_record_hash: home,
                phase: operation.map_or(terminal_phase, |o| o.phase),
                state_version: operation.map_or(0, |o| o.state_version),
                sealed_at: seal.and_then(|s| s.body.sealed_at),
                commit_deadline: seal.and_then(|s| s.body.commit_deadline),
                commit_proof_hash: self
                    .commit_proof
                    .as_ref()
                    .map(message_hash)
                    .transpose()
                    .map_err(wire)?,
                response_payload_hash: ramflux_protocol::custody::framed_hash(
                    ramflux_protocol::domain::HOME_RECEIPT,
                    &self,
                )
                .map_err(wire)?,
                issued_at: now,
                expires_at: now.checked_add(300).ok_or_else(|| wire("receipt time overflow"))?,
                reason_code: None,
            },
            node.node_id(),
            &node.key,
        )
        .map_err(wire)?;
        Ok(Response {
            receipt,
            offer: self.offer,
            commit_proof: self.commit_proof,
            noncommit_fence: self.noncommit_fence,
            resolve_result: self.resolve_result,
            backlog_progress: self.backlog_progress,
            attestation: self.attestation,
        })
    }
}
fn wire(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
