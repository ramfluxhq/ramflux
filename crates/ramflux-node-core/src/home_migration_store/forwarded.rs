// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reconstruct forwarded activation exclusively from the destination's sealed evidence.
use super::{
    CommitProof, HomeRecord, MigrationNode, MigrationRole, NodeCoreError, RecordEvidence, Refusal,
    RouterRedbStore, Signed, crypto, refusal,
};
use ramflux_protocol::home_migration::ResolveResult;

impl RouterRedbStore {
    /// Activate a forwarded target using only a commit proof and locally sealed evidence.
    /// An ordinary active target needs no proof. This does not accept or ACK an envelope.
    /// # Errors
    /// Refuses dormant targets without proof, unmapped proof targets, forged proofs and seal mismatches.
    pub fn activate_forwarded_target(
        &self,
        node: &MigrationNode,
        target: &str,
        proof: Option<&Signed<CommitProof>>,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.check_forwarded_target(node, target, proof, now, true)
    }
    pub(crate) fn check_forwarded_target(
        &self,
        node: &MigrationNode,
        target: &str,
        proof: Option<&Signed<CommitProof>>,
        now: u64,
        activate: bool,
    ) -> Result<(), NodeCoreError> {
        let Some(proof) = proof else {
            return if self.home_migration_target_active(target)? {
                Ok(())
            } else {
                Err(refusal(Refusal::DormantInbox))
            };
        };
        let op = self
            .migration_operation(
                &proof.body.account_anchor,
                &proof.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        if !op.delivery_map.iter().any(|entry| entry.target_delivery_id == target) {
            return Err(refusal(Refusal::BaseMismatch));
        }
        let (source, key) = op.base.record.home();
        crypto::verify_node(proof, source, key).map_err(|_| refusal(Refusal::BaseMismatch))?;
        // A committed base can carry the previous signer's descriptor. Never substitute
        // a descriptor supplied by the forwarder when the local seal lacks the current one.
        if op.base.node_record.body.node_id != source
            || op.base.node_record.body.node_signing_public_key != key
        {
            return Err(refusal(Refusal::EvidenceRequired));
        }
        let authorization = op.authorization.ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let authority = op.sealed_authority.ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let actor = authority
            .record
            .body
            .devices
            .iter()
            .find(|device| device.device_id == authorization.body.actor.device_id)
            .and_then(|device| device.branch_certificate.clone())
            .ok_or_else(|| refusal(Refusal::ActorRevoked))?;
        let home = RecordEvidence {
            management_certificate_chain: vec![authority.record.body.master_certificate.clone()],
            authority,
            actor_certificate: Some(actor),
            node_record: op.base.node_record,
            record: HomeRecord::Committed {
                authorization: Box::new(authorization),
                commit_proof: Box::new(proof.clone()),
            },
        };
        self.apply_forwarded_activation(
            node,
            &ResolveResult { home, predecessors: vec![] },
            now,
            activate,
        )
        .map_err(|error| match error {
            NodeCoreError::HomeMigration(Refusal::AuthorityUpdateRequired) => {
                refusal(Refusal::BaseMismatch)
            }
            error => error,
        })
    }
}
