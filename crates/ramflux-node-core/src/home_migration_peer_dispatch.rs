// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dispatch authenticated peer control without interpreting transport failure as noncommit.
use crate::{
    AttestMigration, CommitMigration, FenceOutcome, MigrationNode, MigrationPeer,
    MigrationPeerCall, MigrationPeerReply, NodeCoreError, RouterCore, RouterRedbStore,
};
use ramflux_crypto::home_migration as crypto;
use ramflux_protocol::{
    custody::object_hash,
    home_migration::{HomeAttestation, Refusal, delivery_map_hash, record_hash},
};

impl RouterCore {
    /// Serve only a call authenticated with an independently admitted peer key.
    /// Transport implementations must enforce frame, connection, rate and execution budgets.
    /// # Errors
    /// Returns storage/serialization failures; expected protocol refusals are typed replies.
    pub fn handle_migration_peer(
        &self,
        store: &RouterRedbStore,
        node: &MigrationNode,
        peer: MigrationPeer<'_>,
        call: &MigrationPeerCall,
        now: u64,
    ) -> Result<MigrationPeerReply, NodeCoreError> {
        let result = (|| {
            call.verify(peer, node.node_id(), now)?;
            match call {
                MigrationPeerCall::Attest { owner, .. } => self
                    .attest_home_migration(store, node, AttestMigration { request: owner }, now)
                    .map(|home| MigrationPeerReply::Attested(Box::new(home))),
                MigrationPeerCall::AuthorizeRead { authentication, owner } => self
                    .with_migration_authority(
                        &authentication.body.account_anchor,
                        now,
                        |authority, _| {
                            crypto::verify_actor(owner, authority, now).map_err(authority_error)?;
                            let head = store
                                .migration_home(&authentication.body.account_anchor)?
                                .ok_or_else(|| failure(Refusal::HomeGenesisRequired))?;
                            if head.record.home() != (node.node_id(), node.public_key()) {
                                return Err(failure(Refusal::BaseMismatch));
                            }
                            let map = super::home_migration_store::map_for(authority)?;
                            let attestation = crypto::sign_node(
                                HomeAttestation {
                                    version: 1,
                                    account_anchor: authentication.body.account_anchor.clone(),
                                    audience_node: peer.node_id.into(),
                                    previous_home_hash: record_hash(&head.record).map_err(wire)?,
                                    authority_record_hash: object_hash(authority.envelope())
                                        .map_err(wire)?,
                                    device_set_epoch: authority.envelope().body.device_set_epoch,
                                    delivery_map_hash: delivery_map_hash(&map).map_err(wire)?,
                                    nonce: authentication.body.nonce.clone(),
                                    issued_at: now,
                                    expires_at: now
                                        .checked_add(30)
                                        .ok_or_else(|| failure(Refusal::AuthorityUpdateRequired))?,
                                },
                                node.node_id(),
                                &node.key,
                            )
                            .map_err(authority_error)?;
                            Ok(MigrationPeerReply::Authorized(Box::new(attestation)))
                        },
                    ),
                MigrationPeerCall::Commit { sealed, .. } => self
                    .commit_home_migration(store, node, CommitMigration { sealed, peer }, now)
                    .map(|record| MigrationPeerReply::Committed(Box::new(record))),
                MigrationPeerCall::Status { authorization, .. } => self
                    .fence_home_authorization(store, node, authorization, now, None)
                    .map(|outcome| match outcome {
                        FenceOutcome::Committed(record) => MigrationPeerReply::Committed(record),
                        FenceOutcome::Fenced(fence) => MigrationPeerReply::Fenced(Box::new(fence)),
                    }),
            }
        })();
        match result {
            Err(NodeCoreError::HomeMigration(reason)) => Ok(MigrationPeerReply::Refused(reason)),
            other => other,
        }
    }
}
fn failure(reason: Refusal) -> NodeCoreError {
    NodeCoreError::HomeMigration(reason)
}
fn authority_error(_: impl std::fmt::Display) -> NodeCoreError {
    failure(Refusal::AuthorityUpdateRequired)
}
fn wire(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
