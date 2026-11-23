// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persist the initial node attestation together with the master's home consent.
use super::{
    Genesis, HomeRecord, MigrationNode, NodeCoreError, RecordEvidence, Refusal, Signed,
    VerifiedRecord, auth_error, crypto, refusal, save_head, storage,
};
use ramflux_protocol::{custody::object_hash, home_migration::HomeDeclarationV1};

impl crate::RouterCore {
    /// Enrol the current ordinary home without manufacturing a migration destination.
    /// The caller must have authenticated the current native account/branch before dispatch.
    /// Existing home evidence is returned verbatim; this never replaces a genesis or lineage.
    /// # Errors
    /// Refuses missing registration, stale native/declaration authority, a different home,
    /// unsafe clock, changed node signer and unavailable durable storage.
    pub fn ensure_home_genesis(
        &self,
        store: &crate::RouterRedbStore,
        node: &MigrationNode,
        declaration: &Signed<HomeDeclarationV1>,
        now: u64,
    ) -> Result<RecordEvidence, NodeCoreError> {
        let anchor = declaration.body.account_anchor.as_str();
        let _root = store.migration_root_barrier(anchor)?;
        self.with_migration_authority(anchor, now, |authority, publication| {
            crypto::verify_home_declaration(declaration, authority, node.node_id(), now)
                .map_err(|_| refusal(Refusal::HomeDeclarationRequired))?;
            let map = super::map_for(authority)?;
            let mut registered = false;
            for entry in &map {
                registered |= store.custody_prekey(&entry.target_delivery_id)?.is_some();
            }
            if !registered {
                return Err(refusal(Refusal::HomeGenesisRequired));
            }
            let tx = store.begin_write().map_err(storage)?;
            let now = super::clock(&tx, now)?;
            super::signer_pin::retain(&tx, node)?;
            super::authority_evidence::remember(&tx, publication, now)?;
            let head = match super::read::<RecordEvidence>(&tx, super::HEADS, anchor)? {
                Some(existing) => existing,
                None => create(&tx, node, publication, authority, Some(declaration), now)?,
            };
            if head.record.home() != (node.node_id(), node.public_key()) {
                return Err(refusal(Refusal::BaseMismatch));
            }
            super::commit_transition(store, tx)?;
            Ok(head)
        })
    }
}

pub(super) fn create(
    tx: &redb::WriteTransaction,
    node: &MigrationNode,
    publication: &crate::CustodyPublication,
    authority: &VerifiedRecord,
    declaration: Option<&Signed<HomeDeclarationV1>>,
    now: u64,
) -> Result<RecordEvidence, NodeCoreError> {
    let genesis = crypto::sign_node(
        Genesis {
            home_declaration: Box::new(
                declaration.ok_or_else(|| refusal(Refusal::HomeDeclarationRequired))?.clone(),
            ),
            version: 1,
            account_anchor: authority.envelope().body.account_anchor.clone(),
            home_epoch: 0,
            home_node: node.node_id().into(),
            home_node_key: node.public_key().into(),
            custody_record_hash: object_hash(authority.envelope()).map_err(storage)?,
            registered_at: now,
        },
        node.node_id(),
        &node.key,
    )
    .map_err(auth_error)?;
    let head = RecordEvidence {
        authority: ramflux_protocol::custody::Publication {
            record: publication.record.clone(),
            compacted_ids: publication.compacted_ids.clone(),
        },
        record: HomeRecord::Genesis { genesis: Box::new(genesis) },
        management_certificate_chain: vec![],
        actor_certificate: None,
        node_record: node.record.clone(),
    };
    save_head(tx, &head)?;
    Ok(head)
}
