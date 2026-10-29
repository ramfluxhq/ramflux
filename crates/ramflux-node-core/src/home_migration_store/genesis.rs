// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persist the initial node attestation together with the master's home consent.
use super::{
    Genesis, HomeRecord, MigrationNode, NodeCoreError, RecordEvidence, Refusal, Signed,
    VerifiedRecord, auth_error, crypto, refusal, save_head, storage,
};
use ramflux_protocol::{custody::object_hash, home_migration::HomeDeclarationV1};

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
