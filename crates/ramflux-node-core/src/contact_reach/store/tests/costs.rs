// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original certified master consent and node genesis bind the real issuer transaction.
use super::*;
use ramflux_protocol::home_migration::{
    Genesis, HomeDeclarationV1, HomeRecord, RecordEvidence, ResolveResult,
};
use redb::{ReadableTableMetadata, TableDefinition};
const CHALLENGES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_challenges_v1");
fn issuer(store: &RouterRedbStore, f: &Fixture) -> TestResult<crate::MigrationNode> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let mut body = {
        let tx = store.begin_write()?;
        home(&tx, &f.root)?.node_record.body
    };
    body.node_id = "issuer.example".into();
    body.node_signing_public_key = ramflux_crypto::public_key_base64url_from_seed([8; 32]);
    let record = ramflux_crypto::custody::sign_node_identity_record(&key, body)?;
    let node = crate::MigrationNode::new(
        record.clone(),
        [8; 32],
        crate::MigrationEndpoints {
            gateway_tcp_addr: "issuer.example:443".into(),
            federation_endpoint: "https://issuer.example".into(),
            discovery_hash: digest(85),
            server_record_hash: digest(86),
        },
        NOW,
    )?;
    let declaration = f.key.sign_home_declaration(
        HomeDeclarationV1 {
            version: 1,
            principal_id: f.authority.envelope().body.principal_id.clone(),
            account_anchor: f.root.clone(),
            home_node: node.node_id().into(),
            created_at: NOW,
            nonce: digest(80),
        },
        &f.authority,
        NOW,
    )?;
    let genesis = ramflux_crypto::home_migration::sign_node(
        Genesis {
            home_declaration: Box::new(declaration),
            version: 1,
            account_anchor: f.root.clone(),
            home_epoch: 0,
            home_node: node.node_id().into(),
            home_node_key: node.public_key().into(),
            custody_record_hash: custody::object_hash(f.authority.envelope())?,
            registered_at: NOW,
        },
        node.node_id(),
        &key,
    )?;
    let evidence = RecordEvidence {
        authority: ramflux_protocol::custody::Publication {
            record: f.authority.envelope().clone(),
            compacted_ids: None,
        },
        record: HomeRecord::Genesis { genesis: Box::new(genesis) },
        management_certificate_chain: vec![],
        actor_certificate: None,
        node_record: record,
    };
    ramflux_crypto::home_migration::verify_home_chain(
        &ResolveResult { home: evidence.clone(), predecessors: vec![] },
        &evidence,
        NOW,
    )?;
    let tx = store.begin_write()?;
    tx.open_table(HEADS)?.insert(f.root.as_str(), encoded(&evidence)?.as_slice())?;
    tx.commit()?;
    Ok(node)
}
fn count(store: &RouterRedbStore) -> TestResult<u64> {
    let tx = store.begin_write()?;
    Ok(tx.open_table(CHALLENGES)?.len()?)
}
#[test]
fn cr_reach_error_lifting_cost_storage_orphans_expire_and_custody_is_definite() -> TestResult {
    use crate::contact_reach::{CostIssuerPeer, ReachError, cost::fault, owner_error};
    use ramflux_protocol::contact_reach::{
        COMMAND_LIFETIME, COST_DOMAIN, ChallengeRequest, CostPurpose,
    };
    for point in [fault::Point::BeforeCommit, fault::Point::AfterCommit] {
        let dir = tempfile::TempDir::new()?;
        let (store, f) = initialize(&dir.path().join("issuer.redb"))?;
        let node = issuer(&store, &f)?;
        let peer = crate::parse_mesh_spiffe_uri("spiffe://source.example/ramflux-federation")?;
        let peer = CostIssuerPeer::from_tls(&peer, "192.0.2.20".parse()?)?;
        let request = ChallengeRequest {
            purpose: CostPurpose::Stranger,
            source_root: digest(41),
            recipient_root: Some(f.root.clone()),
            operation_hash: digest(90),
        };
        {
            let _fault = fault::arm(point);
            let result = store.reach_issue_cost(&node, &peer, &request, NOW).map_or_else(
                |error| owner_error(&error),
                |challenge| OperationResult::Challenge { challenge },
            );
            assert_eq!(
                result,
                OperationResult::Error {
                    reason: Reason::ForeignStorageUnavailable,
                    retry_after_ms: None,
                    current_revision: None
                },
                "both sides of challenge commit return uncertain storage, never a fabricated puzzle"
            );
        }
        assert_eq!(
            count(&store)?,
            u64::from(point == fault::Point::AfterCommit),
            "the actual durable issuer commit distinguishes a rollback from an orphan"
        );
        let fresh = store.reach_issue_cost(&node, &peer, &request, NOW)?;
        ramflux_crypto::verify_canonical_signature(
            &custody::signing_bytes(COST_DOMAIN, &fresh.body)?,
            &fresh.signature,
            node.public_key(),
        )?;
        assert_eq!(
            count(&store)?,
            1 + u64::from(point == fault::Point::AfterCommit),
            "a fresh challenge can coexist with the bounded earlier orphan"
        );
        store.reach_issue_cost(&node, &peer, &request, NOW + COMMAND_LIFETIME + 60)?;
        assert_eq!(count(&store)?, 1, "expiry plus retention must collect the abandoned challenge");
        let mut wrong = request.clone();
        wrong.recipient_root = Some(digest(99));
        assert!(
            matches!(
                store.reach_issue_cost(&node, &peer, &wrong, NOW + COMMAND_LIFETIME + 60),
                Err(ReachError::Refused(Reason::CostInvalid))
            ),
            "a missing local target is a definite cost mismatch"
        );
        let tx = store.begin_write()?;
        let mut state: CustodyAccountState = tx
            .open_table(CUSTODY)?
            .get(f.root.as_str())?
            .map(|value| row::<CustodyAccountState>(value.value()))
            .transpose()?
            .ok_or("custody row")?;
        state.publication.record.signature = ramflux_protocol::encode_base64url([99; 64]);
        tx.open_table(CUSTODY)?.insert(f.root.as_str(), encoded(&state)?.as_slice())?;
        tx.commit()?;
        let denied = store
            .reach_issue_cost(&node, &peer, &request, NOW + COMMAND_LIFETIME + 60)
            .map_or_else(
                |error| owner_error(&error),
                |challenge| OperationResult::Challenge { challenge },
            );
        assert_eq!(
            denied,
            OperationResult::Error {
                reason: Reason::CustodyRefused,
                retry_after_ms: None,
                current_revision: None
            },
            "invalid current target custody is a definite refusal before challenge allocation"
        );
        assert_eq!(count(&store)?, 1, "custody refusal cannot create another orphan");
    }
    Ok(())
}

#[test]
fn cr_home_lookup_rejects_another_roots_original_signed_head() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let (store, f) = initialize(&dir.path().join("home-binding.redb"))?;
    let tx = store.begin_write()?;
    let original = home(&tx, &f.root)?;
    tx.open_table(HEADS)?.insert(digest(99).as_str(), encoded(&original)?.as_slice())?;
    tx.commit()?;
    let tx = store.begin_write()?;
    assert!(
        matches!(
            home(&tx, &digest(99)),
            Err(crate::contact_reach::ReachError::Refused(Reason::HomeRollback))
        ),
        "an authentic head for a different root cannot establish this lookup's local home"
    );
    assert_eq!(
        home(&tx, &f.root)?,
        original,
        "the original account retains its exact signed routing evidence"
    );
    Ok(())
}
