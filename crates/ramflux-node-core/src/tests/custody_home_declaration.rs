// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-only registration at a fresh node cannot mint another home genesis.
use super::*;
fn migration_node(driver: &Driver, seed: u8) -> Result<crate::MigrationNode> {
    Ok(crate::MigrationNode::new(
        driver.node.envelope().clone(),
        [seed; 32],
        crate::MigrationEndpoints {
            gateway_tcp_addr: "127.0.0.1:9443".into(),
            federation_endpoint: "127.0.0.1:9444".into(),
            discovery_hash: ramflux_protocol::encode_base64url([14; 32]),
            server_record_hash: ramflux_protocol::encode_base64url([15; 32]),
        },
        NOW,
    )?)
}
fn attest(
    driver: &Driver,
    router: &RouterCore,
    store: &RouterRedbStore,
    node: &crate::MigrationNode,
    destination: &str,
    declaration: Option<
        ramflux_protocol::home_migration::Signed<
            ramflux_protocol::home_migration::HomeDeclarationV1,
        >,
    >,
) -> Result<crate::AttestedHome> {
    use ramflux_protocol::home_migration::{Action, AttestPayload, AttestRequest, Control};
    let authority = verify_record(&driver.publication.record, NOW, None, None)?;
    let payload = AttestPayload {
        home_declaration: declaration.map(Box::new),
        account_anchor: driver.reference.account_anchor.clone(),
        destination_node: destination.into(),
        nonce: ramflux_protocol::encode_base64url([47; 32]),
    };
    let control = ramflux_crypto::home_migration::sign_actor(
        Control {
            version: 1,
            action: Action::Attest,
            audience_node: node.node_id().into(),
            migration_id: ramflux_protocol::encode_base64url([48; 32]),
            requester: driver.reference.clone(),
            authority_record_hash: object_hash(&driver.publication.record)?,
            payload_hash: framed_hash(ramflux_protocol::domain::HOME_ATTEST_REQUEST, &payload)?,
            nonce: payload.nonce.clone(),
            issued_at: NOW,
            expires_at: NOW + 60,
        },
        &driver.branch,
        &authority,
        NOW,
    )?;
    Ok(router.attest_home_migration(
        store,
        node,
        crate::AttestMigration { request: &AttestRequest { control, payload } },
        NOW,
    )?)
}
#[test]
fn copied_publication_and_stolen_branch_cannot_mint_genesis_at_a_fresh_node() -> Result {
    let _store_directory_0 = temp_store_path("migration-bootstrap-a")?;
    let a_store = RouterRedbStore::open(_store_directory_0.to_path_buf())?;
    let _store_directory_1 = temp_store_path("migration-bootstrap-b")?;
    let b_store = RouterRedbStore::open(_store_directory_1.to_path_buf())?;
    let a = RouterCore::new();
    a.set_local_home_node_id(Some("node".into()));
    let b = RouterCore::new();
    b.set_local_home_node_id(Some("node-b".into()));
    let a_driver = Driver::new("alice", 10)?;
    let a_service = super::service(&a_driver, &a_store)?;
    a_driver.run(&a_service, &a, &a_store, a_driver.publish())?;
    a_driver.run(
        &a_service,
        &a,
        &a_store,
        CustodyProofAction::Register { prekey_bundle: a_driver.bundle(10)? },
    )?;
    let authority = verify_record(&a_driver.publication.record, NOW, None, None)?;
    let primary = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([11; 32]));
    let declaration = primary.sign_home_declaration(
        ramflux_protocol::home_migration::HomeDeclarationV1 {
            version: 1,
            principal_id: "alice".into(),
            account_anchor: a_driver.reference.account_anchor.clone(),
            home_node: "node".into(),
            created_at: NOW,
            nonce: ramflux_protocol::encode_base64url([49; 32]),
        },
        &authority,
        NOW,
    )?;
    let a_head = attest(
        &a_driver,
        &a,
        &a_store,
        &migration_node(&a_driver, 8)?,
        "node-b",
        Some(declaration.clone()),
    )?;
    let mut b_driver = Driver::new("alice", 10)?;
    b_driver.publication = a_driver.publication.clone();
    let b_signer = SigningKey::from_bytes(&[18; 32]);
    let b_key = ramflux_protocol::encode_base64url(b_signer.verifying_key().to_bytes());
    let mut record = a_driver.node.envelope().body.clone();
    record.node_id = "node-b".into();
    record.node_signing_public_key.clone_from(&b_key);
    record.proxy_keys[0].audiences = vec!["node-b".into()];
    let record = sign_node_identity_record(&b_signer, record)?;
    b_driver.node = verify_node_identity_record(&record, "node-b", &b_key, NOW)?;
    let b_service = crate::CustodyService::new(b_driver.node.clone(), false, &b_store, NOW)?
        .with_home_migration(crate::HomeMigrationService::new(
            std::sync::Arc::new(migration_node(&b_driver, 18)?),
            std::sync::Arc::new(super::UnavailablePeers),
        ))?;
    assert_eq!(
        a_driver.publication.record, b_driver.publication.record,
        "no new management signature"
    );
    b_driver.run(&b_service, &b, &b_store, b_driver.publish())?;
    b_driver.run(
        &b_service,
        &b,
        &b_store,
        CustodyProofAction::Register { prekey_bundle: b_driver.bundle(10)? },
    )?;
    assert!(matches!(
        b_driver.run(&b_service, &b, &b_store, CustodyProofAction::OpenSession)?,
        CustodyServerFrame::SessionEstablished { .. }
    ));
    for declaration in [None, Some(declaration)] {
        assert!(
            matches!(attest(&b_driver, &b, &b_store, &migration_node(&b_driver, 18)?, "node-c", declaration),
                Err(error) if matches!(error.downcast_ref::<NodeCoreError>(),
                    Some(NodeCoreError::HomeMigration(ramflux_protocol::home_migration::Refusal::HomeDeclarationRequired)))
            )
        );
        assert!(b_store.migration_home(&b_driver.reference.account_anchor)?.is_none());
    }
    assert_eq!(a_head.home.record.epoch(), 0);
    assert_eq!(
        a_store.migration_home(&a_driver.reference.account_anchor)?.ok_or("A home")?,
        a_head.home
    );
    Ok(())
}
