// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-purpose migration possession grants never become ordinary account sessions.
use super::*;
use ramflux_protocol::home_migration::{
    Action, ActionPayload, Control, Evidence, OperationPayload, Request,
};
use std::sync::Arc;
struct UnavailablePeers;
impl crate::HomeMigrationMesh for UnavailablePeers {
    fn peer_key(
        &self,
        _node: &str,
        _deadline: std::time::Instant,
    ) -> std::result::Result<String, NodeCoreError> {
        Err(NodeCoreError::HomeMigration(
            ramflux_protocol::home_migration::Refusal::PeeringUnavailable,
        ))
    }
}
fn service(driver: &Driver, store: &RouterRedbStore) -> Result<crate::CustodyService> {
    let node = crate::MigrationNode::new(
        driver.node.envelope().clone(),
        [8; 32],
        crate::MigrationEndpoints {
            gateway_tcp_addr: "127.0.0.1:9443".into(),
            federation_endpoint: "127.0.0.1:9444".into(),
            discovery_hash: ramflux_protocol::encode_base64url([14; 32]),
            server_record_hash: ramflux_protocol::encode_base64url([15; 32]),
        },
        NOW,
    )?;
    Ok(crate::CustodyService::new(driver.node.clone(), false, store, NOW)?.with_home_migration(
        crate::HomeMigrationService::new(Arc::new(node), Arc::new(UnavailablePeers)),
    )?)
}
fn request(driver: &Driver, wrong_authority: bool) -> Result<Request> {
    let payload = OperationPayload {
        account_anchor: driver.reference.account_anchor.clone(),
        migration_id: ramflux_protocol::encode_base64url([21; 32]),
    };
    let authority = verify_record(&driver.publication.record, NOW, None, None)?;
    let control = ramflux_crypto::home_migration::sign_actor(
        Control {
            version: 1,
            action: Action::Status,
            audience_node: "node".into(),
            migration_id: payload.migration_id.clone(),
            requester: driver.reference.clone(),
            authority_record_hash: if wrong_authority {
                ramflux_protocol::encode_base64url([99; 32])
            } else {
                object_hash(&driver.publication.record)?
            },
            payload_hash: ramflux_protocol::custody::framed_hash(
                ramflux_protocol::domain::HOME_CONTROL,
                &payload,
            )?,
            nonce: ramflux_protocol::encode_base64url([22; 32]),
            issued_at: NOW,
            expires_at: NOW + 60,
        },
        &driver.branch,
        &authority,
        NOW,
    )?;
    Ok(Request {
        control,
        payload: ActionPayload::Operation(payload),
        evidence: Evidence::default(),
    })
}
fn grant(
    driver: &Driver,
    service: &crate::CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    request: &Request,
) -> Result<CustodySession> {
    grant_with_purpose(driver, service, router, store, request, MigrationPurpose::Manage)
}
fn grant_with_purpose(
    driver: &Driver,
    service: &crate::CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    request: &Request,
    purpose: MigrationPurpose,
) -> Result<CustodySession> {
    let action = CustodyProofAction::HomeMigration {
        purpose,
        control_hash: ramflux_protocol::home_migration::message_hash(&request.control)?,
        publication: Box::new(Publication {
            record: driver.publication.record.clone(),
            compacted_ids: None,
        }),
    };
    let CustodyServerFrame::SessionEstablished { session } =
        driver.run(service, router, store, action)?
    else {
        return Err("migration possession".into());
    };
    Ok(session)
}
fn send(
    driver: &Driver,
    service: &crate::CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    session: &CustodySession,
    action: CustodySessionAction,
) -> Result<CustodyServerFrame> {
    let request = signed_request(
        driver,
        session,
        &action,
        &ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
    )?;
    Ok(service.mesh(
        router,
        store,
        CustodyMeshRequest::Request {
            session_id: session.session_id.clone(),
            request: Box::new(request),
            action,
            connection_id: driver.connection.clone(),
        },
        PEER,
        NOW,
    ))
}
#[test]
fn migration_grant_binds_the_control_authority_even_when_possession_and_control_hash_match()
-> Result {
    let store = RouterRedbStore::open(temp_store_path("migration-authority-grant")?)?;
    let router = RouterCore::new();
    let driver = Driver::new("alice", 10)?;
    let service = service(&driver, &store)?;
    let control = request(&driver, true)?;
    let session = grant(&driver, &service, &router, &store, &control)?;
    let response = send(
        &driver,
        &service,
        &router,
        &store,
        &session,
        CustodySessionAction::HomeMigration { request: Box::new(control) },
    )?;
    assert_eq!(response, CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused });
    assert_eq!(store.custody_publication_write_count(), 0);
    assert!(router.custody_record(&driver.reference.account_anchor, NOW)?.is_none());
    Ok(())
}
#[test]
fn new_to_destination_grant_is_one_use_and_does_not_import_authority_for_a_read() -> Result {
    let store = RouterRedbStore::open(temp_store_path("migration-one-use-grant")?)?;
    let router = RouterCore::new();
    let driver = Driver::new("alice", 10)?;
    let service = service(&driver, &store)?;
    let control = request(&driver, false)?;
    let session = grant(&driver, &service, &router, &store, &control)?;
    let action = CustodySessionAction::HomeMigration { request: Box::new(control) };
    let response = send(&driver, &service, &router, &store, &session, action.clone())?;
    assert_ne!(response, CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused });
    assert_eq!(
        send(&driver, &service, &router, &store, &session, action)?,
        CustodyServerFrame::Refused { code: CustodyRefusal::SessionRequired }
    );
    assert_eq!(store.custody_publication_write_count(), 0);
    assert!(router.custody_record(&driver.reference.account_anchor, NOW)?.is_none());
    assert!(store.custody_prekey(&session.target_delivery_id)?.is_none());
    Ok(())
}
#[test]
fn migration_possession_grant_cannot_lookup_peers_or_read_a_normal_inbox() -> Result {
    let store = RouterRedbStore::open(temp_store_path("migration-isolated-grant")?)?;
    let router = RouterCore::new();
    let driver = Driver::new("alice", 10)?;
    let service = service(&driver, &store)?;
    let session = grant(&driver, &service, &router, &store, &request(&driver, false)?)?;
    for action in [
        CustodySessionAction::Inbox { after_seq: 0, limit: 10 },
        CustodySessionAction::Lookup { device_ref: driver.reference.clone() },
    ] {
        assert_eq!(
            send(&driver, &service, &router, &store, &session, action)?,
            CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused }
        );
    }
    assert_eq!(store.custody_publication_write_count(), 0);
    Ok(())
}

#[test]
fn message_only_branch_can_obtain_a_one_use_read_grant_without_management_authority() -> Result {
    let store = RouterRedbStore::open(temp_store_path("migration-read-capability")?)?;
    let router = RouterCore::new();
    let mut driver = Driver::new("alice", 10)?;
    let primary = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([11; 32]));
    let mut body = driver.publication.record.body.clone();
    let mut certificate = body.devices[0].branch_certificate.take().ok_or("branch")?.body;
    certificate.capabilities = vec!["message".into()];
    body.devices[0].branch_certificate = Some(primary.certify_branch(certificate)?);
    driver.publication.record = primary.sign_record(body)?;
    let service = service(&driver, &store)?;
    let control = request(&driver, false)?;
    let authority = verify_record(&driver.publication.record, NOW, None, None)?;
    ramflux_crypto::home_migration::verify_actor(&control.control, &authority, NOW)?;
    let mut write = control.control.body.clone();
    write.action = Action::Abort;
    assert!(
        ramflux_crypto::home_migration::sign_actor(write, &driver.branch, &authority, NOW).is_err()
    );
    let session =
        grant_with_purpose(&driver, &service, &router, &store, &control, MigrationPurpose::Read)?;
    let response = send(
        &driver,
        &service,
        &router,
        &store,
        &session,
        CustodySessionAction::HomeMigration { request: Box::new(control) },
    )?;
    assert_ne!(response, CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused });
    assert_eq!(store.custody_publication_write_count(), 0);
    Ok(())
}
#[test]
fn read_grant_cannot_execute_a_management_control_even_for_a_privileged_branch() -> Result {
    let store = RouterRedbStore::open(temp_store_path("migration-read-isolation")?)?;
    let router = RouterCore::new();
    let driver = Driver::new("alice", 10)?;
    let service = service(&driver, &store)?;
    let authority = verify_record(&driver.publication.record, NOW, None, None)?;
    let mut control = request(&driver, false)?.control.body;
    control.action = Action::Attest;
    control.audience_node = "old".into();
    let payload = ramflux_protocol::home_migration::AttestPayload {
        account_anchor: driver.reference.account_anchor.clone(),
        destination_node: "node".into(),
        nonce: control.nonce.clone(),
    };
    control.payload_hash = ramflux_protocol::custody::framed_hash(
        ramflux_protocol::domain::HOME_ATTEST_REQUEST,
        &payload,
    )?;
    let control =
        ramflux_crypto::home_migration::sign_actor(control, &driver.branch, &authority, NOW)?;
    let request =
        Request { control, payload: ActionPayload::Attest(payload), evidence: Evidence::default() };
    let session =
        grant_with_purpose(&driver, &service, &router, &store, &request, MigrationPurpose::Read)?;
    assert_eq!(
        send(
            &driver,
            &service,
            &router,
            &store,
            &session,
            CustodySessionAction::HomeMigration { request: Box::new(request) }
        )?,
        CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused }
    );
    assert_eq!(store.custody_publication_write_count(), 0);
    Ok(())
}
