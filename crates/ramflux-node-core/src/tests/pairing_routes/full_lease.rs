// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
mod discovery;
mod resume;
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::pairing::full_transfer::lease::{
    BranchKeys, DataGrant, LeaseRequest,
};

fn request(created: &Created, driver: &custody_sessions::Driver) -> TestResult<LeaseRequest> {
    let invitation = &created.invitation.body;
    let mut request = LeaseRequest {
        schema: "ramflux.pairing.full_transfer.lease_request.v1".into(),
        version: 1,
        invitation_id: invitation.invitation_id.clone(),
        issuer_seq: invitation.issuer_seq,
        transcript_hash: encode_base64url([31; 32]),
        grant: DataGrant {
            schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
            version: 1,
            transfer_id: invitation.transfer_id.clone().ok_or("transfer id")?,
            node_id: driver.node.envelope().body.node_id.clone(),
            source_ref: driver.reference.clone(),
            destination_ref: DeviceRef {
                account_anchor: driver.reference.account_anchor.clone(),
                device_id: "new-b".into(),
                device_epoch: 1,
            },
            branch_keys: BranchKeys {
                source: driver.publication.record.body.devices[0]
                    .branch_certificate
                    .as_ref()
                    .ok_or("branch")?
                    .body
                    .branch_signing_public_key
                    .clone(),
                destination: ramflux_crypto::public_key_base64url_from_seed([37; 32]),
            },
            opaque_commitment: encode_base64url([32; 32]),
            expires_at: WALL + 604_800,
        },
        source_signature: encode_base64url([0; 64]),
        destination_signature: encode_base64url([0; 64]),
    };
    sign(&mut request)?;
    Ok(request)
}
fn sign(request: &mut LeaseRequest) -> TestResult {
    request.source_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &request.signing_bytes("initiator")?,
        [12; 32],
    );
    request.destination_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &request.signing_bytes("responder")?,
        [37; 32],
    );
    Ok(())
}
fn action(request: &LeaseRequest) -> CustodyProofAction {
    CustodyProofAction::PairingDataLease { request: Box::new(request.clone()) }
}
#[test]
fn pairing_full_data_lease_native_proof_requires_live_invitation_both_branches_and_idempotent_scope()
-> TestResult {
    run_native_lease(None)
}
#[test]
fn pairing_full_control_replayed_arm_refused() -> TestResult {
    run_native_lease(Some(resume::ControlCase::Replay))
}
#[test]
fn pairing_full_control_wrong_role_token_refused() -> TestResult {
    run_native_lease(Some(resume::ControlCase::WrongRoleToken))
}
#[test]
fn pairing_full_auth_prebody_header_scope_epoch_and_no_oracle() -> TestResult {
    run_native_lease(Some(resume::ControlCase::Header))
}
#[test]
fn pairing_full_shared_queue_retries_ready_control_release_and_retired_buffers() -> TestResult {
    run_native_lease(Some(resume::ControlCase::Queue))
}
#[test]
fn pairing_full_mesh_permit_scope_race_and_release() -> TestResult {
    run_native_lease(Some(resume::ControlCase::Mesh))
}
fn run_native_lease(control_case: Option<resume::ControlCase>) -> TestResult {
    let path = temp_store_path("pairing-full-data-lease")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.bootstrap_router(&router)?;
    let driver = custody_sessions::Driver::new("alice", 10)?;
    let clock = TestPairingClock::new(WALL);
    let relay = Arc::new(Mutex::new(PairingRelayStore::new(PairingRelayConfig {
        clock: Arc::clone(&clock) as Arc<dyn PairingClock>,
        node_seed: [8; 32],
        public_origin: ORIGIN.into(),
    })?));
    let service = crate::CustodyService::new(driver.node.clone(), false, &store, NOW)?
        .with_pairing_relay(Arc::clone(&relay));
    assert!(matches!(
        driver.run(&service, &router, &store, driver.publish())?,
        CustodyServerFrame::Published { .. }
    ));
    let mut full_spec = spec(&driver, WALL)?;
    full_spec.purpose = "primary_transfer".into();
    let issued = issued_of(driver.run(
        &service,
        &router,
        &store,
        CustodyProofAction::PairingIssue {
            request: Box::new(Issue {
                schema: "ramflux.pairing.Issue.v2".into(),
                version: 2,
                spec: full_spec.clone(),
            }),
        },
    )?)?;
    let created = created_of(driver.run(
        &service,
        &router,
        &store,
        CustodyProofAction::PairingCreate {
            request: Box::new(Create {
                schema: "ramflux.pairing.Create.v2".into(),
                version: 2,
                ticket: issued.ticket,
                spec: full_spec,
            }),
        },
    )?)?;
    let request = request(&created, &driver)?;
    let before = locked(&relay)?.accounted_bytes();
    let mut missing = request.clone();
    missing.destination_signature = encode_base64url([0; 64]);
    assert_eq!(
        failure_code(driver.run(&service, &router, &store, action(&missing))?)?,
        "WrongContext"
    );
    assert_eq!(locked(&relay)?.accounted_bytes(), before);
    let lease = match driver.run(&service, &router, &store, action(&request))? {
        CustodyServerFrame::PairingDataLease { lease } => *lease,
        other => return Err(format!("expected data-only lease: {other:?}").into()),
    };
    ramflux_crypto::custody::pairing::verify_full_data_lease(
        &lease,
        &request.grant,
        &driver.node,
        WALL,
    )?;
    let after = locked(&relay)?.accounted_bytes();
    assert!(after > before);
    let retried = match driver.run(&service, &router, &store, action(&request))? {
        CustodyServerFrame::PairingDataLease { lease } => *lease,
        other => return Err(format!("expected same data-only lease: {other:?}").into()),
    };
    assert_eq!(
        ramflux_protocol::canonical_json_bytes(&lease)?,
        ramflux_protocol::canonical_json_bytes(&retried)?
    );
    assert_eq!(locked(&relay)?.accounted_bytes(), after);
    let mut replaced = request.clone();
    replaced.transcript_hash = encode_base64url([33; 32]);
    sign(&mut replaced)?;
    assert_eq!(failure_code(driver.run(&service, &router, &store, action(&replaced))?)?, "Replay");
    let measured = locked(&relay)?;
    assert_eq!(measured.accounted_bytes(), measured.measured_bytes());
    drop(measured);
    resume::prove_resume(&relay, &lease, &driver, &router, &clock, control_case)?;
    clock.advance_secs(301);
    assert_eq!(failure_code(driver.run(&service, &router, &store, action(&request))?)?, "Retired");
    assert_eq!(locked(&relay)?.stats().slots, 0);
    Ok(())
}
