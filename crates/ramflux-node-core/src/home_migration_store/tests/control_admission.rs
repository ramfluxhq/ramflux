// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Destination preflight and atomic admission run after the native operation-scoped grant boundary.
use super::*;
use crate::home_migration_service::MigrationCaller;
use crate::{HomeMigrationMesh, HomeMigrationService, MigrationPeerCall, MigrationPeerReply};
use ramflux_protocol::{
    custody::MigrationPurpose,
    home_migration::{
        ActionPayload, AttestRequest, Control, Evidence, Request, control_payload_hash,
    },
};
use std::sync::{Arc, Mutex};
struct Mesh {
    source: Mutex<TestNode>,
}
impl HomeMigrationMesh for Mesh {
    fn peer_key(&self, peer: &str) -> Result<String, NodeCoreError> {
        if peer == "A" { Ok(public(8)) } else { Err(refusal(Refusal::PeeringUnavailable)) }
    }
    fn exchange(
        &self,
        _: &str,
        call: &MigrationPeerCall,
    ) -> Result<MigrationPeerReply, NodeCoreError> {
        let source = self.source.lock().map_err(storage)?;
        source.core.handle_migration_peer(
            source.store.as_ref().ok_or_else(|| storage("closed"))?,
            &source.node,
            MigrationPeer { node_id: "B", node_key: &public(9) },
            call,
            NOW,
        )
    }
}
fn service(b: &TestNode, a: TestNode) -> TestResult<HomeMigrationService> {
    let node = MigrationNode::new(
        b.node.record.clone(),
        b.node.key.to_bytes(),
        MigrationEndpoints {
            gateway_tcp_addr: b.node.gateway_tcp_addr.clone(),
            federation_endpoint: b.node.federation_endpoint.clone(),
            discovery_hash: b.node.discovery_hash.clone(),
            server_record_hash: b.node.server_record_hash.clone(),
        },
        NOW,
    )?;
    Ok(HomeMigrationService::new(Arc::new(node), Arc::new(Mesh { source: Mutex::new(a) })))
}
fn caller() -> TestResult<MigrationCaller> {
    Ok(MigrationCaller {
        publication: publication()?,
        purpose: MigrationPurpose::Manage,
        source: "127.0.0.1".parse()?,
    })
}
fn owner_request() -> TestResult<Request> {
    let anchor = publication()?.record.body.account_anchor;
    let owner = attest_request(&anchor, "B", &hash(91), NOW)?;
    Ok(Request {
        control: owner.control,
        payload: ActionPayload::Attest(owner.payload),
        evidence: Evidence::default(),
    })
}
fn prepare_request(base: &RecordEvidence, owner: &Request) -> TestResult<Request> {
    let authority = verify_record(&publication()?.record, NOW, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let mut body: Prepare =
        serde_json::from_value(fixture()?["messages"][0]["signed"]["body"].clone())?;
    body.migration_id = owner.control.body.migration_id.clone();
    body.previous_home_hash = record_hash(&base.record)?;
    body.previous_home_epoch = base.record.epoch();
    body.issued_at = NOW;
    body.expires_at = NOW + 300;
    body.destination_node = "B".into();
    body.destination_key = public(9);
    body.delivery_map_hash = delivery_map_hash(&map_for(&authority)?)?;
    body.nonce = owner.control.body.nonce.clone();
    let prepare = crypto::sign_actor(body, &branch, &authority, NOW)?;
    let payload = ActionPayload::Prepare(Box::new(prepare));
    let mut control: Control = owner.control.body.clone();
    control.action = Action::Prepare;
    control.audience_node = "B".into();
    control.nonce = hash(92);
    control.payload_hash = control_payload_hash(Action::Prepare, &payload, None)?;
    Ok(Request {
        control: crypto::sign_actor(control, &branch, &authority, NOW)?,
        payload,
        evidence: Evidence::default(),
    })
}
#[test]
fn preflight_imports_nothing_and_prepare_atomically_admits_the_exact_cached_view() -> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let b = TestNode::with_registration("B", 9, false, false)?;
    let service = service(&b, a)?;
    let owner = owner_request()?;
    let preflight = service
        .execute(&b.core, b.store()?, owner.clone(), caller()?, NOW)
        .map_err(|e| format!("preflight {e:?}"))?;
    crypto::verify_node(&preflight.receipt, "B", &public(9))?;
    assert_eq!(preflight.receipt.body.response_payload_hash, preflight.payload_hash()?);
    assert!(b.core.custody_record(&owner.control.body.requester.account_anchor, NOW)?.is_none());
    let request = prepare_request(&preflight.resolve_result.ok_or("base")?.home, &owner)?;
    let reply = service
        .execute(&b.core, b.store()?, request.clone(), caller()?, NOW)
        .map_err(|e| format!("prepare {e:?}"))?;
    assert!(reply.offer.is_some());
    let mut retry = request.clone();
    let mut control = retry.control.body.clone();
    control.nonce = hash(94);
    control.issued_at = NOW + 61;
    control.expires_at = NOW + 121;
    let authority = verify_record(&publication()?.record, NOW + 61, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    retry.control = crypto::sign_actor(control, &branch, &authority, NOW + 61)?;
    let retried = service
        .execute(&b.core, b.store()?, retry, caller()?, NOW + 61)
        .map_err(|e| format!("retry {e:?}"))?;
    assert_eq!(reply.offer, retried.offer);
    assert_eq!(retried.receipt.body.request_nonce, hash(94));
    assert_eq!(retried.receipt.body.state_version, 1);
    assert_eq!(reply.receipt.body.request_hash, message_hash(&request.control)?);
    assert_eq!(reply.receipt.body.request_nonce, request.control.body.nonce);
    assert_eq!(reply.receipt.body.response_payload_hash, reply.payload_hash()?);
    assert!(b.core.custody_record(&owner.control.body.requester.account_anchor, NOW)?.is_some());
    assert!(
        b.store()?
            .custody_prekey(
                &map_for(&verify_record(&publication()?.record, NOW, None, None)?)?[0]
                    .target_delivery_id
            )?
            .is_none()
    );
    Ok(())
}
#[test]
fn missing_preflight_and_substituted_control_never_publish_unknown_destination_authority()
-> TestResult {
    let a = TestNode::new("A", 8, true)?;
    let owner = owner_request()?;
    let base = a
        .core
        .attest_home_migration(
            a.store()?,
            &a.node,
            AttestMigration {
                request: &AttestRequest {
                    control: owner.control.clone(),
                    payload: match &owner.payload {
                        ActionPayload::Attest(p) => p.clone(),
                        _ => return Err("owner".into()),
                    },
                },
            },
            NOW,
        )?
        .home;
    let b = TestNode::with_registration("B", 9, false, false)?;
    let service = service(&b, a)?;
    let request = prepare_request(&base, &owner)?;
    assert!(matches!(
        service.execute(&b.core, b.store()?, request, caller()?, NOW),
        Err(ramflux_protocol::custody::CustodyRefusal::HomeMigration {
            reason: Refusal::EvidenceRequired,
            ..
        })
    ));
    let mut changed = owner;
    changed.control.body.nonce = hash(93);
    assert!(service.execute(&b.core, b.store()?, changed.clone(), caller()?, NOW).is_err());
    assert!(b.core.custody_record(&changed.control.body.requester.account_anchor, NOW)?.is_none());
    assert!(b.store()?.migration_home(&changed.control.body.requester.account_anchor)?.is_none());
    Ok(())
}

#[test]
fn owner_and_peer_jobs_share_one_node_ceiling_and_release_after_refusal() -> TestResult {
    let b = TestNode::with_registration("B", 9, false, false)?;
    let mut held =
        (0..16).map(|_| b.node.acquire_migration_verification()).collect::<Result<Vec<_>, _>>()?;
    assert!(matches!(
        b.node.acquire_migration_verification(),
        Err(NodeCoreError::HomeMigration(Refusal::CapacityRefused))
    ));
    drop(held.pop());
    let replacement = b.node.acquire_migration_verification()?;
    drop(held);
    drop(replacement);
    assert!(b.node.acquire_migration_verification().is_ok());
    Ok(())
}

mod operations;
