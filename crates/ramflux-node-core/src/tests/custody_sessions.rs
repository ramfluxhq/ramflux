// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admission tests. Receipt observations here are fixtures; transport has a real TLS proof.
use super::*;
use ed25519_dalek::SigningKey;
use ramflux_crypto::custody::*;
use ramflux_protocol::custody::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_760_000_000;
const PEER: &str = "ramflux-gateway";
struct Driver {
    publication: crate::CustodyPublication,
    branch: ramflux_crypto::DeviceBranch,
    reference: DeviceRef,
    node: VerifiedNodeRecord,
    proxy: SigningKey,
    connection: String,
}
fn node() -> Result<(VerifiedNodeRecord, SigningKey)> {
    let root = SigningKey::from_bytes(&[8; 32]);
    let proxy = SigningKey::from_bytes(&[9; 32]);
    let record = sign_node_identity_record(
        &root,
        NodeIdentityRecord {
            schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
            version: 1,
            node_id: "node".into(),
            node_signing_public_key: ramflux_protocol::encode_base64url(
                root.verifying_key().to_bytes(),
            ),
            client_tls_certificate_sha256: None,
            epoch: 1,
            previous_record_hash: None,
            issued_at: NOW,
            receipt_keys: vec![],
            revoked_receipt_key_ids: vec![],
            proxy_keys: vec![ProxyKey {
                key_id: ramflux_protocol::encode_base64url([10; 32]),
                public_key: ramflux_protocol::encode_base64url(proxy.verifying_key().to_bytes()),
                not_before: NOW - 1,
                sign_until: NOW + 1000,
                overlap_until: NOW + 606_000,
                status: ReceiptKeyStatus::Active,
                proxy_id: "gateway".into(),
                audiences: vec!["node".into()],
            }],
            revoked_proxy_key_ids: vec![],
            channel_binding_modes: vec![BindingMode::HomeRelayReceipt],
        },
    )?;
    Ok((
        verify_node_identity_record(
            &record,
            "node",
            &ramflux_protocol::encode_base64url(root.verifying_key().to_bytes()),
            NOW,
        )?,
        proxy,
    ))
}
impl Driver {
    fn new(principal: &str, seed: u8) -> Result<Self> {
        let publication = super::custody_registration::native(principal, seed)?;
        let branch = ramflux_crypto::create_device_branch(principal, "primary", 1, [seed + 2; 32]);
        let reference = DeviceRef {
            account_anchor: publication.record.body.account_anchor.clone(),
            device_id: "primary".into(),
            device_epoch: 1,
        };
        let (node, proxy) = node()?;
        Ok(Self {
            publication,
            branch,
            reference,
            node,
            proxy,
            connection: ramflux_protocol::encode_base64url([seed; 32]),
        })
    }
    fn publish(&self) -> CustodyProofAction {
        CustodyProofAction::Publish {
            publication: Box::new(Publication {
                record: self.publication.record.clone(),
                compacted_ids: None,
            }),
        }
    }
    fn challenge(
        &self,
        service: &crate::CustodyService,
        router: &RouterCore,
        store: &RouterRedbStore,
        action: CustodyProofAction,
    ) -> Result<BranchChallenge> {
        match service.mesh(
            router,
            store,
            CustodyMeshRequest::Challenge {
                device_ref: self.reference.clone(),
                action,
                binding_mode: BindingMode::HomeRelayReceipt,
                client_source: "192.0.2.1".into(),
                connection_id: self.connection.clone(),
            },
            PEER,
            NOW,
        ) {
            CustodyServerFrame::Challenge { challenge } => Ok(challenge),
            other => Err(format!("challenge failed: {other:?}").into()),
        }
    }
    fn proof(
        &self,
        challenge: &BranchChallenge,
    ) -> Result<ramflux_protocol::custody::Envelope<BranchProofV3>> {
        let cert =
            self.publication.record.body.devices[0].branch_certificate.as_ref().ok_or("cert")?;
        Ok(sign_branch_proof_v3(
            &self.branch,
            BranchProofV3 {
                schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
                version: 3,
                device_ref: self.reference.clone(),
                certificate_hash: object_hash(cert)?,
                record_hash: object_hash(&self.publication.record)?,
                proof_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                challenge_nonce: challenge.challenge_nonce.clone(),
                action_hash: challenge.action_hash.clone(),
                audience: challenge.audience.clone(),
                binding_mode: challenge.binding_mode,
                transport_binding: branch_exporter_hash(&[5; 32]),
                issued_at: NOW,
                expires_at: NOW + 300,
            },
        )?)
    }
    fn attempt(
        &self,
        service: &crate::CustodyService,
        router: &RouterCore,
        store: &RouterRedbStore,
        action: CustodyProofAction,
        proof: ramflux_protocol::custody::Envelope<BranchProofV3>,
    ) -> Result<CustodyServerFrame> {
        let receipt = sign_proxy_acceptance(
            &self.proxy,
            &self.node,
            &proof,
            &branch_exporter_hash(&[5; 32]),
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            NOW,
        )?;
        Ok(service.mesh(
            router,
            store,
            CustodyMeshRequest::Prove {
                action,
                proof: Box::new(proof),
                receipt: Some(Box::new(receipt)),
                connection_id: self.connection.clone(),
            },
            PEER,
            NOW,
        ))
    }
    fn run(
        &self,
        service: &crate::CustodyService,
        router: &RouterCore,
        store: &RouterRedbStore,
        action: CustodyProofAction,
    ) -> Result<CustodyServerFrame> {
        let challenge = self.challenge(service, router, store, action.clone())?;
        self.attempt(service, router, store, action, self.proof(&challenge)?)
    }
    fn bundle(&self, seed: u8) -> Result<serde_json::Value> {
        let agreement = ramflux_crypto::X25519KeyPair::from_seed([seed + 3; 32]);
        Ok(serde_json::to_value(ramflux_crypto::create_prekey_bundle(
            &self.branch,
            &agreement,
            "signed",
            &ramflux_crypto::X25519KeyPair::from_seed([30; 32]),
            None,
            None,
        )?)?)
    }
}
#[test]
fn custody_network_admits_only_signed_possession_and_consumes_challenge_once() -> Result {
    let path = temp_store_path("custody-network-challenge")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let driver = Driver::new("alice", 10)?;
    let service = crate::CustodyService::new(driver.node.clone(), false, &store, NOW)?;
    let action = driver.publish();
    let challenge = driver.challenge(&service, &router, &store, action.clone())?;
    let proof = driver.proof(&challenge)?;
    assert!(matches!(
        driver.attempt(
            &service,
            &router,
            &store,
            CustodyProofAction::OpenSession,
            proof.clone()
        )?,
        CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused }
    ));
    let mut wrong = proof.clone();
    wrong.body.record_hash = ramflux_protocol::encode_base64url([0; 32]);
    assert!(matches!(
        driver.attempt(&service, &router, &store, action.clone(), wrong)?,
        CustodyServerFrame::Refused { .. }
    ));
    assert!(router.custody_record(&driver.reference.account_anchor, NOW)?.is_none());
    assert!(matches!(
        driver.attempt(&service, &router, &store, action.clone(), proof.clone())?,
        CustodyServerFrame::Published { .. }
    ));
    assert!(matches!(
        driver.attempt(&service, &router, &store, action, proof)?,
        CustodyServerFrame::Refused { code: CustodyRefusal::Replay }
    ));
    let attacker = Driver::new("alice", 20)?;
    let attacker_result = attacker.run(&service, &router, &store, attacker.publish())?;
    assert!(
        matches!(
            attacker_result,
            CustodyServerFrame::Refused { code: CustodyRefusal::PrincipalIdTaken }
        ),
        "unexpected conflict result: {attacker_result:?}"
    );
    assert!(matches!(
        driver.run(
            &service,
            &router,
            &store,
            CustodyProofAction::Register { prekey_bundle: driver.bundle(10)? }
        )?,
        CustodyServerFrame::Registered { .. }
    ));
    let CustodyServerFrame::SessionEstablished { session } =
        driver.run(&service, &router, &store, CustodyProofAction::OpenSession)?
    else {
        return Err("session".into());
    };
    assert_eq!(session.device_ref, driver.reference);
    let lost = driver.challenge(&service, &router, &store, CustodyProofAction::OpenSession)?;
    let lost_proof = driver.proof(&lost)?;
    drop(service);
    let restarted = crate::CustodyService::new(driver.node.clone(), false, &store, NOW)?;
    assert!(matches!(
        driver.attempt(&restarted, &router, &store, CustodyProofAction::OpenSession, lost_proof)?,
        CustodyServerFrame::Refused { code: CustodyRefusal::ChallengeUnknown }
    ));
    assert!(matches!(
        driver.run(&restarted, &router, &store, CustodyProofAction::OpenSession)?,
        CustodyServerFrame::SessionEstablished { .. }
    ));
    drop(restarted);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

fn signed_request(
    driver: &Driver,
    session: &CustodySession,
    action: &CustodySessionAction,
    nonce: &str,
) -> Result<ramflux_protocol::SignedRequest> {
    let mut request = ramflux_protocol::SignedRequest {
        schema: ramflux_protocol::domain::SIGNED_REQUEST.into(),
        version: 1,
        domain: ramflux_protocol::domain::SIGNED_REQUEST.into(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "branch".into(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        source_device_id: driver.reference.device_id.clone(),
        request_id: nonce.into(),
        method: ramflux_protocol::HttpMethod::POST,
        path: CUSTODY_REQUEST_PATH.into(),
        device_proof_hash: session.proof_hash.clone(),
        body_hash: custody_session_action_hash(action)?,
        nonce: nonce.into(),
        created_at: i64::try_from(NOW)?,
        expires_at: i64::try_from(NOW + 60)?,
    };
    request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(&driver.branch, &request)?;
    Ok(request)
}
#[test]
fn custody_session_requests_bind_connection_possession_nonce_and_current_head() -> Result {
    let path = temp_store_path("custody-session-binding")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let driver = Driver::new("alice", 10)?;
    let service = crate::CustodyService::new(driver.node.clone(), false, &store, NOW)?;
    driver.run(&service, &router, &store, driver.publish())?;
    driver.run(
        &service,
        &router,
        &store,
        CustodyProofAction::Register { prekey_bundle: driver.bundle(10)? },
    )?;
    let CustodyServerFrame::SessionEstablished { session } =
        driver.run(&service, &router, &store, CustodyProofAction::OpenSession)?
    else {
        return Err("session".into());
    };
    let action = CustodySessionAction::Inbox { after_seq: 0, limit: 10 };
    let send = |connection: &str, request: ramflux_protocol::SignedRequest, clock| {
        service.mesh(
            &router,
            &store,
            CustodyMeshRequest::Request {
                session_id: session.session_id.clone(),
                request: Box::new(request),
                action: action.clone(),
                connection_id: connection.into(),
            },
            PEER,
            clock,
        )
    };
    let nonce = ramflux_protocol::encode_base64url([1; 32]);
    let request = signed_request(&driver, &session, &action, &nonce)?;
    assert!(matches!(
        send(&ramflux_protocol::encode_base64url([2; 32]), request.clone(), NOW),
        CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused }
    ));
    assert!(matches!(
        send(&driver.connection, request.clone(), NOW),
        CustodyServerFrame::Inbox { .. }
    ));
    assert!(matches!(
        send(&driver.connection, request, NOW),
        CustodyServerFrame::Refused { code: CustodyRefusal::Replay }
    ));
    let mut forged =
        signed_request(&driver, &session, &action, &ramflux_protocol::encode_base64url([3; 32]))?;
    forged.signed.signature = ramflux_protocol::encode_base64url([0; 64]);
    assert!(matches!(
        send(&driver.connection, forged, NOW),
        CustodyServerFrame::Refused { code: CustodyRefusal::InvalidInput }
    ));
    let fresh =
        signed_request(&driver, &session, &action, &ramflux_protocol::encode_base64url([4; 32]))?;
    assert!(matches!(
        send(&driver.connection, fresh.clone(), NOW + 301),
        CustodyServerFrame::Refused { code: CustodyRefusal::SessionExpired }
    ));
    let verified = verify_record(&driver.publication.record, NOW, None, None)?;
    let primary = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([11; 32]));
    let revoked = primary.revoke_device(&verified, "primary", NOW + 1)?;
    router.publish_custody_record(
        &crate::CustodyPublication { record: revoked, compacted_ids: None },
        NOW + 1,
        &store,
    )?;
    assert!(matches!(
        send(&driver.connection, fresh, NOW + 1),
        CustodyServerFrame::Refused { code: CustodyRefusal::UpdateRequired }
    ));
    drop(service);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn custody_node_history_retains_keys_and_rejects_rollback_or_rebinding_after_restart() -> Result {
    let path = temp_store_path("custody-node-pins")?;
    let (first, _) = node()?;
    let root = SigningKey::from_bytes(&[8; 32]);
    let key_id = first.envelope().body.proxy_keys[0].key_id.clone();
    let mut body = first.envelope().body.clone();
    body.epoch = 2;
    body.previous_record_hash = Some(first.hash().into());
    body.issued_at = NOW + 1;
    body.revoked_proxy_key_ids = vec![key_id];
    body.proxy_keys.clear();
    let retired = sign_node_identity_record(&root, body)?;
    let retired = verify_node_identity_record(
        &retired,
        "node",
        &ramflux_protocol::encode_base64url(root.verifying_key().to_bytes()),
        NOW + 1,
    )?;
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        store.observe_custody_node(&first, NOW)?;
        store.observe_custody_node(&retired, NOW + 1)?;
        assert_eq!(store.custody_node_history(first.hash())?, Some(first.envelope().clone()));
    }
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        assert!(store.observe_custody_node(&first, NOW + 1).is_err());
        let mut body = retired.envelope().body.clone();
        body.epoch = 3;
        body.previous_record_hash = Some(retired.hash().into());
        body.issued_at = NOW + 2;
        let mut key = first.envelope().body.proxy_keys[0].clone();
        key.public_key = ramflux_crypto::public_key_base64url_from_seed([21; 32]);
        body.proxy_keys = vec![key];
        let rebound = sign_node_identity_record(&root, body)?;
        let rebound = verify_node_identity_record(
            &rebound,
            "node",
            &ramflux_protocol::encode_base64url(root.verifying_key().to_bytes()),
            NOW + 2,
        )?;
        assert!(store.observe_custody_node(&rebound, NOW + 2).is_err());
        assert_eq!(store.custody_node_history(retired.hash())?, Some(retired.envelope().clone()));
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn custody_node_key_signing_deadline_cannot_restart_after_overlap_history_is_removed() -> Result {
    let path = temp_store_path("custody-key-deadline")?;
    let (first, _) = node()?;
    let root = SigningKey::from_bytes(&[8; 32]);
    let later = NOW + 606_001;
    let mut body = first.envelope().body.clone();
    body.epoch = 2;
    body.previous_record_hash = Some(first.hash().into());
    body.issued_at = later;
    body.proxy_keys.clear();
    let removed = sign_node_identity_record(&root, body)?;
    let removed = verify_node_identity_record(
        &removed,
        "node",
        &ramflux_protocol::encode_base64url(root.verifying_key().to_bytes()),
        later,
    )?;
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        store.observe_custody_node(&first, NOW)?;
        store.observe_custody_node(&removed, later)?;
    }
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let mut body = removed.envelope().body.clone();
        body.epoch = 3;
        body.previous_record_hash = Some(removed.hash().into());
        body.issued_at = later + 1;
        let mut key = first.envelope().body.proxy_keys[0].clone();
        key.not_before = later;
        key.sign_until = later + 1000;
        key.overlap_until = later + 606_000;
        body.proxy_keys = vec![key];
        let recycled = sign_node_identity_record(&root, body)?;
        let recycled = verify_node_identity_record(
            &recycled,
            "node",
            &ramflux_protocol::encode_base64url(root.verifying_key().to_bytes()),
            later + 1,
        )?;
        assert!(store.observe_custody_node(&recycled, later + 1).is_err());
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn custody_mesh_unauthenticated_ipv6_prefix_cannot_exhaust_other_sources() -> Result {
    let path = temp_store_path("custody-unauthenticated-prefixes")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let driver = Driver::new("prefix-test", 70)?;
    let service = crate::CustodyService::new(driver.node.clone(), false, &store, NOW)?;
    let mut issued = 0;
    for address in 1_u8..=64 {
        for _ in 0..64 {
            let request = CustodyMeshRequest::Challenge {
                device_ref: driver.reference.clone(),
                action: driver.publish(),
                binding_mode: BindingMode::HomeRelayReceipt,
                client_source: format!("2001:db8:1:2::{address:x}"),
                connection_id: ramflux_protocol::encode_base64url([address; 32]),
            };
            if matches!(
                service.mesh(&router, &store, request, PEER, NOW),
                CustodyServerFrame::Challenge { .. }
            ) {
                issued += 1;
            }
        }
    }
    assert!(issued <= 64);
    driver.challenge(&service, &router, &store, driver.publish())?;
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn custody_publication_quota_refusal_does_not_occupy_successful_replay_cache() -> Result {
    let path = temp_store_path("custody-publication-quota-admission")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let first = Driver::new("quota-first", 150)?;
    let service = crate::CustodyService::new(first.node.clone(), false, &store, NOW)?;
    for n in 0_u8..8 {
        let driver = Driver::new(&format!("quota-{n}"), 150 + n)?;
        assert!(matches!(
            driver.run(&service, &router, &store, driver.publish())?,
            CustodyServerFrame::Published { .. }
        ));
    }
    let refused = Driver::new("quota-refused", 170)?;
    let action = refused.publish();
    let challenge = refused.challenge(&service, &router, &store, action.clone())?;
    let proof = refused.proof(&challenge)?;
    assert!(matches!(
        refused.attempt(&service, &router, &store, action.clone(), proof.clone())?,
        CustodyServerFrame::Refused { code: CustodyRefusal::Capacity }
    ));
    assert!(matches!(
        refused.attempt(&service, &router, &store, action, proof)?,
        CustodyServerFrame::Refused { code: CustodyRefusal::ChallengeUnknown }
    ));
    assert!(router.custody_record(&refused.reference.account_anchor, NOW)?.is_none());
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}
