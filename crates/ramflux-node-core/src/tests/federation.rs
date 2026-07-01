// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

#[test]
fn federation_redb_store_restores_trust_state() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("federation_redb_store_restores_trust_state")?;
    let store = FederationRedbStore::open(&path)?;
    let mut state = FederationTrustState::new();
    state.upsert_route(federation_route("node_b.example", FederationTrustStatus::Active));
    let node_b_seed = seed_from_nonce(0x41, 2);
    let node_b_public_key = ramflux_crypto::public_key_base64url_from_seed(node_b_seed);
    let request = federation_discovery_request("node_b.example");
    let mut record = federation_server_record("node_b.example", "host.docker.internal:18482");
    record.node_public_key.clone_from(&node_b_public_key);
    sign_federation_server_record_with_seed(&mut record, node_b_seed)?;
    state.resolve_discovery_result(&request, Some(&record), None)?;
    state.apply_bad_node_advisory(BadNodeAdvisory {
        advisory_id: "adv_1".to_owned(),
        issuer_node_id: "node_a.example".to_owned(),
        subject_node_id: "node_c.example".to_owned(),
        reason_code: "warning".to_owned(),
        issued_at: 1_760_000_000,
        expires_at: 1_762_592_000,
        signature_hash: "signature_hash".to_owned(),
    });
    store.save_state(&state)?;
    drop(store);

    let reopened = FederationRedbStore::open(&path)?;
    let mut restored = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("federation_state".to_owned()))?;
    assert!(restored.can_deliver_to("node_b.example", 1_760_000_001));
    assert_eq!(
        restored.pinned_peer_ca_cert_pem("node_b.example").as_deref(),
        Some(record.node_ca_cert_pem.as_str())
    );
    restored.update_trust_status(
        "node_b.example",
        FederationTrustStatus::Revoked,
        1_760_000_010,
    )?;
    assert!(!restored.can_deliver_to("node_b.example", 1_760_000_011));
    assert_eq!(restored.advisory_count(), 1);
    Ok(())
}

#[test]
fn federation_redb_store_restores_node_signing_seed_without_routes()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("federation_redb_store_restores_node_signing_seed_without_routes")?;
    let store = FederationRedbStore::open(&path)?;
    let mut state = FederationTrustState::new();
    let seed = seed_from_nonce(0x77, 11);
    state.set_node_signing_seed(seed);
    store.save_state(&state)?;
    drop(store);

    let reopened = FederationRedbStore::open(&path)?;
    let restored = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("federation_state".to_owned()))?;
    assert_eq!(restored.node_signing_seed(), Some(seed));
    Ok(())
}

#[test]
fn federation_redb_store_spools_retries_and_expires_outbound_forward()
-> Result<(), Box<dyn std::error::Error>> {
    let path =
        temp_store_path("federation_redb_store_spools_retries_and_expires_outbound_forward")?;
    let store = FederationRedbStore::open(&path)?;
    let forward_a = federation_forward_request("env_spool_a", "target_spool_a");
    let forward_b = federation_forward_request("env_spool_b", "target_spool_b");
    let entry_a = store.spool_outbound_forward("node_b.example", &forward_a, 100, 10)?;
    let entry_b = store.spool_outbound_forward("node_b.example", &forward_b, 101, 10)?;
    assert_eq!(entry_a.seq, 1);
    assert_eq!(entry_b.seq, 2);
    store.record_outbound_attempt("node_b.example", entry_a.seq)?;

    let pending = store.list_pending_for_peer("node_b.example", 10)?;
    assert_eq!(pending.iter().map(|entry| entry.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(pending[0].attempt_count, 1);
    assert_eq!(pending[0].forward.envelope.envelope_id, "env_spool_a");

    drop(store);
    let reopened = FederationRedbStore::open(&path)?;
    let restored = reopened.list_pending_for_peer("node_b.example", 10)?;
    assert_eq!(restored.len(), 2);
    reopened.mark_outbound_delivered("node_b.example", entry_a.seq)?;
    let after_delivery = reopened.list_pending_for_peer("node_b.example", 10)?;
    assert_eq!(after_delivery.len(), 1);
    assert_eq!(after_delivery[0].seq, entry_b.seq);
    assert_eq!(reopened.expire_outbound_spool(111)?, 1);
    assert!(reopened.list_pending_for_peer("node_b.example", 10)?.is_empty());
    Ok(())
}

#[test]
fn federation_redb_store_dedups_inbound_forward_replay_persistently()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("federation_redb_store_dedups_inbound_forward_replay_persistently")?;
    let store = FederationRedbStore::open(&path)?;
    let forward_a = federation_forward_request("env_inbound_a", "target_inbound_a");
    let forward_b = federation_forward_request("env_inbound_b", "target_inbound_a");
    let forward_a_other_target = federation_forward_request("env_inbound_a", "target_inbound_b");
    let now = 1_760_000_010;

    assert!(store.accept_inbound_forward_once(&forward_a, now)?);
    assert!(!store.accept_inbound_forward_once(&forward_a, now + 1)?);
    assert!(store.accept_inbound_forward_once(&forward_b, now + 2)?);
    assert!(store.accept_inbound_forward_once(&forward_a_other_target, now + 3)?);

    drop(store);
    let reopened = FederationRedbStore::open(&path)?;
    assert!(!reopened.accept_inbound_forward_once(&forward_a, now + 4)?);
    assert!(!reopened.accept_inbound_forward_once(&forward_b, now + 5)?);
    assert!(!reopened.accept_inbound_forward_once(&forward_a_other_target, now + 6)?);
    Ok(())
}

#[test]
fn federation_discovery_verifies_well_known_and_rejects_pin_hijack()
-> Result<(), Box<dyn std::error::Error>> {
    let mut state = FederationTrustState::new();
    let node_b_seed = seed_from_nonce(0x41, 2);
    let node_b_public_key = ramflux_crypto::public_key_base64url_from_seed(node_b_seed);
    let request = federation_discovery_request("node_b.example");
    let mut record = federation_server_record("node_b.example", "host.docker.internal:18482");
    record.node_public_key.clone_from(&node_b_public_key);
    sign_federation_server_record_with_seed(&mut record, node_b_seed)?;
    let discovered = state.resolve_discovery_result(&request, Some(&record), None)?;
    assert_eq!(discovered.source, FederationDiscoverySource::WellKnown);
    assert_eq!(discovered.pin_state, FederationPinState::Pinned);
    assert_eq!(
        state.discovery_pin("node_b.example").map(|pin| pin.pinned_node_public_key.as_str()),
        Some(node_b_public_key.as_str())
    );
    let pinned_ca =
        state.pinned_peer_ca_cert_pem("node_b.example").ok_or("missing initial node_b CA pin")?;
    assert_eq!(pinned_ca, record.node_ca_cert_pem);

    let forged_seed = [0x77; 32];
    let mut forged = federation_server_record("node_b.example", "host.docker.internal:18482");
    forged.node_public_key = ramflux_crypto::public_key_base64url_from_seed(forged_seed);
    sign_federation_server_record_with_seed(&mut forged, forged_seed)?;
    let rejected = state.resolve_discovery_result(&request, Some(&forged), None);
    assert!(rejected.is_err());
    assert_eq!(
        state.discovery_pin("node_b.example").map(|pin| pin.state),
        Some(FederationPinState::Pinned)
    );
    assert_eq!(
        state.pinned_peer_ca_cert_pem("node_b.example").as_deref(),
        Some(record.node_ca_cert_pem.as_str())
    );
    Ok(())
}

#[test]
fn federation_discovery_uses_srv_before_address_and_honors_no_service() {
    let mut state = FederationTrustState::new();
    let mut request = federation_discovery_request("node_srv.example");
    request.dns_srv_records = vec![
        FederationSrvRecord {
            priority: 20,
            weight: 10,
            target: "slow.example".to_owned(),
            port: 443,
        },
        FederationSrvRecord {
            priority: 10,
            weight: 0,
            target: "fast.example".to_owned(),
            port: 8443,
        },
    ];
    request.address_records = vec!["198.51.100.7".to_owned()];
    let rejected = state.resolve_discovery_result(&request, None, None);
    assert!(rejected.is_err());
    assert!(state.discovery_pin("node_srv.example").is_none());

    let mut no_service = federation_discovery_request("node_no_service.example");
    no_service.dns_srv_records =
        vec![FederationSrvRecord { priority: 0, weight: 0, target: ".".to_owned(), port: 0 }];
    no_service.address_records = vec!["198.51.100.8".to_owned()];
    let rejected = state.resolve_discovery_result(&no_service, None, None);
    assert!(rejected.is_err());
}

#[test]
fn federation_basic_discovery_without_verified_key_does_not_pin_fixture_key() {
    let mut state = FederationTrustState::new();
    let mut request = federation_discovery_request("node_unverified.example");
    request.address_records = vec!["198.51.100.9".to_owned()];
    let rejected = state.resolve_discovery_result(&request, None, None);
    assert!(rejected.is_err());
    assert!(state.discovery_pin("node_unverified.example").is_none());
}

#[test]
#[allow(clippy::too_many_lines)]
fn federation_handshake_requires_pinned_invitation_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = FederationTrustState::new();
    let peer_seed = seed_from_nonce(0x51, 7);
    let peer_public_key = ramflux_crypto::public_key_base64url_from_seed(peer_seed);
    let mut record = federation_server_record("node_pinned.example", "node-pinned:7443");
    record.node_public_key.clone_from(&peer_public_key);
    sign_federation_server_record_with_seed(&mut record, peer_seed)?;
    let request = federation_discovery_request("node_pinned.example");
    let discovered = state.resolve_discovery_result(&request, Some(&record), None)?;
    assert_eq!(discovered.pin_state, FederationPinState::Pinned);

    let key_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::FEDERATION_HANDSHAKE,
        peer_public_key.as_bytes(),
    );
    let route = FederationPeerRoute {
        node_id: "node_pinned.example".to_owned(),
        endpoint: "node-pinned:7443".to_owned(),
        node_public_key_hash: key_hash.clone(),
        node_capabilities: vec!["opaque_delivery".to_owned()],
        trust_status: FederationTrustStatus::Invited,
        updated_at: 1_760_000_000,
        expires_at: 1_760_086_400,
        route_update_proof_hash: "route_update_proof_hash".to_owned(),
    };
    let handshake =
        signed_federation_handshake("node_pinned.example", "node_local.example", peer_seed)?;
    let mut invitation = FederationNodeInvitation {
        invitation_id: "inv_pinned".to_owned(),
        inviter_node_id: "node_local.example".to_owned(),
        candidate_node_id: "node_pinned.example".to_owned(),
        candidate_node_public_key_hash: key_hash,
        candidate_node_public_key: peer_public_key.clone(),
        candidate_node_ca_cert_pem: test_federation_ca_pem(),
        allowed_capabilities: vec!["opaque_delivery".to_owned()],
        expires_at: 1_760_000_900,
        signature: String::new(),
    };
    invitation.signature = ramflux_crypto::sign_protocol_object_with_seed(&invitation, peer_seed)?;
    let admitted = state.admit_handshake(FederationHandshakeAdmissionRequest {
        route: route.clone(),
        handshake: handshake.clone(),
        invitation: Some(invitation),
        local_capabilities: vec!["opaque_delivery".to_owned()],
        local_protocol_versions: vec!["v1".to_owned()],
        local_transport_backends: vec!["quic_quinn".to_owned()],
        now: 1_760_000_010,
    })?;
    assert!(admitted.accepted);

    let bad_handshake = signed_federation_handshake(
        "node_pinned.example",
        "node_local.example",
        seed_from_nonce(0x66, 7),
    )?;
    let mut valid_invitation = FederationNodeInvitation {
        invitation_id: "inv_bad_handshake".to_owned(),
        inviter_node_id: "node_local.example".to_owned(),
        candidate_node_id: "node_pinned.example".to_owned(),
        candidate_node_public_key_hash: route.node_public_key_hash.clone(),
        candidate_node_public_key: peer_public_key.clone(),
        candidate_node_ca_cert_pem: test_federation_ca_pem(),
        allowed_capabilities: vec!["opaque_delivery".to_owned()],
        expires_at: 1_760_000_900,
        signature: String::new(),
    };
    valid_invitation.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&valid_invitation, peer_seed)?;
    let rejected_bad_handshake = state.admit_handshake(FederationHandshakeAdmissionRequest {
        route: route.clone(),
        handshake: bad_handshake,
        invitation: Some(valid_invitation),
        local_capabilities: vec!["opaque_delivery".to_owned()],
        local_protocol_versions: vec!["v1".to_owned()],
        local_transport_backends: vec!["quic_quinn".to_owned()],
        now: 1_760_000_011,
    });
    assert!(rejected_bad_handshake.is_err());

    let forged_public_key = ramflux_crypto::fixture_public_key_base64url();
    let mut forged = FederationNodeInvitation {
        invitation_id: "inv_forged".to_owned(),
        inviter_node_id: "node_local.example".to_owned(),
        candidate_node_id: "node_pinned.example".to_owned(),
        candidate_node_public_key_hash: route.node_public_key_hash.clone(),
        candidate_node_public_key: forged_public_key,
        candidate_node_ca_cert_pem: test_federation_ca_pem(),
        allowed_capabilities: vec!["opaque_delivery".to_owned()],
        expires_at: 1_760_000_900,
        signature: String::new(),
    };
    forged.signature = ramflux_crypto::sign_protocol_object(&forged)?;
    let rejected = state.admit_handshake(FederationHandshakeAdmissionRequest {
        route,
        handshake: signed_federation_handshake(
            "node_pinned.example",
            "node_local.example",
            peer_seed,
        )?,
        invitation: Some(forged),
        local_capabilities: vec!["opaque_delivery".to_owned()],
        local_protocol_versions: vec!["v1".to_owned()],
        local_transport_backends: vec!["quic_quinn".to_owned()],
        now: 1_760_000_011,
    });
    assert!(rejected.is_err());
    Ok(())
}

fn signed_federation_handshake(
    source_node_id: &str,
    target_node_id: &str,
    seed: [u8; 32],
) -> Result<ramflux_protocol::FederationHandshake, Box<dyn std::error::Error>> {
    let mut handshake = federation_handshake(source_node_id, target_node_id);
    handshake.signed.signing_key_id = format!("{source_node_id}#federation");
    handshake.signed.signature = String::new();
    handshake.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(&handshake, seed)?;
    Ok(handshake)
}

fn federation_handshake(
    source_node_id: &str,
    target_node_id: &str,
) -> ramflux_protocol::FederationHandshake {
    ramflux_protocol::FederationHandshake {
        schema: ramflux_protocol::domain::FEDERATION_HANDSHAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::FEDERATION_HANDSHAKE.to_owned(),
        ext: Ext::default(),
        signed: signed_fields(),
        handshake_id: format!("hs_{source_node_id}_{target_node_id}"),
        source_node_id: source_node_id.to_owned(),
        target_node_id: target_node_id.to_owned(),
        source_capabilities: vec!["opaque_delivery".to_owned()],
        protocol_versions: vec!["v1".to_owned()],
        transport_backends: vec!["quic_quinn".to_owned()],
        trust_state_hash: "trust_state_hash".to_owned(),
        nonce: "nonce_hs".to_owned(),
        created_at: 1_760_000_000,
    }
}

#[test]
fn federation_forward_requires_pinned_true_source_key() -> Result<(), Box<dyn std::error::Error>> {
    let source_seed = seed_from_nonce(0xa1, 4);
    let target_seed = seed_from_nonce(0xb2, 4);
    let source_public_key = ramflux_crypto::public_key_base64url_from_seed(source_seed);
    let target_public_key = ramflux_crypto::public_key_base64url_from_seed(target_seed);

    let mut source_state = FederationTrustState::new();
    let mut target_state = FederationTrustState::new();

    let mut node_b_record = federation_server_record("node_b.example", "node-b-federation:7443");
    node_b_record.node_public_key.clone_from(&target_public_key);
    sign_federation_server_record_with_seed(&mut node_b_record, target_seed)?;
    let discovered_b = source_state.resolve_discovery_result(
        &federation_discovery_request("node_b.example"),
        Some(&node_b_record),
        None,
    )?;
    assert_eq!(discovered_b.node_endpoint, "node-b-federation:7443");
    assert_eq!(discovered_b.node_public_key, target_public_key);

    let route_b = federation_route_with_key(
        "node_b.example",
        &target_public_key,
        "node-b-federation:7443",
        FederationTrustStatus::Invited,
    );
    source_state.admit_verified_discovered_peer(
        route_b,
        &["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        &["opaque_delivery".to_owned(), "federation_relay".to_owned()],
    )?;

    let route_a = federation_route_with_key(
        "node_a.example",
        &source_public_key,
        "node-a-federation:7443",
        FederationTrustStatus::Invited,
    );
    let handshake_a = signed_federation_handshake("node_a.example", "node_b.example", source_seed)?;
    let mut invitation_a = FederationNodeInvitation {
        invitation_id: "inv_node_a_to_b".to_owned(),
        inviter_node_id: "node_b.example".to_owned(),
        candidate_node_id: "node_a.example".to_owned(),
        candidate_node_public_key_hash: route_a.node_public_key_hash.clone(),
        candidate_node_public_key: source_public_key.clone(),
        candidate_node_ca_cert_pem: test_federation_ca_pem(),
        allowed_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        expires_at: 1_760_000_900,
        signature: String::new(),
    };
    invitation_a.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&invitation_a, source_seed)?;
    target_state.admit_handshake(FederationHandshakeAdmissionRequest {
        route: route_a,
        handshake: handshake_a,
        invitation: Some(invitation_a),
        local_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        local_protocol_versions: vec!["v1".to_owned()],
        local_transport_backends: vec!["quic_quinn".to_owned()],
        now: 1_760_000_020,
    })?;

    let mut forward = FederatedEnvelopeForwardRequest {
        signed: default_federation_forward_signed_fields(),
        admin_token: String::new(),
        source_node_id: "node_a.example".to_owned(),
        target_node_id: "node_b.example".to_owned(),
        delivery_class: "opaque_event".to_owned(),
        required_capability: "opaque_delivery".to_owned(),
        envelope: envelope("env_true_key_forward", "target_node_b", DeliveryClass::OpaqueEvent),
    };
    let mut self_attested_capability = forward.clone();
    self_attested_capability.required_capability = "federation_relay".to_owned();
    let mut capability_bypass_state = source_state.clone();
    capability_bypass_state
        .negotiated_capabilities_by_node
        .insert("node_b.example".to_owned(), BTreeSet::from(["federation_relay".to_owned()]));
    let rejected = capability_bypass_state.ensure_federated_envelope_allowed(
        &self_attested_capability,
        "node_b.example",
        1_760_000_020,
    );
    assert!(matches!(rejected, Err(NodeCoreError::ItestHttp(_))));

    source_state.ensure_federated_envelope_allowed(&forward, "node_b.example", 1_760_000_020)?;
    sign_federated_envelope_forward(&mut forward, source_seed)?;
    let pinned_a =
        target_state.pinned_node_public_key("node_a.example").ok_or("missing node_a pin")?;
    verify_federated_envelope_forward(&forward, &pinned_a)?;
    target_state.ensure_federated_envelope_allowed(&forward, "node_a.example", 1_760_000_020)?;

    let mut control_class = forward.clone();
    control_class.envelope.delivery_class = DeliveryClass::SelfDeviceControl;
    let rejected = target_state.ensure_federated_envelope_allowed(
        &control_class,
        "node_a.example",
        1_760_000_020,
    );
    assert!(matches!(rejected, Err(NodeCoreError::ItestHttp(_))));

    let wrong_key = ramflux_crypto::public_key_base64url_from_seed(seed_from_nonce(0xcc, 8));
    let rejected = verify_federated_envelope_forward(&forward, &wrong_key);
    assert!(rejected.is_err());
    Ok(())
}

fn federation_route_with_key(
    node_id: &str,
    node_public_key: &str,
    endpoint: &str,
    trust_status: FederationTrustStatus,
) -> FederationPeerRoute {
    FederationPeerRoute {
        node_id: node_id.to_owned(),
        endpoint: endpoint.to_owned(),
        node_public_key_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::FEDERATION_HANDSHAKE,
            node_public_key.as_bytes(),
        ),
        node_capabilities: vec!["opaque_delivery".to_owned()],
        trust_status,
        updated_at: 1_760_000_000,
        expires_at: 1_760_086_400,
        route_update_proof_hash: "route_update_proof_hash".to_owned(),
    }
}

fn federation_forward_request(
    envelope_id: &str,
    target_delivery_id: &str,
) -> FederatedEnvelopeForwardRequest {
    FederatedEnvelopeForwardRequest {
        signed: default_federation_forward_signed_fields(),
        admin_token: String::new(),
        source_node_id: "node_a.example".to_owned(),
        target_node_id: "node_b.example".to_owned(),
        delivery_class: "opaque_event".to_owned(),
        required_capability: "opaque_delivery".to_owned(),
        envelope: envelope(envelope_id, target_delivery_id, DeliveryClass::OpaqueEvent),
    }
}
