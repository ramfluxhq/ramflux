// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::EnvelopeAuthorityReason::StaleEpoch;

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
fn federation_redb_store_never_persists_node_signing_seed() -> Result<(), Box<dyn std::error::Error>>
{
    let path = temp_store_path("federation_redb_store_never_persists_node_signing_seed")?;
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
    assert_eq!(restored.node_signing_seed(), None);
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
    assert_eq!(reopened.list_pending_for_peer("node_b.example", 10)?.len(), 0);
    Ok(())
}

#[test]
fn federation_redb_store_dedups_inbound_forward_replay_persistently()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("federation_redb_store_dedups_inbound_forward_replay_persistently")?;
    let store = FederationRedbStore::open(&path)?;
    let mut forward_a = federation_forward_request("env_inbound_a", "target_inbound_a");
    let mut forward_b = federation_forward_request("env_inbound_b", "target_inbound_a");
    let mut forward_a_other_target =
        federation_forward_request("env_inbound_a", "target_inbound_b");
    for request in [&mut forward_a, &mut forward_b, &mut forward_a_other_target] {
        request.envelope = forwarded_source_envelope(request.envelope.clone())?;
    }
    let source = replay_source(&forward_a.envelope.source_device_id)?;
    let now = 1_760_000_010;

    assert!(store.accept_inbound_forward_once(&source, &forward_a, now)?);
    assert!(!store.accept_inbound_forward_once(&source, &forward_a, now + 1)?);
    assert!(store.accept_inbound_forward_once(&source, &forward_b, now + 2)?);
    assert!(store.accept_inbound_forward_once(&source, &forward_a_other_target, now + 3)?);

    drop(store);
    let reopened = FederationRedbStore::open(&path)?;
    assert!(!reopened.accept_inbound_forward_once(&source, &forward_a, now + 4)?);
    assert!(!reopened.accept_inbound_forward_once(&source, &forward_b, now + 5)?);
    assert!(!reopened.accept_inbound_forward_once(&source, &forward_a_other_target, now + 6)?);
    Ok(())
}

#[test]
fn inbound_forward_seen_record_survives_only_a_real_router_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("inbound_forward_seen_record_survives_only_a_real_router_commit")?;
    let store = FederationRedbStore::open(&path)?;
    let mut forward = federation_forward_request("env_inbound_commit", "target_inbound_commit");
    forward.envelope = forwarded_source_envelope(forward.envelope)?;
    let (_, source) = DeviceAuthKeyResponse::forwarded_envelope_source(&forward.envelope)?;
    let now = 1_760_000_010;

    let failed = store.deliver_inbound_forward_once(&source, &forward, now, || {
        Err(NodeCoreError::ItestHttp("router unavailable".into()))
    });
    assert!(failed.is_err());
    let rejected = store
        .deliver_inbound_forward_once(&source, &forward, now + 1, || {
            Ok(EnvelopeSubmitResponse {
                outcome: "rejected_capacity".into(),
                target_delivery_id: forward.envelope.target_delivery_id.clone(),
                inbox_seq: None,
                cursor: None,
                nack: None,
            })
        })?
        .ok_or("rejected delivery was incorrectly deduplicated")?;
    assert_eq!(rejected.outcome, "rejected_capacity");

    let router = RouterCore::new();
    let committed = store
        .deliver_inbound_forward_once(&source, &forward, now + 2, || {
            match router.submit_envelope_at(
                &source,
                forward.envelope.clone(),
                i64::try_from(now + 2).unwrap_or(i64::MAX),
            ) {
                RouterSubmitOutcome::OfflineQueued(queued) => Ok(EnvelopeSubmitResponse {
                    outcome: "offline_queued".into(),
                    target_delivery_id: queued.entry.target_delivery_id,
                    inbox_seq: Some(queued.entry.inbox_seq),
                    cursor: None,
                    nack: None,
                }),
                other => {
                    Err(NodeCoreError::ItestHttp(format!("unexpected router outcome: {other:?}")))
                }
            }
        })?
        .ok_or("committed delivery was incorrectly deduplicated")?;
    assert_eq!(committed.outcome, "offline_queued");
    assert_eq!(router.resume("target_inbound_commit", 0, 10).len(), 1);

    let duplicate = store.deliver_inbound_forward_once(&source, &forward, now + 3, || {
        Err(NodeCoreError::ItestHttp("duplicate must not reach router".into()))
    })?;
    assert!(duplicate.is_none());
    assert_eq!(router.resume("target_inbound_commit", 0, 10).len(), 1);
    Ok(())
}

#[test]
fn concurrent_inbound_forward_retry_is_pending_until_the_holder_commits()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("concurrent_inbound_forward_retry_is_pending")?;
    let store = std::sync::Arc::new(FederationRedbStore::open(&path)?);
    let mut forward = federation_forward_request("env_inbound_pending", "target_inbound_pending");
    forward.envelope = forwarded_source_envelope(forward.envelope)?;
    let (_, source) = DeviceAuthKeyResponse::forwarded_envelope_source(&forward.envelope)?;
    let now = 1_760_000_010;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder_store = std::sync::Arc::clone(&store);
    let holder_forward = forward.clone();
    let holder_source = source.clone();
    let holder = std::thread::spawn(move || {
        holder_store.deliver_inbound_forward_once(&holder_source, &holder_forward, now, || {
            entered_tx.send(()).map_err(|error| {
                NodeCoreError::ItestHttp(format!("holder signal failed: {error}"))
            })?;
            release_rx.recv().map_err(|error| {
                NodeCoreError::ItestHttp(format!("holder release failed: {error}"))
            })?;
            Ok(EnvelopeSubmitResponse {
                outcome: "offline_queued".into(),
                target_delivery_id: holder_forward.envelope.target_delivery_id.clone(),
                inbox_seq: Some(1),
                cursor: None,
                nack: None,
            })
        })
    });
    entered_rx.recv()?;

    let retry = store
        .deliver_inbound_forward_once(&source, &forward, now + 1, || {
            Err(NodeCoreError::ItestHttp("pending retry reached router".into()))
        })?
        .ok_or("pending retry was reported as committed")?;
    assert_eq!(retry.outcome, "forward_in_progress");
    assert_eq!(retry.inbox_seq, None);

    release_tx.send(())?;
    let committed = holder.join().map_err(|_| "holder panicked")??;
    assert_eq!(committed.ok_or("holder was deduplicated")?.outcome, "offline_queued");
    assert!(
        store
            .deliver_inbound_forward_once(&source, &forward, now + 2, || {
                Err(NodeCoreError::ItestHttp("committed retry reached router".into()))
            })?
            .is_none()
    );
    Ok(())
}

#[test]
fn expired_inbound_forward_lease_is_reclaimed_after_lost_holder()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("expired_inbound_forward_lease_is_reclaimed")?;
    let store = FederationRedbStore::open(&path)?;
    let mut forward = federation_forward_request("env_inbound_expired", "target_inbound_expired");
    forward.envelope = forwarded_source_envelope(forward.envelope)?;
    let (_, source) = DeviceAuthKeyResponse::forwarded_envelope_source(&forward.envelope)?;
    let now = 1_760_000_010;

    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _result = store.deliver_inbound_forward_once(&source, &forward, now, || {
            std::panic::resume_unwind(Box::new("simulated lost holder"))
        });
    }));
    assert!(crashed.is_err());
    let pending = store
        .deliver_inbound_forward_once(&source, &forward, now + 1, || {
            Err(NodeCoreError::ItestHttp("live lease reached router".into()))
        })?
        .ok_or("live lease was reported as committed")?;
    assert_eq!(pending.outcome, "forward_in_progress");

    let reclaimed = store
        .deliver_inbound_forward_once(&source, &forward, now + 20, || {
            Ok(EnvelopeSubmitResponse {
                outcome: "offline_queued".into(),
                target_delivery_id: forward.envelope.target_delivery_id.clone(),
                inbox_seq: Some(1),
                cursor: None,
                nack: None,
            })
        })?
        .ok_or("expired lease was not reclaimed")?;
    assert_eq!(reclaimed.outcome, "offline_queued");
    assert!(
        store
            .deliver_inbound_forward_once(&source, &forward, now + 21, || {
                Err(NodeCoreError::ItestHttp("committed retry reached router".into()))
            })?
            .is_none()
    );
    Ok(())
}

#[test]
fn legacy_inbound_seen_record_without_state_is_committed() -> Result<(), Box<dyn std::error::Error>>
{
    let record: FederationInboundForwardSeenRecord = serde_json::from_value(serde_json::json!({
        "seen_key": "legacy",
        "source_node_id": "node-a",
        "target_node_id": "node-b",
        "source_device_id": "device-a",
        "envelope_id": "envelope-a",
        "target_delivery_id": "target-b",
        "seen_at": 10,
        "expires_at": 20
    }))?;
    assert_eq!(record.state, FederationInboundForwardSeenState::Committed);
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

pub(super) fn federation_forward_request(
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

pub(super) fn root_bound_forward(
    root: &ramflux_crypto::IdentityRoot,
    device: &str,
    record: Option<ramflux_protocol::SignedDeviceSetRecord>,
    id: &str,
) -> Result<FederatedEnvelopeForwardRequest, Box<dyn std::error::Error>> {
    let mut forward = federation_forward_request(id, "root-replay-target");
    let open = gateway_open_frame(device, "root-forward");
    let mut authority = gateway_registered_key(&open)?;
    let devices = authority.signed_device_set.as_ref().ok_or("set")?.devices.clone();
    authority.principal_id = root.principal_id.clone();
    authority.root_public_key =
        Some(ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes()));
    authority.signed_device_set = Some(match record {
        Some(record) => record,
        None => ramflux_crypto::sign_device_set(
            root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                device_set_epoch: 1,
                devices,
            },
        )?,
    });
    let source = authority.authenticated_device_identity()?;
    forward.envelope.source_principal_id = root.principal_id.clone();
    forward.envelope.source_device_id = device.into();
    forward
        .envelope
        .ext
        .ext
        .insert("source_root_commitment".into(), serde_json::json!(source.root_commitment()));
    forward.envelope.signed.signature = ramflux_crypto::sign_protocol_object(&forward.envelope)?;
    forward
        .envelope
        .ext
        .ext
        .insert("source_device_authority".into(), serde_json::to_value(authority)?);
    Ok(forward)
}

#[test]
fn federated_replay_is_root_scoped_even_for_copied_device_and_branch_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("forwarded-root-scope")?;
    let store = FederationRedbStore::open(&path)?;
    let bob_root = ramflux_crypto::create_identity_root("bob", [0xb1; 32]);
    let mallory_root = ramflux_crypto::create_identity_root("mallory", [0xb2; 32]);
    let bob = root_bound_forward(&bob_root, "bob", None, "next-bob-envelope")?;
    let mallory = root_bound_forward(&mallory_root, "bob", None, "next-bob-envelope")?;
    let (_, bob_source) = DeviceAuthKeyResponse::forwarded_envelope_source(&bob.envelope)?;
    let (_, mallory_source) = DeviceAuthKeyResponse::forwarded_envelope_source(&mallory.envelope)?;
    assert_ne!(bob_source, mallory_source);
    assert!(store.accept_inbound_forward_once(&mallory_source, &mallory, 1_760_000_010)?);
    assert!(store.accept_inbound_forward_once(&bob_source, &bob, 1_760_000_010)?);
    assert!(!store.accept_inbound_forward_once(&bob_source, &bob, 1_760_000_011)?);
    let target = RouterCore::new();
    assert_eq!(
        target.authenticated_envelope_source_from(
            &bob.envelope,
            None,
            crate::RouterEnvelopeOrigin::Federation
        )?,
        bob_source
    );
    let mut forged = bob.envelope.clone();
    forged.ext.ext.insert(
        "source_device_authority".into(),
        mallory.envelope.ext.ext.get("source_device_authority").ok_or("authority")?.clone(),
    );
    assert!(
        target
            .authenticated_envelope_source_from(
                &forged,
                None,
                crate::RouterEnvelopeOrigin::Federation
            )
            .is_err()
    );
    drop(store);
    let reopened = FederationRedbStore::open(&path)?;
    assert!(!reopened.accept_inbound_forward_once(&bob_source, &bob, 1_760_000_012)?);
    assert!(!reopened.accept_inbound_forward_once(&mallory_source, &mallory, 1_760_000_012)?);
    Ok(())
}

#[test]
fn forwarded_old_authority_cannot_resurrect_a_revoked_device_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("forwarded-root-head")?;
    let store = FederationRedbStore::open(&path)?;
    let root = ramflux_crypto::create_identity_root("bob", [0xb1; 32]);
    let old = root_bound_forward(&root, "bob", None, "old-bob-envelope")?;
    let (authority, source) = DeviceAuthKeyResponse::forwarded_envelope_source(&old.envelope)?;
    let mut devices = authority.signed_device_set.ok_or("set")?.devices;
    devices[0].status = ramflux_protocol::DeviceSetStatus::Revoked;
    devices[0].revoked_at = Some(1_760_000_005);
    let mut phone = devices[0].clone();
    phone.device_id = "phone".into();
    phone.status = ramflux_protocol::DeviceSetStatus::Active;
    phone.revoked_at = None;
    devices.push(phone);
    let record = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 2,
            devices,
        },
    )?;
    let latest = root_bound_forward(&root, "phone", Some(record), "phone-envelope")?;
    let (_, phone_source) = DeviceAuthKeyResponse::forwarded_envelope_source(&latest.envelope)?;
    let router = RouterCore::new();
    router.authenticated_envelope_source_from(
        &latest.envelope,
        None,
        crate::RouterEnvelopeOrigin::Federation,
    )?;
    assert!(
        router
            .authenticated_envelope_source_from(
                &old.envelope,
                None,
                crate::RouterEnvelopeOrigin::Federation
            )
            .is_err()
    );
    let router_path = temp_store_path("router-forwarded-root-head")?;
    let router_store = crate::RouterRedbStore::open(&router_path)?;
    let durable_router = RouterCore::new();
    durable_router.authenticated_envelope_source_from(
        &latest.envelope,
        Some(&router_store),
        crate::RouterEnvelopeOrigin::Federation,
    )?;
    durable_router.authenticated_envelope_source_from(
        &latest.envelope,
        Some(&router_store),
        crate::RouterEnvelopeOrigin::Federation,
    )?;
    assert_eq!(router_store.identity_registry_write_count(), 0);
    assert_eq!(router_store.foreign_authority_write_count(), 1);
    drop(durable_router);
    drop(router_store);
    let router_store = crate::RouterRedbStore::open(&router_path)?;
    let restored = router_store.load_router()?.ok_or("router snapshot missing")?;
    assert!(
        restored
            .authenticated_envelope_source_from(
                &old.envelope,
                Some(&router_store),
                crate::RouterEnvelopeOrigin::Federation
            )
            .is_err()
    );
    assert!(store.accept_inbound_forward_once(&phone_source, &latest, 1_760_000_010)?);
    assert!(store.accept_inbound_forward_once(&source, &old, 1_760_000_011).is_err());
    drop(store);
    let reopened = FederationRedbStore::open(&path)?;
    assert!(reopened.accept_inbound_forward_once(&source, &old, 1_760_000_012).is_err());
    Ok(())
}

#[test]
fn foreign_epoch_fences_survive_capacity_and_restart_and_gateway_cannot_assert_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("victim", [0xa1; 32]);
    let old = root_bound_forward(&root, "victim", None, "victim-old")?;
    let (authority, old_source) = DeviceAuthKeyResponse::forwarded_envelope_source(&old.envelope)?;
    let mut devices = authority.signed_device_set.ok_or("set")?.devices;
    devices[0].status = ramflux_protocol::DeviceSetStatus::Revoked;
    devices[0].revoked_at = Some(1_760_000_005);
    let mut live = devices[0].clone();
    live.device_id = "phone".into();
    live.status = ramflux_protocol::DeviceSetStatus::Active;
    live.revoked_at = None;
    devices.push(live);
    let latest = root_bound_forward(
        &root,
        "phone",
        Some(ramflux_crypto::sign_device_set(
            &root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                device_set_epoch: 2,
                devices,
            },
        )?),
        "victim-new",
    )?;
    let (_, live_source) = DeviceAuthKeyResponse::forwarded_envelope_source(&latest.envelope)?;
    let router_path = temp_store_path("foreign-capacity-router")?;
    let federation_path = temp_store_path("foreign-capacity-federation")?;
    let router_store = crate::RouterRedbStore::open(&router_path)?;
    let federation_store = FederationRedbStore::open(&federation_path)?;
    let router = RouterCore::new();
    assert!(matches!(
        router.authenticated_envelope_source_durable(&latest.envelope, &router_store),
        Err(NodeCoreError::Unauthorized(_))
    ));
    router.authenticated_envelope_source_from(
        &latest.envelope,
        Some(&router_store),
        crate::RouterEnvelopeOrigin::Federation,
    )?;
    federation_store.accept_inbound_forward_once(&live_source, &latest, 1_760_000_010)?;
    flood_foreign_authority_cache(&router, &router_store, &federation_store)?;
    let (refused_old, refused_source) =
        refuse_new_root_with_permanent_fence(&router, &router_store, &federation_store)?;
    assert!(
        router
            .authenticated_envelope_source_from(
                &old.envelope,
                Some(&router_store),
                crate::RouterEnvelopeOrigin::Federation
            )
            .is_err()
    );
    assert!(
        federation_store.accept_inbound_forward_once(&old_source, &old, 1_760_000_012).is_err()
    );
    let router_writes = router_store.foreign_authority_write_count();
    let federation_writes = federation_store.foreign_authority_write_count();
    router.authenticated_envelope_source_from(
        &latest.envelope,
        Some(&router_store),
        crate::RouterEnvelopeOrigin::Federation,
    )?;
    assert!(!federation_store.accept_inbound_forward_once(&live_source, &latest, 1_760_000_013)?);
    assert_eq!(router_store.foreign_authority_write_count(), router_writes);
    assert_eq!(federation_store.foreign_authority_write_count(), federation_writes);
    assert_eq!(router_store.identity_registry_write_count(), 0);
    drop(router);
    drop(router_store);
    drop(federation_store);
    let router_store = crate::RouterRedbStore::open(&router_path)?;
    let router = router_store.load_router()?.ok_or("router")?;
    let federation_store = FederationRedbStore::open(&federation_path)?;
    assert!(matches!(
        router.authenticated_envelope_source_from(
            &refused_old.envelope,
            Some(&router_store),
            crate::RouterEnvelopeOrigin::Federation
        ),
        Err(NodeCoreError::SourceAuthorityRefused { reason_code: StaleEpoch })
    ));
    assert!(matches!(
        federation_store.accept_inbound_forward_once(&refused_source, &refused_old, 1_760_000_014),
        Err(NodeCoreError::SourceAuthorityRefused { reason_code: StaleEpoch })
    ));
    assert!(
        router
            .authenticated_envelope_source_from(
                &old.envelope,
                Some(&router_store),
                crate::RouterEnvelopeOrigin::Federation
            )
            .is_err()
    );
    assert!(
        federation_store.accept_inbound_forward_once(&old_source, &old, 1_760_000_014).is_err()
    );
    Ok(())
}

fn flood_foreign_authority_cache(
    router: &RouterCore,
    router_store: &RouterRedbStore,
    federation_store: &FederationRedbStore,
) -> Result<(), Box<dyn std::error::Error>> {
    for i in 0..=crate::foreign_device_heads::FOREIGN_HEAD_LIMIT {
        let seed = ramflux_crypto::blake3_256("ramflux.test.foreign.root.v1", &i.to_be_bytes());
        let fresh = ramflux_crypto::create_identity_root(&format!("foreign-{i}"), seed);
        let mut forward = root_bound_forward(&fresh, "device", None, &format!("new-{i}"))?;
        forward.source_node_id = format!("flood-peer-{}", i / 64);
        let (_, source) = DeviceAuthKeyResponse::forwarded_envelope_source(&forward.envelope)?;
        let router_result = router.authenticated_envelope_source_from(
            &forward.envelope,
            Some(router_store),
            crate::RouterEnvelopeOrigin::Federation,
        );
        let federation_result =
            federation_store.accept_inbound_forward_once(&source, &forward, 1_760_000_011);
        if i + 1 < crate::foreign_device_heads::FOREIGN_HEAD_LIMIT {
            router_result?;
            assert!(federation_result?);
        } else {
            assert!(matches!(
                router_result,
                Err(NodeCoreError::Capacity { resource: "foreign_device_sets" })
            ));
            assert!(matches!(
                federation_result,
                Err(NodeCoreError::Capacity { resource: "foreign_device_sets" })
            ));
        }
    }
    Ok(())
}
fn refuse_new_root_with_permanent_fence(
    router: &RouterCore,
    router_store: &RouterRedbStore,
    federation_store: &FederationRedbStore,
) -> Result<
    (FederatedEnvelopeForwardRequest, ramflux_crypto::RootQualifiedDeviceRef),
    Box<dyn std::error::Error>,
> {
    // An over-capacity root still leaves its compact highest-epoch fence behind.
    let refused_root = ramflux_crypto::create_identity_root("refused-root", [0xc1; 32]);
    let refused_old = root_bound_forward(&refused_root, "device", None, "refused-old")?;
    let (refused_authority, refused_source) =
        DeviceAuthKeyResponse::forwarded_envelope_source(&refused_old.envelope)?;
    let mut next_set = refused_authority.signed_device_set.ok_or("set")?;
    next_set.device_set_epoch = 2;
    let refused_new = root_bound_forward(
        &refused_root,
        "device",
        Some(ramflux_crypto::sign_device_set(
            &refused_root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: next_set.principal_kind,
                device_set_epoch: 2,
                devices: next_set.devices,
            },
        )?),
        "refused-new",
    )?;
    assert!(matches!(
        router.authenticated_envelope_source_from(
            &refused_new.envelope,
            Some(router_store),
            crate::RouterEnvelopeOrigin::Federation
        ),
        Err(NodeCoreError::Capacity { .. })
    ));
    assert!(matches!(
        federation_store.accept_inbound_forward_once(&refused_source, &refused_new, 1_760_000_012),
        Err(NodeCoreError::Capacity { .. })
    ));
    assert!(matches!(
        router.authenticated_envelope_source_from(
            &refused_old.envelope,
            Some(router_store),
            crate::RouterEnvelopeOrigin::Federation
        ),
        Err(NodeCoreError::SourceAuthorityRefused { reason_code: StaleEpoch })
    ));
    assert!(matches!(
        federation_store.accept_inbound_forward_once(&refused_source, &refused_old, 1_760_000_012),
        Err(NodeCoreError::SourceAuthorityRefused { reason_code: StaleEpoch })
    ));
    Ok((refused_old, refused_source))
}
