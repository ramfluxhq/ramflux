// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;

pub(super) fn assert_incomplete_request_times_out(
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let handle = std::thread::spawn(move || -> Result<String, String> {
        let (mut stream, _) = listener.accept().map_err(|source| source.to_string())?;
        match read_itest_http_request_with_timeout(&mut stream, Duration::from_millis(100)) {
            Ok(Some(request)) => Err(format!("parsed incomplete request {}", request.path)),
            Ok(None) => Ok("incomplete request timed out".to_owned()),
            Err(error) => Err(error.to_string()),
        }
    });
    let mut client = TcpStream::connect(addr)?;
    client.write_all(bytes)?;
    let message = handle.join().map_err(|_| "reader thread panicked")??;
    assert_eq!(message, "incomplete request timed out");
    Ok(())
}

pub(super) fn lifecycle_request(
    principal_id: &str,
    event_id: &str,
    event_type: &str,
    lifecycle_epoch: u64,
    now: u64,
    timelock_seconds: Option<u64>,
) -> ItestMvp7LifecycleRequest {
    ItestMvp7LifecycleRequest {
        principal_id: principal_id.to_owned(),
        event_id: event_id.to_owned(),
        event_type: event_type.to_owned(),
        actor_device_id: "device_delete".to_owned(),
        lifecycle_epoch,
        now,
        reason_code: "user_requested".to_owned(),
        timelock_seconds,
        recovery_quorum: None,
        recovery_quorum_proof: None,
    }
}

pub(super) fn retention_record(
    record_id: &str,
    subject_hash: &str,
    expires_at: u64,
    legal_hold: bool,
) -> RetentionMetadataRecord {
    RetentionMetadataRecord {
        record_id: record_id.to_owned(),
        subject_hash: subject_hash.to_owned(),
        metadata_class: "router_inbox".to_owned(),
        source_service_id: "ramflux-router".to_owned(),
        retention_policy_id: "metadata.default_short".to_owned(),
        created_at: 1_760_000_000,
        expires_at,
        delete_after_ack: None,
        legal_hold,
        legal_hold_next_review_at: legal_hold.then_some(1_760_000_000 + 180 * 24 * 60 * 60),
        legal_basis: legal_hold.then_some("litigation_hold".to_owned()),
        legal_hold_actor: legal_hold.then_some("legal@example".to_owned()),
        legal_hold_created_at: legal_hold.then_some(1_760_000_000),
        metadata_hash: format!("hash_{record_id}"),
    }
}

pub(super) fn session(
    target_delivery_id: &str,
    lifecycle: SessionLifecycle,
    device_epoch: u64,
    session_seq: u64,
) -> SessionDescriptor {
    SessionDescriptor {
        target_delivery_id: target_delivery_id.to_owned(),
        device_id: "device_a".to_owned(),
        gateway_id: "gateway_a".to_owned(),
        session_id: "session_a".to_owned(),
        device_epoch,
        session_seq,
        last_cursor: Some("cursor_a".to_owned()),
        push_alias_hash: Some("push_alias_hash_a".to_owned()),
        lifecycle,
    }
}

pub(super) fn registration_request(
    principal_id: &str,
    device_id: &str,
    nonce: u64,
    registration_pow: Option<ItestRegistrationPowProof>,
    source_ip: &str,
) -> Result<ItestMvp1RegisterIdentityRequest, Box<dyn std::error::Error>> {
    let root_seed = seed_from_nonce(0x31, nonce);
    let device_seed = seed_from_nonce(0x41, nonce);
    let root = ramflux_crypto::create_identity_root(principal_id, root_seed);
    let device = ramflux_crypto::create_device_branch(principal_id, device_id, 1, device_seed);
    let proof = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        ITEST_MVP1_AUDIENCE,
        vec![ITEST_MVP1_BIND_CAPABILITY.to_owned()],
        1_760_000_000 + i64::try_from(nonce)?,
        1_760_003_600 + i64::try_from(nonce)?,
    )?;
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
    Ok(ItestMvp1RegisterIdentityRequest {
        principal_commitment: ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.root_public_key.commitment.v1",
            &root_public_key_bytes,
        ),
        root_public_key,
        branch_public_key: ramflux_protocol::encode_base64url(
            device.signing_key.verifying_key().to_bytes(),
        ),
        proof,
        target_delivery_id: format!("target_{principal_id}"),
        gateway_id: "ramflux-gateway".to_owned(),
        session_id: format!("session_{principal_id}"),
        push_alias_hash: Some(format!("push_{principal_id}")),
        now: 1_760_000_010 + i64::try_from(nonce)?,
        registration_pow,
        source_ip_hash: Some(source_ip_hash(source_ip)),
    })
}

pub(super) fn solved_pow(principal_id: &str, difficulty_bits: u8) -> ItestRegistrationPowProof {
    ItestRegistrationPowProof {
        nonce: ramflux_crypto::solve_registration_pow(principal_id, difficulty_bits),
        difficulty_bits,
    }
}

pub(super) fn friend_request(
    source_principal_id: &str,
    target_principal_id: &str,
    now: i64,
) -> ItestMvp6FriendRequestBudgetRequest {
    ItestMvp6FriendRequestBudgetRequest {
        source_principal_id: source_principal_id.to_owned(),
        target_principal_id: target_principal_id.to_owned(),
        now,
    }
}

pub(super) fn abuse_report(report_id: &str) -> AbuseReportRequest {
    AbuseReportRequest {
        report_id: report_id.to_owned(),
        reporter_identity: "reporter_keyed".to_owned(),
        reported_identity: "reported_keyed".to_owned(),
        reported_node: "node_keyed.example".to_owned(),
        selected_evidence: SelectedFrankingEvidence {
            evidence_kind: FrankingEvidenceKind::ReceiverAttestedDm,
            plaintext_excerpt: "selected excerpt".to_owned(),
            opening_key: "invalid_opening_key".to_owned(),
            commitment_key: "invalid_commitment_key".to_owned(),
            sender_device_id_hash: "invalid_sender_hash".to_owned(),
            msg_event_id: "msg_keyed".to_owned(),
            canonical_header_bytes: "invalid_header".to_owned(),
            associated_data: "invalid_ad".to_owned(),
            ciphertext: "invalid_ciphertext".to_owned(),
            header_hash: "invalid_header_hash".to_owned(),
            associated_data_hash: "invalid_ad_hash".to_owned(),
            ciphertext_hash: "invalid_cipher_hash".to_owned(),
            franking_commitment: "invalid_franking_commitment".to_owned(),
            commitment: "invalid_commitment".to_owned(),
            franking_tag: "invalid_tag".to_owned(),
            franking_timestamp: 1_760_000_500,
            group_header_signature: None,
        },
        submitted_at: 1_760_000_500,
    }
}

pub(super) fn seed_from_nonce(prefix: u8, nonce: u64) -> [u8; 32] {
    let mut seed = [prefix; 32];
    seed[24..].copy_from_slice(&nonce.to_be_bytes());
    seed
}

pub(super) fn envelope(
    envelope_id: &str,
    target_delivery_id: &str,
    delivery_class: DeliveryClass,
) -> Envelope {
    Envelope {
        schema: "ramflux.envelope.v1".to_owned(),
        version: 1,
        domain: "ramflux.envelope.v1".to_owned(),
        ext: Ext::default(),
        signed: signed_fields(),
        envelope_id: envelope_id.to_owned(),
        source_principal_id: "alice".to_owned(),
        source_device_id: "alice_device".to_owned(),
        target_delivery_id: target_delivery_id.to_owned(),
        routing_set_id: None,
        delivery_class,
        priority: Priority::Normal,
        ttl: 3_600,
        created_at: 1_760_000_000,
        encrypted_payload: "ciphertext".to_owned(),
        payload_hash: "payload_hash".to_owned(),
    }
}

pub(super) fn ack(envelope_id: &str) -> Ack {
    Ack {
        schema: "ramflux.ack.v1".to_owned(),
        version: 1,
        domain: "ramflux.ack.v1".to_owned(),
        ext: Ext::default(),
        signed: signed_fields(),
        ack_id: format!("ack_{envelope_id}"),
        envelope_id: envelope_id.to_owned(),
        receiver_device_id: "device_a".to_owned(),
        received_at: 1_760_000_010,
        cursor_after: None,
    }
}

pub(super) fn nack(envelope_id: &str, reason: NackReason) -> Nack {
    Nack {
        schema: "ramflux.nack.v1".to_owned(),
        version: 1,
        domain: "ramflux.nack.v1".to_owned(),
        ext: Ext::default(),
        signed: signed_fields(),
        nack_id: format!("nack_{envelope_id}"),
        envelope_id: envelope_id.to_owned(),
        receiver_device_id: "device_a".to_owned(),
        reason,
        received_at: 1_760_000_010,
        retry_after: Some(30),
    }
}

pub(super) fn signed_fields() -> SignedFields {
    SignedFields {
        signing_key_id: "fixture".to_owned(),
        signature_alg: SignatureAlg::Ed25519,
        signature: "sig".to_owned(),
    }
}

pub(super) fn security_incident(incident_id: &str) -> SecurityIncident {
    SecurityIncident {
        incident_id: incident_id.to_owned(),
        incident_class: "service_auth_failed".to_owned(),
        source_service_id: "ramflux-gateway".to_owned(),
        subject_hash: "subject_hash".to_owned(),
        severity: IncidentSeverity::High,
        occurred_at: 1_760_000_000,
        expires_at: 1_791_536_000,
        retention_policy_id: "security_incident_log.default_12_months".to_owned(),
        metadata_hash: "metadata_hash".to_owned(),
    }
}

pub(super) fn rate_limit_abuse(bucket_id: &str) -> RateLimitAbuseMetadata {
    RateLimitAbuseMetadata {
        bucket_id: bucket_id.to_owned(),
        source_service_id: "ramflux-gateway".to_owned(),
        abuse_signal: "deviceproof_rate_limited".to_owned(),
        subject_hash: "subject_hash".to_owned(),
        attempt_count: 3,
        window_started_at: 1_760_000_000,
        window_expires_at: 1_762_592_000,
        retention_policy_id: "rate_limit_abuse_metadata.default_30_days".to_owned(),
    }
}

pub(super) fn notification_wake(wake_id: &str, ttl: u32) -> ramflux_protocol::NotificationWake {
    ramflux_protocol::NotificationWake {
        schema: "ramflux.notification_wake.v1".to_owned(),
        version: 1,
        domain: "ramflux.notification_wake.v1".to_owned(),
        ext: Ext::default(),
        signed: signed_fields(),
        wake_id: wake_id.to_owned(),
        push_alias: "push_alias_raw_notify_only".to_owned(),
        delivery_class: ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification,
        priority: ramflux_protocol::PushPriority::Normal,
        ttl,
        collapse_key: Some("collapse_self_device".to_owned()),
        encrypted_hint: Some("encrypted_hint".to_owned()),
    }
}

pub(super) fn notify_attempt(queue_id: &str, accepted: bool) -> ProviderPushAttempt {
    ProviderPushAttempt {
        queue_id: queue_id.to_owned(),
        device_delivery_id: "device_notify_test".to_owned(),
        provider: PushProviderKind::WebPush,
        push_alias_hash: "push_alias_hash".to_owned(),
        collapse_key_hash: "collapse_key_hash".to_owned(),
        delivery_class: ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification,
        action: if accepted {
            NotifyDeliveryAction::Accept
        } else {
            NotifyDeliveryAction::ProviderRejected
        },
        sent_at: 1_760_000_001,
        accepted,
        error_class: (!accepted).then(|| "provider_rejected".to_owned()),
    }
}

pub(super) fn notify_webpush_credential(credential_id: &str) -> ProviderCredential {
    ProviderCredential::WebPush(WebPushProviderCredential {
        credential_id: credential_id.to_owned(),
        vapid_public_key_ref: "env:VAPID_PUBLIC".to_owned(),
        vapid_private_key_ref: "env:VAPID_PRIVATE".to_owned(),
        subject: "mailto:ops@example.test".to_owned(),
        provider_ca_pem_ref: None,
    })
}

pub(super) fn notify_webpush_route(
    device_delivery_id: &str,
    credential_id: &str,
) -> DevicePushRoute {
    DevicePushRoute {
        device_delivery_id: device_delivery_id.to_owned(),
        provider: PushProviderKind::WebPush,
        credential_id: Some(credential_id.to_owned()),
        token: "webpush_token".to_owned(),
        endpoint: "https://push.example.test:443/webpush".to_owned(),
        webpush_p256dh: None,
        webpush_auth: None,
        registered_at: 1_760_000_000,
        expires_at: 1_760_010_000,
    }
}

pub(super) fn relay_chunk(chunk_id: &str, stored_at: u64, ttl: u64) -> RelayChunkEntry {
    RelayChunkEntry {
        chunk_id: chunk_id.to_owned(),
        object_id: "object_1".to_owned(),
        manifest_hash: "manifest_hash".to_owned(),
        chunk_index: 0,
        chunk_cipher_hash: "chunk_cipher_hash".to_owned(),
        encrypted_chunk: b"encrypted chunk bytes".to_vec(),
        stored_at,
        expires_at: stored_at.saturating_add(ttl),
        delete_after_ack: false,
        acked_by: std::collections::BTreeSet::new(),
        status: RelayChunkStatus::Available,
    }
}

pub(super) fn federation_route(
    node_id: &str,
    trust_status: FederationTrustStatus,
) -> FederationPeerRoute {
    FederationPeerRoute {
        node_id: node_id.to_owned(),
        endpoint: format!("https://{node_id}"),
        node_public_key_hash: "node_public_key_hash".to_owned(),
        node_capabilities: vec!["opaque_delivery".to_owned()],
        trust_status,
        updated_at: 1_760_000_000,
        expires_at: 1_762_592_000,
        route_update_proof_hash: "route_update_proof_hash".to_owned(),
    }
}

pub(super) fn federation_discovery_request(node_id: &str) -> FederationDiscoveryRequest {
    FederationDiscoveryRequest {
        node_id: node_id.to_owned(),
        now: 1_760_000_020,
        invite_endpoint: None,
        well_known_url: None,
        dns_srv_records: Vec::new(),
        address_records: Vec::new(),
        directory_endpoint: None,
    }
}

pub(super) fn federation_server_record(node_id: &str, endpoint: &str) -> FederationServerRecord {
    FederationServerRecord {
        schema: "ramflux.well_known_server.v1".to_owned(),
        node_id: node_id.to_owned(),
        node_public_key: ramflux_crypto::fixture_public_key_base64url(),
        node_ca_cert_pem: test_federation_ca_pem(),
        node_endpoint: endpoint.to_owned(),
        protocol_versions: vec!["v1".to_owned()],
        transport_backends: vec!["quic_quinn".to_owned(), "https_json".to_owned()],
        node_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        node_policy_hash: "node_policy_hash".to_owned(),
        updated_at: 1_760_000_000,
        expires_at: 1_760_086_400,
        signature: String::new(),
    }
}

pub(super) fn test_federation_ca_pem() -> String {
    include_str!("../../../../deploy/certs/ca.pem").to_owned()
}

pub(super) fn call_session(call_id: &str) -> OpaqueCallSession {
    OpaqueCallSession {
        call_id: call_id.to_owned(),
        caller_device_hash: "caller_hash".to_owned(),
        callee_device_hash: "callee_hash".to_owned(),
        allowed_peer_hashes: BTreeSet::from(["peer_b_hash".to_owned()]),
        created_at: 1_760_000_000,
        expires_at: 1_760_003_600,
        lifecycle: CallSessionLifecycle::Pending,
        opaque_envelope_hash: "opaque_envelope_hash".to_owned(),
    }
}

pub(super) fn turn_allocation(
    allocation_id: &str,
    call_id: &str,
    peer_hash: &str,
) -> TurnAllocation {
    TurnAllocation {
        allocation_id: allocation_id.to_owned(),
        call_id: call_id.to_owned(),
        username_hash: "turn_username_hash".to_owned(),
        identity_hash: "identity_hash".to_owned(),
        peer_hash: peer_hash.to_owned(),
        source_ip_hash: "source_ip_hash".to_owned(),
        relay_address: "203.0.113.10:49152".to_owned(),
        bandwidth_limit_bps: 2_000_000,
        burst_limit_bps: 4_000_000,
        created_at: 1_760_000_001,
        expires_at: 1_760_000_601,
        bytes_relayed: 0,
        packets_relayed: 0,
    }
}

pub(super) fn pre_auth_challenge(challenge_id: &str) -> PreAuthChallenge {
    PreAuthChallenge {
        challenge_id: challenge_id.to_owned(),
        source_ip_hash: "source_ip_hash".to_owned(),
        issued_at: 1_760_000_000,
        expires_at: 1_760_000_030,
        used: false,
    }
}

pub(super) fn gateway_session(session_id: &str) -> GatewaySession {
    GatewaySession {
        session_id: session_id.to_owned(),
        target_delivery_id: "target_a".to_owned(),
        device_id: "device_a".to_owned(),
        opened_at: 1_760_000_001,
        last_heartbeat_at: 1_760_000_001,
        lifecycle: GatewaySessionLifecycle::Authed,
    }
}

pub(super) fn gateway_open_frame(device_id: &str, stream_nonce: &str) -> GatewayOpenFrame {
    GatewayOpenFrame {
        protocol_version: GATEWAY_SESSION_PROTOCOL_VERSION.to_owned(),
        transport_kind: "quic_quinn".to_owned(),
        client_instance_id: "client_a".to_owned(),
        device_id: device_id.to_owned(),
        target_delivery_id: "target_a".to_owned(),
        stream_nonce: stream_nonce.to_owned(),
        previous_session_id: None,
        resume_token_hash: None,
        last_seen_inbox_seq: None,
        max_inflight_downstream: 32,
        max_inflight_upstream: 32,
        pre_auth_cookie: None,
        pre_auth_now: None,
        source_ip_hash: None,
    }
}

pub(super) fn gateway_auth_frame(
    open: &GatewayOpenFrame,
    request_id: &str,
    now: i64,
) -> Result<GatewayAuthFrame, Box<dyn std::error::Error>> {
    gateway_auth_frame_with_seed(open, request_id, now, ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES)
}

pub(super) fn gateway_auth_frame_with_seed(
    open: &GatewayOpenFrame,
    request_id: &str,
    now: i64,
    seed: [u8; 32],
) -> Result<GatewayAuthFrame, Box<dyn std::error::Error>> {
    let mut device_proof = ramflux_protocol::DeviceProof {
        schema: "ramflux.device_proof.v1".to_owned(),
        version: 1,
        domain: "ramflux.device_proof.v1".to_owned(),
        ext: Ext::default(),
        signed: signed_fields(),
        principal_id: "alice".to_owned(),
        device_id: open.device_id.clone(),
        device_epoch: 1,
        branch_proof_hash: "branch_proof_hash".to_owned(),
        capability_scope: vec!["gateway_session".to_owned()],
        nonce: open.stream_nonce.clone(),
        expires_at: now + 60,
    };
    device_proof.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&device_proof, seed)?;
    let device_proof_bytes = ramflux_protocol::canonical_json_bytes(&device_proof)?;
    let device_proof_hash =
        ramflux_crypto::blake3_256_base64url(GATEWAY_DEVICE_PROOF_HASH_DOMAIN, &device_proof_bytes);
    let mut signed_request = ramflux_protocol::SignedRequest {
        schema: "ramflux.signed_request.v1".to_owned(),
        version: 1,
        domain: "ramflux.signed_request.v1".to_owned(),
        ext: Ext::default(),
        signed: signed_fields(),
        source_device_id: open.device_id.clone(),
        request_id: request_id.to_owned(),
        method: ramflux_protocol::HttpMethod::POST,
        path: "/gateway/open".to_owned(),
        device_proof_hash,
        body_hash: gateway_open_hash(open),
        nonce: open.stream_nonce.clone(),
        created_at: now,
        expires_at: now + 60,
    };
    signed_request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&signed_request, seed)?;
    Ok(GatewayAuthFrame { signed_request, device_proof })
}

pub(super) fn temp_store_path(test_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let path = std::env::temp_dir().join(format!(
        "ramflux-node-core-{test_name}-{}-{}.redb",
        std::process::id(),
        elapsed.as_nanos()
    ));
    Ok(path)
}
