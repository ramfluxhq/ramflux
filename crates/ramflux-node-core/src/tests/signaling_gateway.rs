// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

#[test]
fn signaling_redb_store_restores_call_and_turn_state() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("signaling_redb_store_restores_call_and_turn_state")?;
    let store = SignalingRedbStore::open(&path)?;
    let mut state = SignalingState::new();
    state.submit_opaque_call_envelope(call_session("call_1"));
    state.activate_call("call_1")?;
    state.allocate_turn(turn_allocation("alloc_1", "call_1", "peer_b_hash"))?;
    store.save_state(&state)?;
    drop(store);

    let reopened = SignalingRedbStore::open(&path)?;
    let restored = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("signaling_state".to_owned()))?;
    assert_eq!(restored.active_call_count(), 1);
    assert_eq!(
        restored.allocation("alloc_1").map(|allocation| allocation.peer_hash.as_str()),
        Some("peer_b_hash")
    );
    assert!(!restored.srtp_media_key_visible("call_1"));
    Ok(())
}

#[test]
fn turn_credentials_validate_mac_ttl_and_replay() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = SignalingState::new();
    state.submit_opaque_call_envelope(call_session("call_cred"));
    state.activate_call("call_cred")?;
    let parts = TurnCredentialParts {
        call_session_id_hash: "call_cred".to_owned(),
        device_id_hash: "device_hash".to_owned(),
        issued_at: 1_760_000_010,
        nonce: "nonce_1".to_owned(),
    };
    let username = turn_username(&parts);
    let password = turn_credential_password(b"signaling-service-key", &username)?;
    let verified = state.validate_turn_credential(
        &username,
        &password,
        b"signaling-service-key",
        1_760_000_011,
    )?;
    assert_eq!(verified, parts);

    let replay = state.validate_turn_credential(
        &username,
        &password,
        b"signaling-service-key",
        1_760_000_012,
    );
    assert!(matches!(replay, Err(NodeCoreError::ReplayGuard(_))));

    let mut expired_state = SignalingState::new();
    expired_state.submit_opaque_call_envelope(call_session("call_cred"));
    expired_state.activate_call("call_cred")?;
    let expired = expired_state.validate_turn_credential(
        &username,
        &password,
        b"signaling-service-key",
        1_760_000_611,
    );
    assert!(matches!(expired, Err(NodeCoreError::TtlExpired { .. })));

    let bad_mac = expired_state.validate_turn_credential(
        &username,
        "bad-password",
        b"signaling-service-key",
        1_760_000_011,
    );
    assert!(matches!(bad_mac, Err(NodeCoreError::ItestHttp(message)) if message.contains("mac")));
    Ok(())
}

#[test]
fn relay_target_filter_rejects_internal_and_reserved_addresses()
-> Result<(), Box<dyn std::error::Error>> {
    let internal = ["10.1.0.5".parse()?];
    for blocked in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "169.254.169.254",
        "224.0.0.1",
        "192.0.2.10",
        "100.64.0.1",
        "10.1.0.5",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:10.1.0.5",
    ] {
        assert!(!relay_target_allowed(blocked.parse()?, &internal));
    }
    assert!(relay_target_allowed("8.8.8.8".parse()?, &internal));
    Ok(())
}

#[test]
fn turn_quota_limits_allocations_and_rate_windows() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = SignalingState::new();
    state.submit_opaque_call_envelope(call_session("call_quota"));
    state.activate_call("call_quota")?;
    let policy = TurnQuotaPolicy {
        max_allocations_per_username: 1,
        max_allocate_per_identity_per_minute: 1,
        max_allocate_per_source_ip_per_minute: 1,
        ..TurnQuotaPolicy::default()
    };
    state.record_allocate_attempt("identity_hash", "source_ip_hash", 1_760_000_001, &policy)?;
    let limited =
        state.record_allocate_attempt("identity_hash", "source_ip_hash", 1_760_000_002, &policy);
    assert!(matches!(limited, Err(NodeCoreError::ItestHttp(message)) if message.contains("rate")));

    state.allocate_turn_with_policy(
        turn_allocation("alloc_1", "call_quota", "peer_b_hash"),
        &policy,
    )?;
    let rejected = state.allocate_turn_with_policy(
        turn_allocation("alloc_2", "call_quota", "peer_b_hash"),
        &policy,
    );
    assert!(
        matches!(rejected, Err(NodeCoreError::ItestHttp(message)) if message.contains("username"))
    );
    Ok(())
}

#[test]
fn srtp_flow_bind_counts_only_bytes_and_never_media_key() -> Result<(), Box<dyn std::error::Error>>
{
    let mut state = SignalingState::new();
    state.submit_opaque_call_envelope(call_session("call_srtp"));
    state.activate_call("call_srtp")?;
    let mut alloc_a = turn_allocation("alloc_a", "call_srtp", "peer_b_hash");
    alloc_a.username_hash = "turn_username_hash_a".to_owned();
    let mut alloc_b = turn_allocation("alloc_b", "call_srtp", "peer_b_hash");
    alloc_b.username_hash = "turn_username_hash_b".to_owned();
    state.allocate_turn(alloc_a)?;
    state.allocate_turn(alloc_b)?;
    let flow = state.bind_srtp_relay_flow(
        "flow_1",
        "alloc_a",
        "alloc_b",
        1_760_000_010,
        &TurnQuotaPolicy::default(),
    )?;
    assert_eq!(flow.allocation_id_a, "alloc_a");
    let target = state.relay_srtp_packet("flow_1", "alloc_a", 1200, 1_760_000_011)?;
    assert_eq!(target, "alloc_b");
    let flow = state.srtp_flow("flow_1").ok_or("missing flow")?;
    assert_eq!(flow.bytes_a_to_b, 1200);
    assert_eq!(flow.packets_a_to_b, 1);
    assert!(!state.srtp_media_key_visible("call_srtp"));
    Ok(())
}

#[test]
fn turn_media_relay_token_binds_source_and_rejects_hijack() -> Result<(), Box<dyn std::error::Error>>
{
    let service_key = b"media-relay-service-key";
    let mut state = SignalingState::new();
    state.submit_opaque_call_envelope(call_session("call_media"));
    state.activate_call("call_media")?;
    let mut alloc_a = turn_allocation("alloc_a", "call_media", "peer_b_hash");
    alloc_a.identity_hash = "identity_a_hash".to_owned();
    let mut alloc_b = turn_allocation("alloc_b", "call_media", "peer_b_hash");
    alloc_b.identity_hash = "identity_b_hash".to_owned();
    state.allocate_turn(alloc_a)?;
    state.allocate_turn(alloc_b)?;
    state.bind_srtp_relay_flow(
        "flow_media",
        "alloc_a",
        "alloc_b",
        1_760_000_010,
        &TurnQuotaPolicy::default(),
    )?;
    let token = media_token(
        service_key,
        MediaTokenFixture {
            call_id: "call_media",
            allocation_id: "alloc_a",
            target_allocation_id: "alloc_b",
            flow_id: "flow_media",
            identity_hash: "identity_a_hash",
            peer_hash: "peer_b_hash",
        },
    )?;

    let target = state.validate_turn_media_packet(
        &token,
        "203.0.113.50:49152".parse()?,
        512,
        service_key,
        1_760_000_011,
    )?;

    assert_eq!(target, "alloc_b");
    assert_eq!(state.turn_allocation_source("alloc_a"), Some("203.0.113.50:49152"));
    let hijack = state.validate_turn_media_packet(
        &token,
        "203.0.113.51:49152".parse()?,
        512,
        service_key,
        1_760_000_012,
    );
    assert!(matches!(hijack, Err(NodeCoreError::ItestHttp(message)) if message.contains("source")));
    let allocation = state.allocation("alloc_a").ok_or("missing allocation")?;
    assert_eq!(allocation.bytes_relayed, 512);
    assert_eq!(allocation.packets_relayed, 1);
    Ok(())
}

#[test]
fn turn_media_relay_token_rejects_forgery_and_missing_permission()
-> Result<(), Box<dyn std::error::Error>> {
    let service_key = b"media-relay-service-key";
    let mut state = SignalingState::new();
    state.submit_opaque_call_envelope(call_session("call_media_reject"));
    state.activate_call("call_media_reject")?;
    let mut alloc_a = turn_allocation("alloc_a", "call_media_reject", "peer_b_hash");
    alloc_a.identity_hash = "identity_a_hash".to_owned();
    let mut alloc_b = turn_allocation("alloc_b", "call_media_reject", "peer_b_hash");
    alloc_b.identity_hash = "identity_b_hash".to_owned();
    alloc_b.username_hash = "turn_username_hash_b".to_owned();
    let mut alloc_c = turn_allocation("alloc_c", "call_media_reject", "peer_b_hash");
    alloc_c.identity_hash = "identity_c_hash".to_owned();
    alloc_c.username_hash = "turn_username_hash_c".to_owned();
    state.allocate_turn(alloc_a)?;
    state.allocate_turn(alloc_b)?;
    state.allocate_turn(alloc_c)?;
    state.bind_srtp_relay_flow(
        "flow_media_reject",
        "alloc_a",
        "alloc_b",
        1_760_000_010,
        &TurnQuotaPolicy::default(),
    )?;
    let mut forged = media_token(
        service_key,
        MediaTokenFixture {
            call_id: "call_media_reject",
            allocation_id: "alloc_a",
            target_allocation_id: "alloc_b",
            flow_id: "flow_media_reject",
            identity_hash: "identity_a_hash",
            peer_hash: "peer_b_hash",
        },
    )?;
    forged.mac = "forged".to_owned();
    let rejected_mac = state.validate_turn_media_packet(
        &forged,
        "203.0.113.60:49152".parse()?,
        256,
        service_key,
        1_760_000_011,
    );
    assert!(
        matches!(rejected_mac, Err(NodeCoreError::ItestHttp(message)) if message.contains("mac"))
    );

    let no_permission = media_token(
        service_key,
        MediaTokenFixture {
            call_id: "call_media_reject",
            allocation_id: "alloc_c",
            target_allocation_id: "alloc_b",
            flow_id: "flow_media_reject",
            identity_hash: "identity_c_hash",
            peer_hash: "peer_b_hash",
        },
    )?;
    let rejected_permission = state.validate_turn_media_packet(
        &no_permission,
        "203.0.113.61:49152".parse()?,
        256,
        service_key,
        1_760_000_011,
    );
    assert!(matches!(rejected_permission, Err(NodeCoreError::SessionNotFound(_))));
    assert_eq!(state.turn_allocation_source("alloc_c"), None);
    Ok(())
}

#[test]
fn turn_media_relay_ttl_purge_clears_allocation_source_and_flow()
-> Result<(), Box<dyn std::error::Error>> {
    let service_key = b"media-relay-service-key";
    let mut state = SignalingState::new();
    state.submit_opaque_call_envelope(call_session("call_media_ttl"));
    state.activate_call("call_media_ttl")?;
    let mut alloc_a = turn_allocation("alloc_a", "call_media_ttl", "peer_b_hash");
    alloc_a.identity_hash = "identity_a_hash".to_owned();
    alloc_a.expires_at = 1_760_000_020;
    let mut alloc_b = turn_allocation("alloc_b", "call_media_ttl", "peer_b_hash");
    alloc_b.identity_hash = "identity_b_hash".to_owned();
    alloc_b.expires_at = 1_760_000_030;
    state.allocate_turn(alloc_a)?;
    state.allocate_turn(alloc_b)?;
    state.bind_srtp_relay_flow(
        "flow_media_ttl",
        "alloc_a",
        "alloc_b",
        1_760_000_010,
        &TurnQuotaPolicy::default(),
    )?;
    let token = media_token(
        service_key,
        MediaTokenFixture {
            call_id: "call_media_ttl",
            allocation_id: "alloc_a",
            target_allocation_id: "alloc_b",
            flow_id: "flow_media_ttl",
            identity_hash: "identity_a_hash",
            peer_hash: "peer_b_hash",
        },
    )?;
    state.validate_turn_media_packet(
        &token,
        "203.0.113.70:49152".parse()?,
        128,
        service_key,
        1_760_000_011,
    )?;

    let expired = state.expire_turn_media_state(1_760_000_020);

    assert_eq!(expired, vec!["alloc_a".to_owned()]);
    assert_eq!(state.turn_allocation_source("alloc_a"), None);
    assert!(state.allocation("alloc_a").is_none());
    assert!(state.srtp_flow("flow_media_ttl").is_none());
    let rejected = state.validate_turn_media_packet(
        &token,
        "203.0.113.70:49152".parse()?,
        128,
        service_key,
        1_760_000_021,
    );
    assert!(matches!(rejected, Err(NodeCoreError::TtlExpired { .. })));
    Ok(())
}

#[test]
fn turn_media_relay_packet_round_trips_header_and_opaque_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let token = media_token(
        b"media-relay-service-key",
        MediaTokenFixture {
            call_id: "call_media",
            allocation_id: "alloc_a",
            target_allocation_id: "alloc_b",
            flow_id: "flow_packet",
            identity_hash: "identity_a_hash",
            peer_hash: "peer_b_hash",
        },
    )?;
    let header = TurnMediaRelayPacketHeader { token };
    let payload = b"opaque srtp packet bytes";

    let encoded = encode_turn_media_relay_packet(&header, payload)?;
    let decoded = decode_turn_media_relay_packet(&encoded)?;

    assert_eq!(decoded.header, header);
    assert_eq!(decoded.payload, payload);
    let oversized = vec![0_u8; TURN_MEDIA_RELAY_PACKET_MAX_BYTES + 1];
    assert!(decode_turn_media_relay_packet(&oversized).is_err());
    Ok(())
}

#[test]
fn gateway_redb_store_restores_session_and_delivery_frames()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("gateway_redb_store_restores_session_and_delivery_frames")?;
    let store = GatewayRedbStore::open(&path)?;
    let mut state = GatewayState::new();
    state.issue_challenge(pre_auth_challenge("challenge_1"));
    state.consume_challenge("challenge_1", 1_760_000_001)?;
    state.open_session(gateway_session("session_1"));
    state.mark_live("session_1", 1_760_000_010)?;
    state.deliver(GatewayFrame::Deliver {
        session_id: "session_1".to_owned(),
        envelope_id: "env_1".to_owned(),
        payload_hash: "payload_hash".to_owned(),
    })?;
    state.drain("session_1")?;
    store.save_state(&state)?;
    drop(store);

    let reopened = GatewayRedbStore::open(&path)?;
    let restored = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("gateway_state".to_owned()))?;
    assert_eq!(
        restored.session("session_1").map(|session| session.lifecycle.clone()),
        Some(GatewaySessionLifecycle::Draining)
    );
    assert_eq!(restored.queued_frame_count("session_1"), 2);
    Ok(())
}

#[test]
fn gateway_resume_token_is_bound_ttl_checked_and_persisted()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("gateway_resume_token_is_bound_ttl_checked_and_persisted")?;
    let store = GatewayRedbStore::open(&path)?;
    let mut state = GatewayState::new();
    state.open_session(gateway_session("session_resume"));
    let issued = state.issue_resume_token(GatewayResumeIssueInput {
        session_id: "session_resume",
        target_delivery_id: "target_a",
        device_id: "device_a",
        device_epoch: 1,
        issued_at: 1_760_000_000,
        window_seconds: 300,
    });
    assert_eq!(
        state
            .validate_resume_token_hash(GatewayResumeValidateInput {
                resume_token_hash: &gateway_resume_token_hash(&issued.token),
                previous_session_id: "session_resume",
                target_delivery_id: "target_a",
                device_id: "device_a",
                device_epoch: 1,
                now: 1_760_000_120,
                window_seconds: 300,
            })
            .map(|metadata| metadata.session_id),
        Some("session_resume".to_owned())
    );
    assert!(
        state
            .validate_resume_token_hash(GatewayResumeValidateInput {
                resume_token_hash: "forged_hash",
                previous_session_id: "session_resume",
                target_delivery_id: "target_a",
                device_id: "device_a",
                device_epoch: 1,
                now: 1_760_000_120,
                window_seconds: 300,
            })
            .is_none()
    );
    assert!(
        state
            .validate_resume_token_hash(GatewayResumeValidateInput {
                resume_token_hash: &gateway_resume_token_hash(&issued.token),
                previous_session_id: "session_resume",
                target_delivery_id: "target_a",
                device_id: "device_a",
                device_epoch: 1,
                now: 1_760_000_301,
                window_seconds: 300,
            })
            .is_none()
    );
    let refreshed = state.issue_resume_token(GatewayResumeIssueInput {
        session_id: "session_resume",
        target_delivery_id: "target_a",
        device_id: "device_a",
        device_epoch: 1,
        issued_at: 1_760_000_200,
        window_seconds: 300,
    });
    store.save_state(&state)?;
    drop(store);

    let reopened = GatewayRedbStore::open(&path)?;
    let mut restored = reopened
        .load_state()?
        .ok_or_else(|| NodeCoreError::SessionNotFound("gateway_state".to_owned()))?;
    assert!(
        restored
            .validate_resume_token_hash(GatewayResumeValidateInput {
                resume_token_hash: &gateway_resume_token_hash(&refreshed.token),
                previous_session_id: "session_resume",
                target_delivery_id: "target_a",
                device_id: "device_a",
                device_epoch: 1,
                now: 1_760_000_220,
                window_seconds: 300,
            })
            .is_some()
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct MediaTokenFixture<'a> {
    call_id: &'a str,
    allocation_id: &'a str,
    target_allocation_id: &'a str,
    flow_id: &'a str,
    identity_hash: &'a str,
    peer_hash: &'a str,
}

fn media_token(
    service_key: &[u8],
    fixture: MediaTokenFixture<'_>,
) -> Result<TurnMediaRelayToken, Box<dyn std::error::Error>> {
    Ok(sign_turn_media_relay_token(
        service_key,
        TurnMediaRelayToken {
            call_id: fixture.call_id.to_owned(),
            allocation_id: fixture.allocation_id.to_owned(),
            target_allocation_id: fixture.target_allocation_id.to_owned(),
            flow_id: fixture.flow_id.to_owned(),
            identity_hash: fixture.identity_hash.to_owned(),
            peer_hash: fixture.peer_hash.to_owned(),
            issued_at: 1_760_000_010,
            expires_at: 1_760_000_020,
            nonce: format!("nonce_{}_{}", fixture.allocation_id, fixture.flow_id),
            mac: String::new(),
        },
    )?)
}

#[test]
fn gateway_auth_replay_guard_rejects_duplicate_signed_request()
-> Result<(), Box<dyn std::error::Error>> {
    let open = gateway_open_frame("device_replay", "nonce_replay");
    let auth = gateway_auth_frame(&open, "request_replay", 1_760_000_000)?;
    let registered = ItestMvp1DeviceAuthKeyResponse {
        principal_id: "alice".to_owned(),
        device_id: open.device_id.clone(),
        device_epoch: 1,
        branch_public_key: ramflux_crypto::fixture_public_key_base64url(),
        target_delivery_id: open.target_delivery_id.clone(),
        revoked: false,
    };
    let mut replay_guard = NodeReplayGuardState::new();
    validate_gateway_auth_with_replay(&open, &auth, 1_760_000_001, &mut replay_guard, &registered)?;
    let rejected = validate_gateway_auth_with_replay(
        &open,
        &auth,
        1_760_000_002,
        &mut replay_guard,
        &registered,
    );
    assert!(rejected.is_err());
    assert_eq!(replay_guard.len(), 1);
    Ok(())
}

#[test]
fn gateway_auth_replay_guard_rejects_long_validity_signed_request_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let open = gateway_open_frame("device_replay_window", "nonce_replay_window");
    let mut auth = gateway_auth_frame(&open, "request_replay_window", 1_760_000_000)?;
    auth.signed_request.expires_at = auth.signed_request.created_at + 3_600;
    let mut replay_guard = NodeReplayGuardState::new();

    replay_guard
        .check_signed_request(&auth.signed_request, auth.signed_request.created_at + 901)?;
    let rejected = replay_guard
        .check_signed_request(&auth.signed_request, auth.signed_request.created_at + 902);

    assert!(matches!(rejected, Err(NodeCoreError::ReplayGuard(_))));
    assert_eq!(replay_guard.len(), 1);
    Ok(())
}

#[test]
fn gateway_auth_replay_guard_rejects_signed_request_validity_above_maximum()
-> Result<(), Box<dyn std::error::Error>> {
    let open = gateway_open_frame("device_replay_max", "nonce_replay_max");
    let mut auth = gateway_auth_frame(&open, "request_replay_max", 1_760_000_000)?;
    auth.signed_request.expires_at =
        auth.signed_request.created_at + ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS + 1;
    let mut replay_guard = NodeReplayGuardState::new();

    let rejected =
        replay_guard.check_signed_request(&auth.signed_request, auth.signed_request.created_at);

    assert!(matches!(rejected, Err(NodeCoreError::ReplayGuard(_))));
    assert_eq!(replay_guard.len(), 0);
    Ok(())
}

#[test]
fn gateway_auth_rejects_fixture_signature_when_registered_branch_key_differs()
-> Result<(), Box<dyn std::error::Error>> {
    let open = gateway_open_frame("device_branch_bound", "nonce_branch_bound");
    let auth = gateway_auth_frame(&open, "request_branch_bound", 1_760_000_000)?;
    let registered = ItestMvp1DeviceAuthKeyResponse {
        principal_id: "alice".to_owned(),
        device_id: open.device_id.clone(),
        device_epoch: 1,
        branch_public_key: ramflux_crypto::public_key_base64url_from_seed([0x42; 32]),
        target_delivery_id: open.target_delivery_id.clone(),
        revoked: false,
    };
    let mut replay_guard = NodeReplayGuardState::new();
    let rejected = validate_gateway_auth_with_replay(
        &open,
        &auth,
        1_760_000_001,
        &mut replay_guard,
        &registered,
    );
    assert!(rejected.is_err());
    assert_eq!(replay_guard.len(), 0);
    Ok(())
}

#[test]
fn mesh_spiffe_authorization_accepts_uri_san_identity() -> Result<(), Box<dyn std::error::Error>> {
    let allowed = BTreeSet::from(["ramflux-gateway".to_owned()]);
    let peer = authorize_mesh_peer(
        "ramflux-router",
        &allowed,
        Some("spiffe://localhost/ramflux-gateway"),
    )?;
    assert_eq!(peer.node_id, "localhost");
    assert_eq!(peer.service_id, "ramflux-gateway");
    Ok(())
}

#[test]
fn mesh_spiffe_authorization_rejects_dns_only_certificate_identity() {
    let allowed = BTreeSet::from(["ramflux-gateway".to_owned()]);
    let rejected = authorize_mesh_peer("ramflux-router", &allowed, None);
    assert!(
        matches!(rejected, Err(NodeCoreError::ItestHttp(message)) if message.contains("missing SPIFFE SAN"))
    );
}

#[test]
fn mesh_spiffe_authorization_rejects_service_mismatch() {
    let allowed = BTreeSet::from(["ramflux-signaling".to_owned()]);
    let rejected =
        authorize_mesh_peer("ramflux-router", &allowed, Some("spiffe://node-a/ramflux-signaling"));
    assert!(matches!(rejected, Err(NodeCoreError::MeshPeerUnauthorized { .. })));
}

#[test]
fn gateway_preauth_cookie_rate_limit_and_metrics() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = GatewayState::new();
    state.set_pre_auth_policy(GatewayPreAuthPolicy {
        enabled: true,
        per_source_ip_handshake_rate: 1,
        window_seconds: 60,
        cookie_ttl_seconds: 10,
        auth_deadline_ms: 1_000,
        cookie_secret: DEFAULT_PRE_AUTH_COOKIE_SECRET.to_owned(),
    });
    let source = source_ip_hash("127.0.0.1");
    assert_eq!(
        state.check_pre_auth(&source, None, 1_760_000_000)?,
        GatewayPreAuthDecision::Accepted
    );
    let challenge = match state.check_pre_auth(&source, None, 1_760_000_001)? {
        GatewayPreAuthDecision::Challenge(challenge) => challenge,
        GatewayPreAuthDecision::Accepted => {
            return Err("expected pre-auth challenge".into());
        }
    };
    assert_eq!(state.pre_auth_metrics().pre_auth_cookie_required, 1);
    assert_eq!(
        state.check_pre_auth(&source, Some(&challenge.pre_auth_cookie), 1_760_000_002)?,
        GatewayPreAuthDecision::Accepted
    );
    assert!(state.check_pre_auth(&source, Some("forged-cookie"), 1_760_000_003).is_err());
    let expired = sign_pre_auth_cookie(
        &source,
        PRE_AUTH_PROTOCOL_VERSION,
        1_760_000_000,
        DEFAULT_PRE_AUTH_COOKIE_SECRET,
    );
    assert!(state.check_pre_auth(&source, Some(&expired), 1_760_000_020).is_err());
    state.record_slowloris_timeout();
    assert_eq!(state.pre_auth_metrics().pre_auth_cookie_failed, 2);
    assert_eq!(state.pre_auth_metrics().deviceproof_rate_limited, 1);
    assert_eq!(state.pre_auth_metrics().slowloris_auth_timeout, 1);
    Ok(())
}
