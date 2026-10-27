// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source pinning, return routability and quota ownership at the production routing boundary.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn spoofed_keepalive_and_copied_tokens_cannot_redirect_a_pinned_voice_endpoint() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = pair(&mut state, "node", &scope(1), "relay:9000", 100)?;
    let a = "8.8.8.8:1000".parse()?;
    let b = "1.1.1.1:2000".parse()?;
    let attacker = "9.9.9.9:3000".parse()?;
    let bind = encode_voice_datagram(&lease.callee_token, &[])?;
    state.route(&bind, b, 100, false)?;
    for payload in [&[][..], &b"copied-token-media"[..]] {
        let packet = encode_voice_datagram(&lease.callee_token, payload)?;
        let decision = state.route_with_rebinding(&packet, attacker, 101, false)?;
        assert!(!matches!(decision, VoiceRoute::Forward { .. }));
        let media = encode_voice_datagram(&lease.caller_token, b"opaque")?;
        assert_eq!(state.route(&media, a, 101, false)?, Some((b, &b"opaque"[..])));
    }
    Ok(())
}
#[test]
fn unpinned_traffic_cannot_spend_the_pinned_sources_bandwidth() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = pair(&mut state, "node", &scope(1), "relay:9000", 100)?;
    let pinned = "8.8.8.8:1000".parse()?;
    let attacker = "9.9.9.9:3000".parse()?;
    state.route(&encode_voice_datagram(&lease.caller_token, &[])?, pinned, 101, false)?;
    let packet = encode_voice_datagram(&lease.caller_token, &[0; VOICE_PACKET_MAX_BYTES])?;
    for _ in 0..2 {
        state.route_with_rebinding(&packet, attacker, 101, false)?;
    }
    assert!(state.route_with_rebinding(&packet, attacker, 101, false).is_err());
    for _ in 0..91 {
        state.route(&packet, pinned, 101, false)?;
    }
    assert!(state.route(&packet, pinned, 101, false).is_err());
    Ok(())
}
#[test]
fn rebinding_challenges_require_a_sixty_byte_datagram() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = pair(&mut state, "node", &scope(1), "relay:9000", 100)?;
    let old = "1.1.1.1:2000".parse()?;
    let new = "9.9.9.9:3000".parse()?;
    state.route(&encode_voice_datagram(&lease.callee_token, &[])?, old, 100, false)?;
    let short = encode_voice_datagram(&lease.callee_token, &[0; 23])?;
    assert_eq!(short.len(), 59);
    assert_eq!(state.route_with_rebinding(&short, new, 101, false)?, VoiceRoute::Drop);
    let minimum = encode_voice_datagram(&lease.callee_token, &[0; 24])?;
    assert_eq!(minimum.len(), 60);
    assert!(matches!(
        state.route_with_rebinding(&minimum, new, 101, false)?,
        VoiceRoute::Challenge { .. }
    ));
    Ok(())
}
#[test]
fn authenticated_rebind_response_survives_exhausted_unpinned_media_budget() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = pair(&mut state, "node", &scope(1), "relay:9000", 100)?;
    let old = "1.1.1.1:2000".parse()?;
    let moved = "9.9.9.9:3000".parse()?;
    let peer = "8.8.8.8:1000".parse()?;
    let media = encode_voice_datagram(&lease.callee_token, &[0; 104])?;
    assert_eq!(media.len(), 140);
    state.route(&media, old, 100, false)?;
    let VoiceRoute::Challenge { packet: challenge, .. } =
        state.route_with_rebinding(&media, moved, 101, false)?
    else {
        return Err("missing challenge".into());
    };
    let mut refused = 0;
    for _ in 0..49 {
        if state.route_with_rebinding(&media, moved, 101, false).is_err() {
            refused += 1;
        }
    }
    assert!(refused > 0, "approximately 7 KiB/s must exhaust the unpinned media window");

    let proof =
        ramflux_crypto::voice_rebind_response(&lease.callee_key, &lease.lease_id, 1, &challenge)?;
    let response = encode_voice_datagram(&lease.callee_token, &proof)?;
    assert_eq!(state.route_with_rebinding(&response, moved, 101, false)?, VoiceRoute::Drop);
    let peer_media = encode_voice_datagram(&lease.caller_token, b"opaque")?;
    assert_eq!(state.route(&peer_media, peer, 101, false)?, Some((moved, &b"opaque"[..])));
    Ok(())
}
#[test]
fn nat_rebinding_requires_an_unexpired_cookie_echo_from_the_challenged_address() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = pair(&mut state, "node", &scope(1), "relay:9000", 100)?;
    let old = "1.1.1.1:2000".parse()?;
    let new = "9.9.9.9:3000".parse()?;
    let third = "8.8.4.4:4000".parse()?;
    let caller = "8.8.8.8:1000".parse()?;
    let bind = encode_voice_datagram(&lease.callee_token, &[0; 24])?;
    state.route(&bind, old, 100, false)?;
    let VoiceRoute::Challenge { target, packet } =
        state.route_with_rebinding(&bind, new, 101, false)?
    else {
        return Err("missing challenge".into());
    };
    assert_eq!(target, new);
    assert_eq!(&packet[..4], b"RFVC");
    assert!(packet.len() <= 55);
    let proof =
        ramflux_crypto::voice_rebind_response(&lease.callee_key, &lease.lease_id, 1, &packet)?;
    let response = encode_voice_datagram(&lease.callee_token, &proof)?;
    state.route_with_rebinding(&response, third, 102, false)?;
    let media = encode_voice_datagram(&lease.caller_token, b"opaque")?;
    assert_eq!(state.route(&media, caller, 102, false)?, Some((old, &b"opaque"[..])));
    let mut wrong = proof;
    wrong[36] ^= 1;
    state.route_with_rebinding(
        &encode_voice_datagram(&lease.callee_token, &wrong)?,
        new,
        103,
        false,
    )?;
    assert_eq!(state.route(&media, caller, 103, false)?, Some((old, &b"opaque"[..])));
    state.route_with_rebinding(&response, new, 104, false)?;
    assert_eq!(state.route(&media, caller, 104, false)?, Some((new, &b"opaque"[..])));
    // The old cookie cannot authorize another source after expiry.
    state.route_with_rebinding(&response, old, 110, false)?;
    assert_eq!(state.route(&media, caller, 110, false)?, Some((new, &b"opaque"[..])));
    Ok(())
}
#[test]
fn naming_a_victim_as_callee_does_not_spend_the_victims_voice_capacity() -> TestResult {
    let mut state = VoiceRelayState::default();
    for id in [1, 2] {
        state.allocate("node", &scope(id), "relay:9000", 100)?;
    }
    let mut victim = scope(3);
    victim.caller = scope(1).callee;
    victim.callee.principal_id = "charlie".into();
    victim.callee.root_public_key = ramflux_protocol::encode_base64url([3; 32]);
    assert!(state.allocate("node", &victim, "relay:9000", 100).is_ok());
    victim.call_id = ramflux_protocol::encode_base64url([4; 16]);
    let own = state.allocate("node", &victim, "relay:9000", 100)?;
    let incoming = state.allocate("node", &scope(1), "relay:9000", 100)?;
    assert!(
        state.accept_verified("node", &consent(&scope(1), &incoming), "relay:9000", 100).is_err()
    );
    assert!(
        state
            .route(&encode_voice_datagram(&own.token, &[])?, "1.1.1.1:2000".parse()?, 100, false)
            .is_ok()
    );
    Ok(())
}
#[test]
fn renewal_cannot_extend_a_voice_lease_beyond_four_hours() -> TestResult {
    let mut state = VoiceRelayState::default();
    let scope = scope(1);
    pair(&mut state, "node", &scope, "relay:9000", 100)?;
    for now in (120..100 + MAX_LEASE_LIFETIME).step_by(20) {
        assert!(state.renew("node", &scope, now)? <= 100 + MAX_LEASE_LIFETIME);
    }
    assert!(state.renew("node", &scope, 100 + MAX_LEASE_LIFETIME).is_err());
    Ok(())
}
#[test]
fn a_clock_rollback_starts_a_fresh_voice_bandwidth_window() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = pair(&mut state, "node", &scope(1), "relay:9000", 100)?;
    let source = "8.8.8.8:1000".parse()?;
    let packet = encode_voice_datagram(&lease.caller_token, &[0; 1400])?;
    state.route(&encode_voice_datagram(&lease.caller_token, &[])?, source, 101, false)?;
    for _ in 0..91 {
        state.route(&packet, source, 101, false)?;
    }
    assert!(state.route(&packet, source, 101, false).is_err());
    for _ in 0..91 {
        state.route(&packet, source, 100, false)?;
    }
    assert!(state.route(&packet, source, 100, false).is_err());
    Ok(())
}

#[test]
fn callee_capacity_is_charged_once_on_use_and_released_with_the_lease() -> TestResult {
    let mut state = VoiceRelayState::default();
    let incoming = scope(1);
    let lease = pair(&mut state, "node", &incoming, "relay:9000", 100)?;
    let bind = encode_voice_datagram(&lease.callee_token, &[])?;
    for _ in 0..5 {
        state.route(&bind, "1.1.1.1:2000".parse()?, 100, false)?;
    }
    let mut outgoing = scope(2);
    outgoing.caller = incoming.callee.clone();
    outgoing.callee.principal_id = "charlie".into();
    outgoing.callee.root_public_key = ramflux_protocol::encode_base64url([3; 32]);
    state.allocate("node", &outgoing, "relay:9000", 100)?;
    outgoing.call_id = ramflux_protocol::encode_base64url([3; 16]);
    assert!(state.allocate("node", &outgoing, "relay:9000", 100).is_err());
    state.release("node", &incoming)?;
    assert!(state.allocate("node", &outgoing, "relay:9000", 100).is_ok());
    Ok(())
}
#[test]
fn expired_return_routability_cookies_do_not_move_the_pinned_source() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = pair(&mut state, "node", &scope(1), "relay:9000", 100)?;
    let old = "1.1.1.1:2000".parse()?;
    let new = "9.9.9.9:3000".parse()?;
    let bind = encode_voice_datagram(&lease.callee_token, &[0; 24])?;
    state.route(&bind, old, 100, false)?;
    let VoiceRoute::Challenge { packet, .. } =
        state.route_with_rebinding(&bind, new, 101, false)?
    else {
        return Err("missing challenge".into());
    };
    let proof =
        ramflux_crypto::voice_rebind_response(&lease.callee_key, &lease.lease_id, 1, &packet)?;
    let echo = encode_voice_datagram(&lease.callee_token, &proof)?;
    assert!(matches!(
        state.route_with_rebinding(&echo, new, 106, false)?,
        VoiceRoute::Challenge { .. }
    ));
    let media = encode_voice_datagram(&lease.caller_token, b"opaque")?;
    assert_eq!(
        state.route(&media, "8.8.8.8:1000".parse()?, 106, false)?,
        Some((old, &b"opaque"[..]))
    );
    Ok(())
}

#[test]
fn a_copied_token_and_return_cookie_cannot_rebind_without_the_private_side_key() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = pair(&mut state, "node", &scope(1), "relay:9000", 100)?;
    let old = "1.1.1.1:2000".parse()?;
    let thief = "9.9.9.9:3000".parse()?;
    let bind = encode_voice_datagram(&lease.callee_token, &[0; 24])?;
    state.route(&bind, old, 100, false)?;
    let VoiceRoute::Challenge { packet, .. } =
        state.route_with_rebinding(&bind, thief, 101, false)?
    else {
        return Err("challenge missing".into());
    };
    let forged = ramflux_crypto::voice_rebind_response(&[0; 32], &lease.lease_id, 1, &packet)?;
    state.route_with_rebinding(
        &encode_voice_datagram(&lease.callee_token, &forged)?,
        thief,
        102,
        false,
    )?;
    let media = encode_voice_datagram(&lease.caller_token, b"opaque")?;
    assert_eq!(
        state.route(&media, "8.8.8.8:1000".parse()?, 102, false)?,
        Some((old, &b"opaque"[..]))
    );
    Ok(())
}
#[test]
fn pending_lease_cannot_mint_peer_credentials_or_renew_without_gateway_verified_consent()
-> TestResult {
    let mut state = VoiceRelayState::default();
    let scope = scope(1);
    let own = state.allocate("node", &scope, "relay:9000", 100)?;
    let wire = serde_json::to_value(&own)?;
    assert!(wire.get("callee_token").is_none());
    assert!(wire.get("callee_rebind_key").is_none());
    assert_eq!(state.usage.count(&scope.callee), 0);
    assert!(state.renew("node", &scope, 101).is_err());
    let valid = consent(&scope, &own);
    let mut changed = valid.clone();
    changed.lease_id = ramflux_protocol::encode_base64url([9; 16]);
    assert!(state.accept_verified("node", &changed, "relay:9000", 101).is_err());
    let peer = state.accept_verified("node", &valid, "relay:9000", 101)?;
    assert_ne!(peer.token, own.token);
    assert_ne!(peer.rebind_key, own.rebind_key);
    assert_eq!(state.usage.count(&scope.callee), 1);
    state.accept_verified("node", &valid, "relay:9000", 102)?;
    assert_eq!(state.usage.count(&scope.callee), 1);
    assert!(state.renew_consented("node", &valid, 120).is_ok());
    Ok(())
}
