// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source pinning, return routability and quota ownership at the production routing boundary.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn spoofed_keepalive_and_copied_tokens_cannot_redirect_a_pinned_voice_endpoint() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = state.allocate("node", &scope(1), "relay:9000", 100)?;
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
fn nat_rebinding_requires_an_unexpired_cookie_echo_from_the_challenged_address() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = state.allocate("node", &scope(1), "relay:9000", 100)?;
    let old = "1.1.1.1:2000".parse()?;
    let new = "9.9.9.9:3000".parse()?;
    let third = "8.8.4.4:4000".parse()?;
    let caller = "8.8.8.8:1000".parse()?;
    let bind = encode_voice_datagram(&lease.callee_token, &[])?;
    state.route(&bind, old, 100, false)?;
    let VoiceRoute::Challenge { target, mut packet } =
        state.route_with_rebinding(&bind, new, 101, false)?
    else {
        return Err("missing challenge".into());
    };
    assert_eq!(target, new);
    assert_eq!(&packet[..4], b"RFVC");
    assert!(packet.len() <= bind.len());
    packet[..4].copy_from_slice(b"RFVE");
    let response = encode_voice_datagram(&lease.callee_token, &packet)?;
    state.route_with_rebinding(&response, third, 102, false)?;
    let media = encode_voice_datagram(&lease.caller_token, b"opaque")?;
    assert_eq!(state.route(&media, caller, 102, false)?, Some((old, &b"opaque"[..])));
    let mut wrong = packet;
    wrong[4] ^= 1;
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
    let packet = encode_voice_datagram(&incoming.callee_token, &[])?;
    assert!(state.route(&packet, "1.1.1.1:2000".parse()?, 100, false).is_err());
    assert!(
        state
            .route(
                &encode_voice_datagram(&own.caller_token, &[])?,
                "1.1.1.1:2000".parse()?,
                100,
                false
            )
            .is_ok()
    );
    Ok(())
}
#[test]
fn renewal_cannot_extend_a_voice_lease_beyond_four_hours() -> TestResult {
    let mut state = VoiceRelayState::default();
    let scope = scope(1);
    state.allocate("node", &scope, "relay:9000", 100)?;
    for now in (120..100 + MAX_LEASE_LIFETIME).step_by(20) {
        assert!(state.renew("node", &scope, now)? <= 100 + MAX_LEASE_LIFETIME);
    }
    assert!(state.renew("node", &scope, 100 + MAX_LEASE_LIFETIME).is_err());
    Ok(())
}
#[test]
fn a_clock_rollback_starts_a_fresh_voice_bandwidth_window() -> TestResult {
    let mut state = VoiceRelayState::default();
    let lease = state.allocate("node", &scope(1), "relay:9000", 100)?;
    let source = "8.8.8.8:1000".parse()?;
    let packet = encode_voice_datagram(&lease.caller_token, &[0; 1400])?;
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
    let lease = state.allocate("node", &incoming, "relay:9000", 100)?;
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
    let lease = state.allocate("node", &scope(1), "relay:9000", 100)?;
    let old = "1.1.1.1:2000".parse()?;
    let new = "9.9.9.9:3000".parse()?;
    let bind = encode_voice_datagram(&lease.callee_token, &[])?;
    state.route(&bind, old, 100, false)?;
    let VoiceRoute::Challenge { mut packet, .. } =
        state.route_with_rebinding(&bind, new, 101, false)?
    else {
        return Err("missing challenge".into());
    };
    packet[..4].copy_from_slice(b"RFVE");
    let echo = encode_voice_datagram(&lease.callee_token, &packet)?;
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
