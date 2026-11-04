// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

#[test]
fn session_registry_routes_live_session_to_gateway() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = SessionRegistry::new();
    registry.upsert_session(session("target_a", SessionLifecycle::Authed, 1, 1))?;
    registry.mark_live("target_a")?;
    let decision = registry.route_target("target_a", DeliveryClass::OpaqueEvent);
    assert_eq!(
        decision,
        DeliveryDecision::Online {
            gateway_id: "gateway_a".to_owned(),
            session_id: "session_a".to_owned(),
            target_delivery_id: "target_a".to_owned(),
        }
    );
    Ok(())
}

#[test]
fn draining_or_missing_session_uses_offline_wake() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = SessionRegistry::new();
    registry.upsert_session(session("target_a", SessionLifecycle::Live, 1, 1))?;
    registry.mark_draining("target_a")?;
    let decision = registry.route_target("target_a", DeliveryClass::NotificationWake);
    assert_eq!(
        decision,
        DeliveryDecision::OfflineWake(WakeHint {
            target_delivery_id: "target_a".to_owned(),
            push_alias_hash: Some("push_alias_hash_a".to_owned()),
            delivery_class: DeliveryClass::NotificationWake,
        })
    );

    let missing = registry.route_target("target_missing", DeliveryClass::SelfDeviceControl);
    assert_eq!(
        missing,
        DeliveryDecision::OfflineWake(WakeHint {
            target_delivery_id: "target_missing".to_owned(),
            push_alias_hash: None,
            delivery_class: DeliveryClass::SelfDeviceControl,
        })
    );
    Ok(())
}

#[test]
fn stale_session_update_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = SessionRegistry::new();
    registry.upsert_session(session("target_a", SessionLifecycle::Live, 2, 10))?;
    assert!(registry.upsert_session(session("target_a", SessionLifecycle::Live, 2, 9)).is_err());
    assert!(registry.upsert_session(session("target_a", SessionLifecycle::Live, 1, 99)).is_err());
    registry.upsert_session(session("target_a", SessionLifecycle::Live, 2, 11))?;
    assert_eq!(registry.resume_cursor("target_a"), Some("cursor_a"));
    Ok(())
}

#[test]
fn envelope_routing_uses_target_delivery_id() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = SessionRegistry::new();
    registry.upsert_session(session("target_env", SessionLifecycle::Live, 1, 1))?;
    let envelope = envelope("env_1", "target_env", DeliveryClass::OpaqueEvent);
    assert!(matches!(registry.route_envelope(&envelope), DeliveryDecision::Online { .. }));
    Ok(())
}

#[test]
fn router_sessions_preserve_gateway_instance_ids() -> Result<(), Box<dyn std::error::Error>> {
    let source_identity = replay_source("alice_device")?;
    let router = RouterCore::new();
    let mut east = session("target_gateway_east", SessionLifecycle::Live, 1, 1);
    east.gateway_id = "gateway-east-1".to_owned();
    east.session_id = "session-east".to_owned();
    router.upsert_session(east)?;

    let mut west = session("target_gateway_west", SessionLifecycle::Live, 1, 1);
    west.gateway_id = "gateway-west-1".to_owned();
    west.session_id = "session-west".to_owned();
    router.upsert_session(west)?;

    assert_eq!(
        router.session("target_gateway_east").ok_or("missing east session")?.gateway_id,
        "gateway-east-1"
    );
    assert_eq!(
        router.session("target_gateway_west").ok_or("missing west session")?.gateway_id,
        "gateway-west-1"
    );

    let submit_outcome = router.submit_envelope_at_created(
        &source_identity,
        envelope("env_gateway_west", "target_gateway_west", DeliveryClass::OpaqueEvent),
    );
    let RouterSubmitOutcome::Online(delivery) = submit_outcome else {
        return Err("expected online delivery".into());
    };
    assert_eq!(delivery.gateway_id, "gateway-west-1");
    assert_eq!(delivery.session_id, "session-west");
    Ok(())
}

#[test]
fn offline_inbox_pull_after_cursor_returns_pending_entries() {
    let mut inbox = OpaqueDeviceInbox::new();
    let first = inbox.append(envelope("env_1", "target_a", DeliveryClass::OpaqueEvent));
    let second = inbox.append(envelope("env_2", "target_a", DeliveryClass::OpaqueEvent));
    assert_eq!(first.inbox_seq, 1);
    assert_eq!(second.inbox_seq, 2);

    let pulled = inbox.pull_after("target_a", 1, 10);
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].envelope.envelope_id, "env_2");
}

#[test]
fn ack_advances_cursor_and_removes_pending_entry() -> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = OpaqueDeviceInbox::new();
    inbox.append(envelope("env_1", "target_a", DeliveryClass::OpaqueEvent));
    inbox.append(envelope("env_2", "target_a", DeliveryClass::OpaqueEvent));

    let state = inbox.apply_ack(&ack("env_1"))?;
    assert_eq!(state.inbox_seq, 1);
    assert_eq!(state.last_envelope_id, Some("env_1".to_owned()));
    assert!(state.acked_envelope_ids.contains("env_1"));
    let remaining = inbox.pull_after("target_a", 0, 10);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].envelope.envelope_id, "env_2");
    Ok(())
}

#[test]
fn nack_records_reason_without_advancing_cursor() -> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = OpaqueDeviceInbox::new();
    inbox.append(envelope("env_1", "target_a", DeliveryClass::OpaqueEvent));
    let state = inbox.apply_nack(&nack("env_1", NackReason::RateLimited))?;
    assert_eq!(state.inbox_seq, 0);
    assert_eq!(state.last_envelope_id, None);
    assert_eq!(state.nacked_envelope_ids.get("env_1"), Some(&NackReason::RateLimited));
    assert_eq!(inbox.pull_after("target_a", 0, 10).len(), 1);
    Ok(())
}

#[test]
fn nack_after_ack_returns_existing_cursor_idempotently() -> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = OpaqueDeviceInbox::new();
    inbox.append(envelope("env_ack_then_nack", "target_a", DeliveryClass::OpaqueEvent));

    let acked = inbox.apply_ack(&ack("env_ack_then_nack"))?;
    assert!(acked.acked_envelope_ids.contains("env_ack_then_nack"));
    assert_eq!(inbox.pull_after("target_a", 0, 10).len(), 0);

    let nacked = inbox.apply_nack(&nack("env_ack_then_nack", NackReason::RateLimited))?;
    assert_eq!(nacked.target_delivery_id, "target_a");
    assert!(nacked.acked_envelope_ids.contains("env_ack_then_nack"));
    Ok(())
}

#[test]
fn bound_ack_and_nack_reject_other_target_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let source_identity = replay_source("alice_device")?;
    let router = RouterCore::new();
    let _accepted_a = router.submit_envelope_at_created(
        &source_identity,
        envelope("env_bound_target_a", "target_a", DeliveryClass::OpaqueEvent),
    );
    let _accepted_b = router.submit_envelope_at_created(
        &source_identity,
        envelope("env_bound_target_b", "target_b", DeliveryClass::OpaqueEvent),
    );

    let ack_rejected = router.apply_ack_for_target("target_a", &ack("env_bound_target_b"));
    assert!(matches!(ack_rejected, Err(NodeCoreError::EnvelopeTargetMismatch { .. })));
    assert_eq!(router.resume("target_b", 0, 10).len(), 1);

    let nack_rejected = router
        .apply_nack_for_target("target_a", &nack("env_bound_target_b", NackReason::RateLimited));
    assert!(matches!(nack_rejected, Err(NodeCoreError::EnvelopeTargetMismatch { .. })));
    assert_eq!(router.resume("target_b", 0, 10).len(), 1);
    Ok(())
}

#[test]
fn router_target_index_supports_concurrent_submit_and_ack() -> Result<(), Box<dyn std::error::Error>>
{
    let source_identity = replay_source("alice_device")?;
    let router = std::sync::Arc::new(RouterCore::new());
    let worker_count = 16usize;
    let envelopes_per_worker = 32usize;
    let mut workers = Vec::with_capacity(worker_count);
    for worker_index in 0..worker_count {
        let router = std::sync::Arc::clone(&router);
        let source_identity = source_identity.clone();
        workers.push(std::thread::spawn(move || {
            for envelope_index in 0..envelopes_per_worker {
                let envelope_id = format!("env_index_{worker_index}_{envelope_index}");
                let target_delivery_id = format!("target_index_{worker_index}_{envelope_index}");
                let outcome = router.submit_envelope_at_created(
                    &source_identity,
                    envelope(&envelope_id, &target_delivery_id, DeliveryClass::OpaqueEvent),
                );
                if !matches!(outcome, RouterSubmitOutcome::OfflineQueued(_)) {
                    return Err(format!("unexpected submit outcome: {outcome:?}"));
                }
            }
            Ok::<(), String>(())
        }));
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| std::io::Error::other("target index worker panicked"))?
            .map_err(std::io::Error::other)?;
    }
    for worker_index in 0..worker_count {
        for envelope_index in 0..envelopes_per_worker {
            let envelope_id = format!("env_index_{worker_index}_{envelope_index}");
            let target_delivery_id = format!("target_index_{worker_index}_{envelope_index}");
            assert_eq!(router.target_for_envelope_id(&envelope_id), Some(target_delivery_id));
            router.apply_ack(&ack(&envelope_id))?;
        }
    }
    Ok(())
}

#[test]
fn mvp10_own_device_fanout_uses_collision_safe_envelope_ids()
-> Result<(), Box<dyn std::error::Error>> {
    assert_ne!(mvp10_fanout_envelope_id("a:b", "c"), mvp10_fanout_envelope_id("a", "b:c"));

    let router = RouterCore::new();
    router.mvp1_register_identity(&registration_request(
        &router,
        "principal_fanout_collision_a",
        "source_a",
        701,
        None,
        "ip_fanout_collision_a_source",
    )?)?;
    router.mvp1_register_identity(&registration_request(
        &router,
        "principal_fanout_collision_a",
        "c",
        702,
        None,
        "ip_fanout_collision_a_peer",
    )?)?;
    router.mvp1_register_identity(&registration_request(
        &router,
        "principal_fanout_collision_b",
        "source_b",
        703,
        None,
        "ip_fanout_collision_b_source",
    )?)?;
    router.mvp1_register_identity(&registration_request(
        &router,
        "principal_fanout_collision_b",
        "b:c",
        704,
        None,
        "ip_fanout_collision_b_peer",
    )?)?;

    let first = router.mvp10_own_device_fanout_at_created(ItestMvp10OwnDeviceFanoutRequest {
        principal_id: "principal_fanout_collision_a".to_owned(),
        source_device_id: "source_a".to_owned(),
        envelope: signed_registered_envelope(
            envelope("a:b", "unused_fanout_target_a", DeliveryClass::SelfDeviceControl),
            "principal_fanout_collision_a",
            "source_a",
            701,
        )?,
    })?;
    let second = router.mvp10_own_device_fanout_at_created(ItestMvp10OwnDeviceFanoutRequest {
        principal_id: "principal_fanout_collision_b".to_owned(),
        source_device_id: "source_b".to_owned(),
        envelope: signed_registered_envelope(
            envelope("a", "unused_fanout_target_b", DeliveryClass::SelfDeviceControl),
            "principal_fanout_collision_b",
            "source_b",
            703,
        )?,
    })?;

    assert_eq!(first.delivered.len(), 1);
    assert_eq!(second.delivered.len(), 1);
    let first_entries = router.resume("target_principal_fanout_collision_a", 0, 10);
    let second_entries = router.resume("target_principal_fanout_collision_b", 0, 10);
    assert_eq!(first_entries.len(), 1);
    assert_eq!(second_entries.len(), 1);
    assert_eq!(first_entries[0].envelope.envelope_id, mvp10_fanout_envelope_id("a:b", "c"));
    assert_eq!(second_entries[0].envelope.envelope_id, mvp10_fanout_envelope_id("a", "b:c"));
    assert_ne!(first_entries[0].envelope.envelope_id, second_entries[0].envelope.envelope_id);

    let cross_principal =
        router.mvp10_own_device_fanout_at_created(ItestMvp10OwnDeviceFanoutRequest {
            principal_id: "principal_fanout_collision_b".to_owned(),
            source_device_id: "source_a".to_owned(),
            envelope: envelope(
                "cross_principal",
                "unused_fanout_target",
                DeliveryClass::SelfDeviceControl,
            ),
        });
    assert!(
        matches!(cross_principal, Err(NodeCoreError::ItestHttp(message)) if message.contains("source device is not registered for principal"))
    );
    Ok(())
}

#[test]
fn gateway_own_device_fanout_frame_round_trips_json() -> Result<(), Box<dyn std::error::Error>> {
    let frame = GatewayClientFrame::OwnDeviceFanout {
        fanout: GatewayOwnDeviceFanoutFrame {
            signed_request: gateway_fanout_signed_request("device_frame_fanout"),
            principal_id: "principal_frame_fanout".to_owned(),
            source_device_id: "device_frame_fanout".to_owned(),
            envelope: envelope(
                "env_frame_fanout",
                "fanout-placeholder",
                DeliveryClass::SelfDeviceControl,
            ),
        },
    };
    let value = serde_json::to_value(&frame)?;
    assert_eq!(value["frame_type"], "own_device_fanout");
    let decoded: GatewayClientFrame = serde_json::from_value(value)?;
    assert_eq!(decoded, frame);

    let response = GatewayServerFrame::OwnDeviceFanout {
        response: GatewayOwnDeviceFanoutResponse {
            principal_id: "principal_frame_fanout".to_owned(),
            source_device_id: "device_frame_fanout".to_owned(),
            delivered: vec![GatewayOwnDeviceFanoutDelivery {
                device_id: "device_frame_peer".to_owned(),
                target_delivery_id: "target_frame_peer".to_owned(),
                outcome: "online".to_owned(),
                inbox_seq: Some(7),
            }],
        },
    };
    let value = serde_json::to_value(&response)?;
    assert_eq!(value["frame_type"], "own_device_fanout");
    let decoded: GatewayServerFrame = serde_json::from_value(value)?;
    assert_eq!(decoded, response);
    Ok(())
}

#[test]
fn router_core_routes_online_and_queues_offline() -> Result<(), Box<dyn std::error::Error>> {
    let source_identity = replay_source("alice_device")?;
    let router = RouterCore::new();
    router.upsert_session(session("target_live", SessionLifecycle::Live, 1, 1))?;

    let online = router.submit_envelope_at_created(
        &source_identity,
        envelope("env_online", "target_live", DeliveryClass::OpaqueEvent),
    );
    assert!(matches!(online, RouterSubmitOutcome::Online(_)));
    if let RouterSubmitOutcome::Online(delivery) = online {
        assert_eq!(delivery.gateway_id, "gateway_a");
        assert_eq!(delivery.session_id, "session_a");
        assert_eq!(delivery.inbox_seq, 1);
        assert_eq!(delivery.envelope.envelope_id, "env_online");
    }
    assert_eq!(router.resume("target_live", 0, 10).len(), 1);

    let offline = router.submit_envelope_at_created(
        &source_identity,
        envelope("env_offline", "target_offline", DeliveryClass::SelfDeviceControl),
    );
    assert!(matches!(offline, RouterSubmitOutcome::OfflineQueued(_)));
    if let RouterSubmitOutcome::OfflineQueued(queued) = offline {
        assert_eq!(queued.entry.inbox_seq, 1);
        assert_eq!(queued.wake_hint.target_delivery_id, "target_offline");
        assert_eq!(queued.wake_hint.delivery_class, DeliveryClass::SelfDeviceControl);
    }
    assert_eq!(router.resume("target_offline", 0, 10).len(), 1);

    let state = router.apply_ack(&ack("env_offline"))?;
    assert_eq!(state.inbox_seq, 1);
    assert_eq!(router.resume("target_offline", 0, 10).len(), 0);
    Ok(())
}

#[test]
fn router_replay_guard_rejects_duplicate_envelope_and_expired_ttl()
-> Result<(), Box<dyn std::error::Error>> {
    let source_identity = replay_source("alice_device")?;
    let router = RouterCore::new();
    let accepted = router.submit_envelope_at(
        &source_identity,
        envelope("env_replay", "target_replay", DeliveryClass::OpaqueEvent),
        1_760_000_001,
    );
    assert!(matches!(accepted, RouterSubmitOutcome::OfflineQueued(_)));

    let replay = router.submit_envelope_at(
        &source_identity,
        envelope("env_replay", "target_replay", DeliveryClass::OpaqueEvent),
        1_760_000_002,
    );
    assert!(matches!(replay, RouterSubmitOutcome::RejectedSecurity { .. }));

    let mut expired = envelope("env_expired", "target_replay", DeliveryClass::OpaqueEvent);
    expired.ttl = 1;
    let rejected = router.submit_envelope_at(&source_identity, expired, 1_760_000_010);
    assert!(matches!(rejected, RouterSubmitOutcome::RejectedSecurity { .. }));
    Ok(())
}

#[test]
fn replay_guard_rejects_long_ttl_envelope_replay_until_expiry_then_prunes()
-> Result<(), Box<dyn std::error::Error>> {
    let source_identity = replay_source("alice_device")?;
    let mut replay_guard = NodeReplayGuardState::new();
    let mut first = envelope("env_ttl_window", "target_replay", DeliveryClass::OpaqueEvent);
    first.ttl = 3_600;

    replay_guard.check_envelope(&source_identity, &first, first.created_at + 1)?;
    let replay = replay_guard.check_envelope(&source_identity, &first, first.created_at + 901);
    assert!(matches!(replay, Err(NodeCoreError::ReplayGuard(_))));
    assert_eq!(replay_guard.len(), 1);

    let mut later = envelope("env_after_prune", "target_replay", DeliveryClass::OpaqueEvent);
    later.created_at = first.created_at + 3_601;
    later.ttl = 3_600;
    replay_guard.check_envelope(&source_identity, &later, later.created_at)?;
    assert_eq!(replay_guard.len(), 1);
    Ok(())
}

#[test]
fn replay_guard_rejects_envelope_ttl_above_maximum() -> Result<(), Box<dyn std::error::Error>> {
    let source_identity = replay_source("alice_device")?;
    let mut replay_guard = NodeReplayGuardState::new();
    let mut envelope = envelope("env_ttl_max", "target_replay", DeliveryClass::OpaqueEvent);
    envelope.ttl = ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS_U32 + 1;

    let rejected = replay_guard.check_envelope(&source_identity, &envelope, envelope.created_at);

    assert!(matches!(rejected, Err(NodeCoreError::ReplayGuard(_))));
    assert_eq!(replay_guard.len(), 0);
    Ok(())
}

#[test]
fn registration_pow_tier_and_budgets_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
    const POW_BITS: u8 = 8;
    let router = RouterCore::new();
    router.mvp6_set_registration_policy(RegistrationPolicy {
        challenge_policy: RegistrationChallengePolicy::Pow,
        pow_difficulty_bits: POW_BITS,
        per_source_ip_registration_limit: 2,
        registration_window_seconds: 60,
    });

    assert!(
        router
            .mvp1_register_identity(&registration_request(
                &router,
                "alice_pow_missing",
                "alice_device_missing",
                1,
                None,
                "source_invalid",
            )?)
            .is_err()
    );
    assert!(
        router
            .mvp1_register_identity(&registration_request(
                &router,
                "alice_pow_bad",
                "alice_device_bad",
                2,
                Some(RegistrationPowProof { nonce: 0, difficulty_bits: 0 }),
                "source_invalid",
            )?)
            .is_err()
    );

    assert!(
        router
            .mvp1_register_identity(&registration_request(
                &router,
                "valid_but_source_exhausted",
                "valid_device",
                9,
                Some(solved_pow("valid_but_source_exhausted", POW_BITS)),
                "source_invalid"
            )?)
            .is_err()
    );
    let alice_pow = solved_pow("alice_pow_ok", POW_BITS);
    let alice = router.mvp1_register_identity(&registration_request(
        &router,
        "alice_pow_ok",
        "alice_device_ok",
        3,
        Some(alice_pow),
        "source_a",
    )?)?;
    assert_eq!(alice.registration_trust_tier, RegistrationTrustTier::Challenged);

    let bob_pow = solved_pow("bob_pow_ok", POW_BITS);
    assert!(
        router
            .mvp1_register_identity(&registration_request(
                &router,
                "bob_pow_ok",
                "bob_device_ok",
                4,
                Some(bob_pow),
                "source_a",
            )?)
            .is_ok()
    );
    let carol_pow = solved_pow("carol_pow_limited", POW_BITS);
    assert!(
        router
            .mvp1_register_identity(&registration_request(
                &router,
                "carol_pow_limited",
                "carol_device_limited",
                5,
                Some(carol_pow),
                "source_a",
            )?)
            .is_err()
    );

    for index in 0..friend_request_budget_limit(&RegistrationTrustTier::Challenged) {
        let response = router.mvp6_record_friend_request(&friend_request(
            "alice_pow_ok",
            &format!("target_{index}"),
            1_760_000_100 + i64::from(index),
        ))?;
        assert_eq!(response.registration_trust_tier, RegistrationTrustTier::Challenged);
    }
    assert!(
        router
            .mvp6_record_friend_request(&friend_request(
                "alice_pow_ok",
                "target_over_budget",
                1_760_000_110,
            ))
            .is_err()
    );
    Ok(())
}
