// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded acknowledgement windows, expiry and disconnected-session retention.
use super::*;
#[test]
fn server_retention_full_ack_window_dead_letters_the_stuck_head()
-> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = OpaqueDeviceInbox::new();
    let first = inbox.append(envelope("first", "target", DeliveryClass::OpaqueEvent));
    for index in 0..crate::inbox::ROUTER_ACK_WINDOW {
        let id = format!("next-{index}");
        let entry = inbox.append(envelope(&id, "target", DeliveryClass::OpaqueEvent));
        let mut request = ack(&id);
        request.ext.ext.insert("inbox_seq".into(), serde_json::json!(entry.inbox_seq));
        inbox.apply_ack_for_target("target", &request)?;
    }
    assert_eq!(inbox.pull_after("target", 0, 10).len(), 1, "the gap is preserved");
    let extra = inbox.append(envelope("extra", "target", DeliveryClass::OpaqueEvent));
    let mut extra_ack = ack("extra");
    extra_ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(extra.inbox_seq));
    // A full window dead-letters the stuck head instead of refusing the ACK.
    let cursor = inbox.apply_ack_for_target("target", &extra_ack)?;
    assert_eq!(cursor.settled_inbox_seq, extra.inbox_seq);
    assert_eq!(cursor.acked_inbox_seqs.len(), 0);
    assert!(cursor.acked_envelope_ids.len() <= crate::inbox::ROUTER_ACK_WINDOW);
    assert_eq!(cursor.retired_inbox_seqs, vec![first.inbox_seq]);
    let dead = cursor.dead_letters.back().ok_or("dead letter")?;
    assert_eq!(dead.inbox_seq, first.inbox_seq);
    assert_eq!(dead.reason, crate::DeadLetterReason::AckWindowOverflow);
    assert_eq!(inbox.pull_after("target", 0, 10).len(), 0);
    let mut first_ack = ack("first");
    first_ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(first.inbox_seq));
    inbox.apply_ack_for_target("target", &first_ack)?;
    Ok(())
}
#[test]
fn server_retention_inbox_expiry_preserves_live_gaps_and_sequence_watermarks()
-> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = OpaqueDeviceInbox::new();
    let first = inbox.append(envelope("live", "target", DeliveryClass::OpaqueEvent));
    let mut old = envelope("expired", "target", DeliveryClass::OpaqueEvent);
    old.ttl = 1;
    let expired = inbox.append(old);
    assert_eq!(inbox.expire(1_760_000_002), 1);
    assert_eq!(inbox.pull_after("target", 0, 10), vec![first.clone()]);
    let mut request = ack("live");
    request.ext.ext.insert("inbox_seq".into(), serde_json::json!(first.inbox_seq));
    let cursor = inbox.apply_ack_for_target("target", &request)?;
    assert_eq!(cursor.settled_inbox_seq, expired.inbox_seq);
    assert_eq!(cursor.issued_inbox_seq, expired.inbox_seq);
    Ok(())
}
#[test]
fn server_retention_gateway_keeps_live_sinks_and_drops_expired_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let mut state = GatewayState::new();
    for (id, lifecycle) in [
        ("closed", GatewaySessionLifecycle::Closed),
        ("expired", GatewaySessionLifecycle::Live),
        ("active", GatewaySessionLifecycle::Live),
    ] {
        state.open_session(GatewaySession {
            session_id: id.into(),
            target_delivery_id: id.into(),
            device_id: "phone".into(),
            opened_at: 1,
            last_heartbeat_at: 1,
            lifecycle,
        });
        state.deliver(GatewayFrame::Drain { session_id: id.into() })?;
    }
    assert_eq!(state.prune_retained_sessions(1000, 300, &BTreeSet::from(["active".into()])), 2);
    assert!(state.session("active").is_some());
    assert!(state.session("expired").is_none());
    assert_eq!(state.queued_frame_count("expired"), 0);
    Ok(())
}

#[test]
fn server_retention_router_gc_is_dry_run_safe_and_survives_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("server_retention_router")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    store.save_router(&RouterCore::new())?;
    let mut inbox = OpaqueDeviceInbox::new();
    let mut message = envelope("retire", "mailbox", DeliveryClass::OpaqueEvent);
    message.ttl = 1;
    let entry = inbox.append(message);
    store.record_submission_increment("expiry-proof", 1_760_000_001, Some(&entry))?;
    assert!(store.sweep_delivery_retention(1_760_000_002, true)? > 0);
    assert_eq!(store.load_router()?.ok_or("router")?.resume("mailbox", 0, 10).len(), 1);
    assert!(store.sweep_delivery_retention(1_760_000_002, false)? > 0);
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    assert_eq!(store.load_router()?.unwrap_or_default().resume("mailbox", 0, 10).len(), 0);
    Ok(())
}

#[test]
fn server_retention_federation_gc_and_public_key_pin_survive_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("server_retention_federation")?;
    let store = FederationRedbStore::open(&path)?;
    let mut forward = super::federation::federation_forward_request("retire", "mailbox");
    forward.envelope.created_at = 100;
    forward.envelope.ttl = 2;
    let entry = store.spool_outbound_forward("peer", &forward, 100, u64::MAX)?;
    assert_eq!(entry.expires_at, 102);
    assert_eq!(store.sweep_delivery_retention(102, true)?, 1);
    assert_eq!(store.list_pending_for_peer("peer", 10)?.len(), 1);
    assert_eq!(store.sweep_delivery_retention(102, false)?, 1);
    store.verify_mounted_signing_identity([51; 32])?;
    drop(store);
    let store = FederationRedbStore::open(&path)?;
    assert_eq!(store.list_pending_for_peer("peer", 10)?.len(), 0);
    store.verify_mounted_signing_identity([51; 32])?;
    assert!(store.verify_mounted_signing_identity([52; 32]).is_err());
    Ok(())
}

#[test]
fn server_retention_push_routes_encrypt_rotate_and_revoke_on_current_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("server_retention_push")?;
    let key = NodeSecret::ephemeral()?;
    let mut open = gateway_open_frame("phone", "stream");
    open.target_delivery_id = "delivery".into();
    let authority = gateway_registered_key(&open)?;
    let live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut store = NotifyRedbStore::open_with_route_key(&path, key.clone())?;
    let expected = authority.clone();
    let current = std::sync::Arc::clone(&live);
    store.set_push_route_authorizer(move |owner| {
        Ok(owner == &expected && current.load(std::sync::atomic::Ordering::SeqCst))
    });
    let now = now_unix_seconds();
    let mut route = notify_webpush_route("delivery", "web");
    route.registered_at = now;
    route.expires_at = now + 600;
    route.token = "opaque-private-provider-token-never-in-redb".into();
    let mut legacy = route.clone();
    legacy.provider = PushProviderKind::Apns;
    legacy.token = "unverified-other-provider-token".into();
    store.register_push_route(legacy)?;
    store.register_authenticated_push_route(&authority, &route)?;
    route.token = "rotated-private-provider-token-never-in-redb".into();
    store.register_authenticated_push_route(&authority, &route)?;
    let mut other = authority.clone();
    other.target_delivery_id = "another-target".into();
    assert!(store.register_authenticated_push_route(&other, &route).is_err());
    let mut substituted = authority.clone();
    substituted.root_public_key = Some(ramflux_crypto::public_key_base64url_from_seed([31; 32]));
    assert!(store.register_authenticated_push_route(&substituted, &route).is_err());
    store.set_push_route_authorizer(|_| {
        Err(NodeCoreError::Unauthorized("authority unavailable".into()))
    });
    assert!(store.sweep_push_route_revocations().is_err());
    assert_eq!(
        store
            .load_state()?
            .ok_or("route retained on unavailable authority")?
            .push_routes("delivery", now)
            .len(),
        1
    );
    drop(store);
    let raw = std::fs::read(&path)?;
    assert!(!raw.windows(route.token.len()).any(|window| window == route.token.as_bytes()));
    assert!(NotifyRedbStore::open_with_route_key(&path, NodeSecret::ephemeral()?).is_err());
    let mut store = NotifyRedbStore::open_with_route_key(&path, key)?;
    let restored = store.load_state()?.ok_or("push state")?;
    assert_eq!(restored.push_routes("delivery", now).len(), 1);
    let current = std::sync::Arc::clone(&live);
    store.set_push_route_authorizer(move |_| Ok(current.load(std::sync::atomic::Ordering::SeqCst)));
    live.store(false, std::sync::atomic::Ordering::SeqCst);
    store.sweep_push_route_revocations()?;
    assert_eq!(store.load_state()?.unwrap_or_default().push_routes("delivery", now).len(), 0);
    assert!(store.register_authenticated_push_route(&authority, &route).is_err());
    Ok(())
}

#[test]
fn server_retention_notify_terminal_rows_and_raw_collapse_are_not_exposed()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("server_retention_notify")?;
    let store = NotifyRedbStore::open_without_wal(&path)?;
    let now = now_unix_seconds();
    let mut route = notify_webpush_route("delivery", "web");
    route.registered_at = now;
    route.expires_at = now + 600;
    store.register_push_route(route)?;
    store.update_provider_credential(notify_webpush_credential("web"))?;
    let wake = notification_wake("privacy", 300);
    let (entry, pushes) = store.queue_wake_for_push("delivery", &wake, now, false)?;
    assert_eq!(pushes.len(), 1);
    let payload = &pushes[0].payload;
    assert_ne!(payload.collapse_key, wake.collapse_key);
    assert_eq!(payload.collapse_key.as_deref(), Some(pushes[0].collapse_key_hash.as_str()));
    let mut attempt = notify_attempt(&entry.queue_id, true);
    attempt.sent_at = now;
    store.record_provider_attempt(attempt)?;
    store.sweep_retention(now + 3601)?;
    let state = store.load_state()?.unwrap_or_default();
    assert!(state.entry(&entry.queue_id).is_none());
    assert_eq!(state.provider_attempts(&entry.queue_id).len(), 0);
    Ok(())
}

#[test]
fn server_retention_legacy_federation_seed_is_removed_and_compacted()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("server_retention_seed_migration")?;
    let seed = [77; 32];
    let encoded = serde_json::to_vec(&Some(seed))?;
    {
        let db = redb::Database::create(&path)?;
        let txn = db.begin_write()?;
        txn.open_table(crate::FEDERATION_STATE_TABLE)?
            .insert(crate::FEDERATION_NODE_SIGNING_SEED_KEY, encoded.as_slice())?;
        txn.commit()?;
    }
    let mut store = FederationRedbStore::open(&path)?;
    let state = store.load_state()?.ok_or("legacy state")?;
    assert_eq!(state.node_signing_seed(), Some(seed));
    store.verify_mounted_signing_identity(seed)?;
    store.save_state(&state)?;
    store.compact_migrated_secrets()?;
    drop(store);
    let store = FederationRedbStore::open(&path)?;
    assert_eq!(store.load_state()?.ok_or("migrated state")?.node_signing_seed(), None);
    store.verify_mounted_signing_identity(seed)?;
    drop(store);
    let raw = std::fs::read(path)?;
    assert!(!raw.windows(encoded.len()).any(|window| window == encoded));
    Ok(())
}

#[test]
fn server_retention_signed_push_control_rejects_forgery_expiry_and_selector_injection()
-> Result<(), Box<dyn std::error::Error>> {
    let key = NodeServiceSigningKey::from_seed([23; 32]);
    let body = PushRouteControlBody {
        authority: gateway_registered_key(&gateway_open_frame("phone", "stream"))?,
        registration: PushRouteRegistration {
            provider: PushProviderKind::Fcm,
            token: "opaque-token".into(),
            endpoint: None,
            webpush_p256dh: None,
            webpush_auth: None,
        },
        issued_at: 100,
    };
    let signature = key.sign_push_route_control(&ramflux_protocol::canonical_json_bytes(&body)?);
    let mut control = PushRouteControl { body, signature };
    control.verify(&key, 100)?;
    // Cross-host skew of a few seconds is tolerated; larger future dates are not.
    control.verify(&key, 96)?;
    assert!(control.verify(&key, 94).is_err());
    assert!(control.verify(&key, 131).is_err());
    assert!(control.verify(&NodeServiceSigningKey::from_seed([24; 32]), 100).is_err());
    control.body.authority.target_delivery_id = "foreign-mailbox".into();
    assert!(control.verify(&key, 100).is_err());
    let malicious =
        serde_json::json!({ "provider": "fcm", "token": "token", "device_delivery_id": "victim" });
    assert!(serde_json::from_value::<PushRouteRegistration>(malicious).is_err());
    Ok(())
}

#[test]
fn server_retention_router_wal_does_not_resurrect_expired_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("server_retention_router_wal")?;
    let wal = path.with_extension("wal");
    let now = i64::try_from(now_unix_seconds())?;
    let store = RouterRedbStore::open_with_wal(&path, &wal)?;
    let mut inbox = OpaqueDeviceInbox::new();
    let mut message = envelope("retire-wal", "mailbox", DeliveryClass::OpaqueEvent);
    message.created_at = now;
    message.ttl = 600;
    let entry = inbox.append(message);
    store.record_submission_increment("wal-expiry", now + 600, Some(&entry))?;
    assert!(store.sweep_delivery_retention(now + 601, true)? > 0);
    let router = store.load_router()?.ok_or("WAL router")?;
    assert_eq!(router.sweep_delivery_retention(now + 601), 1);
    store.retain_cursor_checkpoints(&router.take_retention_checkpoints())?;
    store.sweep_delivery_retention(now + 601, false)?;
    drop(store);
    let store = RouterRedbStore::open_with_wal(&path, &wal)?;
    let restored = store.load_router()?.ok_or("cursor checkpoint")?;
    assert_eq!(restored.resume("mailbox", 0, 10).len(), 0);
    assert_eq!(
        restored.cursor_state("mailbox").ok_or("cursor")?.settled_inbox_seq,
        entry.inbox_seq
    );
    Ok(())
}

#[test]
fn server_retention_notify_wal_prunes_expired_work_and_bounded_diagnostics()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("server_retention_notify_wal")?;
    let wal = path.with_extension("wal");
    let store = NotifyRedbStore::open_with_wal(&path, &wal)?;
    let now = now_unix_seconds();
    let entry = store.queue_wake_for_async_accept(
        "delivery",
        &notification_wake("expire-wal", 1),
        now,
        false,
    )?;
    for index in 0..30 {
        let mut attempt = notify_attempt(&entry.queue_id, false);
        attempt.sent_at = now + index;
        store.record_provider_attempt(attempt)?;
    }
    store.sweep_retention(now + 60)?;
    let state = store.load_state()?.unwrap_or_default();
    assert!(state.entry(&entry.queue_id).is_none());
    assert_eq!(state.provider_attempts(&entry.queue_id).len(), 16);
    store.sweep_retention(now + 4000)?;
    drop(store);
    let store = NotifyRedbStore::open_with_wal(&path, &wal)?;
    let state = store.load_state()?.unwrap_or_default();
    assert!(state.entry(&entry.queue_id).is_none());
    assert_eq!(state.provider_attempts(&entry.queue_id).len(), 0);
    Ok(())
}

#[test]
fn server_retention_legacy_notify_routes_are_encrypted_and_compacted()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("server_retention_legacy_push")?;
    let mut state = NotifyQueueState::new();
    let mut route = notify_webpush_route("legacy-delivery", "web");
    route.token = "legacy-provider-token-that-must-leave-plaintext-pages".into();
    state.register_push_route(route.clone());
    let store = NotifyRedbStore::open_without_wal(&path)?;
    store.save_legacy_state_only(&state)?;
    drop(store);
    assert!(
        std::fs::read(&path)?
            .windows(route.token.len())
            .any(|bytes| bytes == route.token.as_bytes())
    );
    let store = NotifyRedbStore::open_with_route_key(&path, NodeSecret::ephemeral()?)?;
    assert_eq!(
        store
            .load_state()?
            .ok_or("migrated routes")?
            .push_routes("legacy-delivery", route.registered_at),
        vec![route.clone()]
    );
    drop(store);
    assert!(
        !std::fs::read(&path)?
            .windows(route.token.len())
            .any(|bytes| bytes == route.token.as_bytes())
    );
    Ok(())
}

#[test]
fn server_retention_legacy_ack_receipts_are_bounded_without_forgetting_gaps()
-> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = OpaqueDeviceInbox::new();
    let entry = inbox.append(envelope("pending-gap", "target", DeliveryClass::OpaqueEvent));
    let mut cursor = inbox.cursor_state("target").ok_or("cursor")?.clone();
    cursor.issued_inbox_seq = 3000;
    cursor.inbox_seq = 3000;
    cursor.acked_envelope_ids = (2..=3000).map(|index| format!("old-{index}")).collect();
    cursor.acked_inbox_seqs = (2..=3000).collect();
    inbox.restore_cursor_state(cursor);
    let cursor = inbox.cursor_state("target").ok_or("cursor")?;
    assert_eq!(cursor.acked_envelope_ids.len(), crate::inbox::ROUTER_ACK_WINDOW);
    assert_eq!(inbox.pull_after("target", 0, 10), vec![entry.clone()]);
    let mut request = ack("pending-gap");
    request.ext.ext.insert("inbox_seq".into(), serde_json::json!(entry.inbox_seq));
    let cursor = inbox.apply_ack_for_target("target", &request)?;
    assert_eq!(cursor.settled_inbox_seq, 3000);
    assert_eq!(cursor.acked_inbox_seqs.len(), 0);
    Ok(())
}
