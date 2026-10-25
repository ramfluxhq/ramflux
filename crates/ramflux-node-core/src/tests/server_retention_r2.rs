// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retention regressions for server time, mailbox progress, WAL recovery and push routes.
//!
//! These tests use only long-standing public APIs, so they also run against older revisions.
use super::*;

fn seq_ack(envelope_id: &str, inbox_seq: u64) -> Ack {
    let mut request = ack(envelope_id);
    request.ext.ext.insert("inbox_seq".into(), serde_json::json!(inbox_seq));
    request
}

fn wall_clock() -> i64 {
    i64::try_from(now_unix_seconds()).unwrap_or(i64::MAX)
}

#[test]
fn own_device_fanout_rejects_future_created_at_by_server_time()
-> Result<(), Box<dyn std::error::Error>> {
    let router = RouterCore::new();
    for (device, nonce) in [("phone", 811), ("laptop", 812)] {
        router.mvp1_register_identity(&registration_request(
            &router,
            "principal_future_fanout",
            device,
            nonce,
            None,
            &format!("ip_future_fanout_{device}"),
        )?)?;
    }
    let mut future = envelope("future", "unused", DeliveryClass::SelfDeviceControl);
    future.created_at = wall_clock() + 10 * 365 * 86_400;
    future.ttl = 604_800;
    let future = signed_registered_envelope(future, "principal_future_fanout", "phone", 811)?;
    let outcome = router.mvp10_own_device_fanout(ItestMvp10OwnDeviceFanoutRequest {
        principal_id: "principal_future_fanout".into(),
        source_device_id: "phone".into(),
        envelope: future,
    });
    assert!(outcome.is_err(), "a future-dated fan-out must not be stored: {outcome:?}");
    Ok(())
}

#[test]
fn nacked_mailbox_head_does_not_stall_later_acks() -> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = OpaqueDeviceInbox::new();
    let stuck = inbox.append(envelope("stuck", "target", DeliveryClass::OpaqueEvent));
    for _ in 0..3 {
        inbox.apply_nack(&nack("stuck", NackReason::UnsupportedSchema))?;
    }
    let mut last = 0;
    for index in 0..=crate::inbox::ROUTER_ACK_WINDOW {
        let id = format!("later-{index}");
        let entry = inbox.append(envelope(&id, "target", DeliveryClass::OpaqueEvent));
        inbox.apply_ack_for_target("target", &seq_ack(&id, entry.inbox_seq))?;
        last = entry.inbox_seq;
    }
    assert!(
        inbox.pull_after("target", 0, 10).iter().all(|entry| entry.inbox_seq != stuck.inbox_seq)
    );
    assert_eq!(inbox.cursor_state("target").ok_or("cursor")?.settled_inbox_seq, last);
    Ok(())
}

#[test]
fn idle_router_wal_segment_survives_retention_then_recovers_new_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_store_path("server_retention_idle_wal")?.with_extension("wal");
    let store = RouterWalStore::open(&root)?;
    let old = std::time::SystemTime::now() - Duration::from_hours(8 * 24);
    let mut segments = Vec::new();
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "wal") {
                segments.push(path);
            }
        }
    }
    assert!(!segments.is_empty(), "the writer opens a segment per shard");
    for segment in &segments {
        std::fs::OpenOptions::new().write(true).open(segment)?.set_modified(old)?;
    }
    store.prune_expired(wall_clock())?;
    let mut message = envelope("after-idle", "idle-mailbox", DeliveryClass::OpaqueEvent);
    message.created_at = wall_clock();
    let entry =
        InboxEntry { inbox_seq: 1, target_delivery_id: "idle-mailbox".into(), envelope: message };
    store.record_submission("after-idle", wall_clock() + 3_600, Some(&entry))?;
    drop(store);
    let reopened = RouterWalStore::open(&root)?;
    assert!(
        reopened.submissions(wall_clock()).iter().any(|record| record.replay_key == "after-idle"),
        "a write after an idle week must survive restart"
    );
    Ok(())
}

#[test]
fn router_restart_never_reuses_an_expired_logged_sequence() -> Result<(), Box<dyn std::error::Error>>
{
    let path = temp_store_path("server_retention_seq_reuse")?;
    let wal = path.with_extension("wal");
    let store = RouterRedbStore::open_with_wal(&path, &wal)?;
    let mut message = envelope("expired-before-checkpoint", "mailbox", DeliveryClass::OpaqueEvent);
    message.created_at = wall_clock() - 1_000;
    message.ttl = 10;
    let entry =
        InboxEntry { inbox_seq: 7, target_delivery_id: "mailbox".into(), envelope: message };
    store.record_submission_increment("expired-key", wall_clock() + 60, Some(&entry))?;
    drop(store);
    let store = RouterRedbStore::open_with_wal(&path, &wal)?;
    let issued = store
        .load_router()?
        .and_then(|router| router.cursor_state("mailbox").map(|cursor| cursor.issued_inbox_seq));
    assert_eq!(issued, Some(7), "the next delivery must be numbered after the logged one");
    Ok(())
}

fn authorized_store(
    name: &str,
    live: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<NotifyRedbStore, Box<dyn std::error::Error>> {
    let mut store =
        NotifyRedbStore::open_with_route_key(temp_store_path(name)?, NodeSecret::ephemeral()?)?;
    let live = std::sync::Arc::clone(live);
    store.set_push_route_authorizer(move |_| Ok(live.load(std::sync::atomic::Ordering::SeqCst)));
    Ok(store)
}

fn owner(target: &str) -> Result<DeviceAuthKeyResponse, Box<dyn std::error::Error>> {
    device_owner("phone", target)
}

fn device_owner(
    device: &str,
    target: &str,
) -> Result<DeviceAuthKeyResponse, Box<dyn std::error::Error>> {
    let mut open = gateway_open_frame(device, "stream");
    open.target_delivery_id = target.into();
    Ok(gateway_registered_key(&open)?)
}

fn route_for(target: &str, now: u64) -> DevicePushRoute {
    let mut route = notify_webpush_route(target, "web");
    route.registered_at = now;
    route.expires_at = now + PUSH_ROUTE_TTL_SECONDS;
    route
}

#[test]
fn backgrounded_device_route_outlives_a_day_and_revocation_deletes_it()
-> Result<(), Box<dyn std::error::Error>> {
    let live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = authorized_store("server_retention_background_route", &live)?;
    let now = now_unix_seconds();
    store.register_authenticated_push_route(&owner("delivery")?, &route_for("delivery", now))?;
    store.sweep_retention(now + 2 * 86_400)?;
    assert_eq!(
        store.load_state()?.unwrap_or_default().push_routes("delivery", now + 2 * 86_400).len(),
        1,
        "a phone left in the background for two days must still be wakeable"
    );
    live.store(false, std::sync::atomic::Ordering::SeqCst);
    store.sweep_push_route_revocations()?;
    assert_eq!(store.load_state()?.unwrap_or_default().push_routes("delivery", now).len(), 0);
    Ok(())
}

#[test]
fn provider_collapse_value_is_keyed_per_node() -> Result<(), Box<dyn std::error::Error>> {
    let now = now_unix_seconds();
    let mut hashes = Vec::new();
    for name in ["server_retention_collapse_a", "server_retention_collapse_b"] {
        let store =
            NotifyRedbStore::open_with_route_key(temp_store_path(name)?, NodeSecret::ephemeral()?)?;
        let mut route = notify_webpush_route("delivery", "web");
        route.registered_at = now;
        route.expires_at = now + 600;
        store.register_push_route(route)?;
        store.update_provider_credential(notify_webpush_credential("web"))?;
        let (_entry, pushes) = store.queue_wake_for_push(
            "delivery",
            &notification_wake("collapse", 300),
            now,
            false,
        )?;
        hashes.push(pushes.first().ok_or("push")?.collapse_key_hash.clone());
    }
    let unkeyed = ramflux_crypto::blake3_256_base64url(
        "ramflux.notification.collapse_key_hash.v1",
        b"target:delivery:content",
    );
    assert_ne!(hashes[0], hashes[1], "a delivery id alone must not predict the provider value");
    assert!(hashes.iter().all(|hash| hash != &unkeyed));
    Ok(())
}

#[test]
fn ownerless_legacy_routes_are_removed_in_production() -> Result<(), Box<dyn std::error::Error>> {
    let live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = authorized_store("server_retention_ownerless", &live)?;
    let now = now_unix_seconds();
    store.register_push_route(route_for("legacy", now))?;
    store.sweep_push_route_revocations()?;
    assert_eq!(store.load_state()?.unwrap_or_default().push_routes("legacy", now).len(), 0);
    Ok(())
}

#[test]
fn revocation_sweep_bounds_authority_lookups_per_pass() -> Result<(), Box<dyn std::error::Error>> {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut store = NotifyRedbStore::open_with_route_key(
        temp_store_path("server_retention_revocation_bound")?,
        NodeSecret::ephemeral()?,
    )?;
    let counter = std::sync::Arc::clone(&calls);
    store.set_push_route_authorizer(move |_| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(true)
    });
    let now = now_unix_seconds();
    for index in 0..1_100 {
        let target = format!("delivery-{index:04}");
        store.register_authenticated_push_route(&owner(&target)?, &route_for(&target, now))?;
    }
    calls.store(0, std::sync::atomic::Ordering::SeqCst);
    store.sweep_push_route_revocations()?;
    let first = calls.swap(0, std::sync::atomic::Ordering::SeqCst);
    assert!(first <= 1_024, "one sweep pass made {first} authority lookups");
    store.sweep_push_route_revocations()?;
    assert_eq!(first + calls.load(std::sync::atomic::Ordering::SeqCst), 1_100);
    Ok(())
}

#[test]
fn new_device_owner_discards_unverified_and_previous_owner_routes()
-> Result<(), Box<dyn std::error::Error>> {
    let live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let store = authorized_store("server_retention_owner_transition", &live)?;
    let now = now_unix_seconds();
    let mut legacy = route_for("delivery", now);
    legacy.provider = PushProviderKind::Apns;
    legacy.token = "unverified-legacy-token".into();
    store.register_push_route(legacy)?;
    let previous = owner("delivery")?;
    let mut previous_route = route_for("delivery", now);
    previous_route.provider = PushProviderKind::Fcm;
    previous_route.token = "previous-epoch-token".into();
    store.register_authenticated_push_route(&previous, &previous_route)?;
    // The mailbox now belongs to a different root-qualified device.
    let current = device_owner("tablet", "delivery")?;
    store.register_authenticated_push_route(&current, &route_for("delivery", now))?;
    let routes = store.load_state()?.unwrap_or_default().push_routes("delivery", now);
    assert_eq!(routes.len(), 1, "only the current owner's route may remain: {routes:?}");
    assert_eq!(routes[0].provider, PushProviderKind::WebPush);
    Ok(())
}
