// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Review r5 regressions: fences expire by notify's clock; only an owner mismatch is typed.
use super::*;

fn fence_store(
    name: &str,
) -> Result<(NotifyRedbStore, DeviceAuthKeyResponse, DevicePushRoute), Box<dyn std::error::Error>> {
    let mut store =
        NotifyRedbStore::open_with_route_key(temp_store_path(name)?, NodeSecret::ephemeral()?)?;
    store.set_push_route_authorizer(|_| Ok(true));
    let mut open = gateway_open_frame("phone", "stream");
    open.target_delivery_id = "skewed-delivery".into();
    let owner = gateway_registered_key(&open)?;
    let now = now_unix_seconds();
    let mut route = notify_webpush_route("skewed-delivery", "web");
    route.registered_at = now;
    route.expires_at = now + PUSH_ROUTE_TTL_SECONDS;
    Ok((store, owner, route))
}

#[test]
fn a_fence_ahead_of_the_client_clock_expires_by_notify_time()
-> Result<(), Box<dyn std::error::Error>> {
    let (store, owner, route) = fence_store("r6_fence_expiry")?;
    let now = now_unix_seconds();
    // A clear sent while the device clock was a year ahead.
    let ahead = (now + 365 * 86_400) * 1_000;
    store.set_route_fence_for_test("skewed-delivery", ahead, now)?;
    assert!(!store.register_authenticated_push_route_at(&owner, &route, Some(now * 1_000))?);
    // Ten minutes later by notify's clock the fence no longer applies, whatever its sequence.
    store.set_route_fence_for_test("skewed-delivery", ahead, now - PUSH_ROUTE_FENCE_SECONDS)?;
    assert!(store.register_authenticated_push_route_at(&owner, &route, Some(now * 1_000))?);
    assert!(store.register_authenticated_push_route_at(&owner, &route, None)?);
    Ok(())
}

#[test]
fn the_retention_sweep_deletes_expired_fences() -> Result<(), Box<dyn std::error::Error>> {
    let (store, owner, _route) = fence_store("r6_fence_sweep")?;
    let now = now_unix_seconds();
    store.set_route_fence_for_test("old-delivery", 7, now - PUSH_ROUTE_FENCE_SECONDS)?;
    store.delete_authenticated_push_routes_at(&owner, None, Some(9))?;
    assert_eq!(store.sweep_retention(now)?, 1, "only the expired fence is removed");
    assert_eq!(store.sweep_retention(now + PUSH_ROUTE_FENCE_SECONDS)?, 1);
    assert_eq!(store.sweep_retention(now + PUSH_ROUTE_FENCE_SECONDS)?, 0);
    Ok(())
}

#[test]
fn only_a_verified_owner_mismatch_is_reported_as_such() -> Result<(), Box<dyn std::error::Error>> {
    let (store, owner, route) = fence_store("r6_owner_mismatch")?;
    store.register_authenticated_push_route(&owner, &route)?;
    let mut stranger_open = gateway_open_frame("tablet", "stream");
    stranger_open.target_delivery_id = "skewed-delivery".into();
    let stranger = gateway_registered_key(&stranger_open)?;
    assert!(matches!(
        store.delete_authenticated_push_routes_at(&stranger, None, Some(1)),
        Err(NodeCoreError::PushRouteOwnerMismatch)
    ));
    // An expired (clock-skewed) control is an ordinary authorization failure, not a mismatch.
    let key = NodeServiceSigningKey::from_seed([29; 32]);
    let body =
        PushRouteDeleteBody { authority: owner, provider: None, issued_at: 100, client_seq: None };
    let signature = key.sign_push_route_delete(&ramflux_protocol::canonical_json_bytes(&body)?);
    assert!(matches!(
        PushRouteDeleteControl { body, signature }.verify(&key, 1_000),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}
