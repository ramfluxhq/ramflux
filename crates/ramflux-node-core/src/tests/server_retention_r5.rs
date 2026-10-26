// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Review r4 regression: a late registration never recreates a confirmed-cleared route.
use super::*;

#[test]
fn registration_older_than_the_confirmed_deregistration_is_refused()
-> Result<(), Box<dyn std::error::Error>> {
    let mut store = NotifyRedbStore::open_with_route_key(
        temp_store_path("r5_route_fence")?,
        NodeSecret::ephemeral()?,
    )?;
    store.set_push_route_authorizer(|_| Ok(true));
    let mut open = gateway_open_frame("phone", "stream");
    open.target_delivery_id = "fenced-delivery".into();
    let owner = gateway_registered_key(&open)?;
    let now = now_unix_seconds();
    let mut route = notify_webpush_route("fenced-delivery", "web");
    route.registered_at = now;
    route.expires_at = now + PUSH_ROUTE_TTL_SECONDS;
    assert!(store.register_authenticated_push_route_at(&owner, &route, Some(5))?);
    // The clear (sequence 10) commits first; the registration sent before it (sequence 9)
    // finishes late, for example after a slow router lookup.
    assert_eq!(store.delete_authenticated_push_routes_at(&owner, None, Some(10))?, 1);
    assert!(!store.register_authenticated_push_route_at(&owner, &route, Some(9))?);
    assert!(!store.register_authenticated_push_route_at(&owner, &route, None)?);
    let routes = store.load_state()?.unwrap_or_default().push_routes("fenced-delivery", now);
    assert_eq!(routes.len(), 0, "a cleared route must stay cleared");
    // A newer registration after the clear is a new intent and is applied.
    assert!(store.register_authenticated_push_route_at(&owner, &route, Some(11))?);
    Ok(())
}
