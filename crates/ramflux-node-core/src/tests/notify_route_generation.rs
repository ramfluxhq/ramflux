// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A stale registration sequence cannot replace a newer route, and an invalid-token
//! delete removes only the snapshotted generation.
use super::*;

fn rotated_store(
    name: &str,
) -> Result<(NotifyRedbStore, DeviceAuthKeyResponse, NodeSecret, PathBuf), Box<dyn std::error::Error>>
{
    let path = temp_store_path(name)?;
    let key = NodeSecret::ephemeral()?;
    let mut store = NotifyRedbStore::open_with_route_key(&path, key.clone())?;
    store.set_push_route_authorizer(|_| Ok(true));
    let mut open = gateway_open_frame("phone", "stream");
    open.target_delivery_id = "rotated-delivery".into();
    let owner = gateway_registered_key(&open)?;
    Ok((store, owner, key, path))
}

fn route_at(token: &str, now: u64) -> DevicePushRoute {
    let mut route = notify_webpush_route("rotated-delivery", "web");
    route.token = token.to_owned();
    route.registered_at = now;
    route.expires_at = now + PUSH_ROUTE_TTL_SECONDS;
    route
}

fn current_route(
    store: &NotifyRedbStore,
    now: u64,
) -> Result<DevicePushRoute, Box<dyn std::error::Error>> {
    let routes = store.load_state()?.unwrap_or_default().push_routes("rotated-delivery", now);
    if let [route] = routes.as_slice() {
        Ok(route.clone())
    } else {
        let found = routes.len();
        Err(format!("expected one rotated route, found {found}").into())
    }
}

#[test]
fn stale_registration_cannot_undo_rotation() -> Result<(), Box<dyn std::error::Error>> {
    let (store, owner, key, path) = rotated_store("stale_registration_cannot_undo_rotation")?;
    let now = now_unix_seconds();
    let first = route_at("token-a", now);
    let second = route_at("token-b", now);
    assert!(store.register_authenticated_push_route_at(&owner, &first, Some(10))?);
    let admitted = current_route(&store, now)?;
    assert_eq!(admitted.token, "token-a");
    assert!(admitted.route_generation > 0);
    let first_generation = admitted.route_generation;
    assert!(store.register_authenticated_push_route_at(&owner, &second, Some(11))?);
    assert!(!store.register_authenticated_push_route_at(&owner, &first, Some(10))?);
    assert!(!store.register_authenticated_push_route_at(&owner, &first, None)?);
    drop(store);
    let mut store = NotifyRedbStore::open_with_route_key(&path, key)?;
    store.set_push_route_authorizer(|_| Ok(true));
    assert!(!store.register_authenticated_push_route_at(&owner, &first, Some(10))?);
    let current = current_route(&store, now)?;
    assert_eq!(current.token, "token-b");
    assert!(current.route_generation > first_generation);
    let mut stale_generation = current.clone();
    stale_generation.route_generation = first_generation;
    assert!(!store.delete_snapshotted_route(&stale_generation)?);
    let mut wrong_credential = current.clone();
    wrong_credential.credential_id = Some("other-credential".to_owned());
    assert!(!store.delete_snapshotted_route(&wrong_credential)?);
    let mut unadmitted = current.clone();
    unadmitted.route_generation = 0;
    assert!(!store.delete_snapshotted_route(&unadmitted)?);
    assert_eq!(current_route(&store, now)?.token, "token-b");
    assert!(store.delete_snapshotted_route(&current)?);
    assert_eq!(
        store.load_state()?.unwrap_or_default().push_routes("rotated-delivery", now).len(),
        0
    );
    assert_eq!(store.delete_authenticated_push_routes_at(&owner, None, Some(20))?, 0);
    assert!(!store.register_authenticated_push_route_at(&owner, &second, Some(11))?);
    assert!(store.register_authenticated_push_route_at(&owner, &second, Some(21))?);
    let restored = current_route(&store, now)?;
    assert_eq!(restored.token, "token-b");
    assert!(restored.route_generation > current.route_generation);
    Ok(())
}

fn kind_route(token: &str, provider: PushProviderKind, now: u64) -> DevicePushRoute {
    let mut route = route_at(token, now);
    route.provider = provider;
    route
}

fn routes_now(
    store: &NotifyRedbStore,
    now: u64,
) -> Result<Vec<DevicePushRoute>, Box<dyn std::error::Error>> {
    Ok(store.load_state()?.unwrap_or_default().push_routes("rotated-delivery", now))
}

fn one_provider(
    routes: &[DevicePushRoute],
    provider: &PushProviderKind,
) -> Result<DevicePushRoute, Box<dyn std::error::Error>> {
    routes
        .iter()
        .find(|route| &route.provider == provider)
        .cloned()
        .ok_or_else(|| "missing provider route".into())
}

#[test]
fn dual_apns_routes_survive_rotation_reconnect_and_delete() -> Result<(), Box<dyn std::error::Error>>
{
    let (store, owner, key, path) = rotated_store("dual_apns_routes_survive_rotation")?;
    let now = now_unix_seconds();
    let alert = kind_route("token-a", PushProviderKind::Apns, now);
    let voip = kind_route("token-v", PushProviderKind::ApnsVoip, now);
    assert!(store.register_authenticated_push_route_at(&owner, &alert, Some(1))?);
    assert!(store.register_authenticated_push_route_at(&owner, &voip, Some(2))?);
    let alert_generation =
        one_provider(&routes_now(&store, now)?, &PushProviderKind::Apns)?.route_generation;
    let rotated = kind_route("token-b", PushProviderKind::Apns, now);
    assert!(store.register_authenticated_push_route_at(&owner, &rotated, Some(3))?);
    let current_alert = one_provider(&routes_now(&store, now)?, &PushProviderKind::Apns)?;
    let current_voip = one_provider(&routes_now(&store, now)?, &PushProviderKind::ApnsVoip)?;
    assert_eq!(current_alert.token, "token-b");
    assert_eq!(current_voip.token, "token-v");
    let mut stale = current_alert.clone();
    stale.route_generation = alert_generation;
    stale.token = "token-a".to_owned();
    assert!(!store.delete_snapshotted_route(&stale)?);
    assert_eq!(routes_now(&store, now)?.len(), 2);
    assert_eq!(
        store.delete_authenticated_push_routes_at(
            &owner,
            Some(&PushProviderKind::Apns),
            Some(4)
        )?,
        1
    );
    let left = routes_now(&store, now)?;
    assert_eq!(left.len(), 1);
    assert_eq!(left.first().ok_or("voip route")?.provider, PushProviderKind::ApnsVoip);
    assert_eq!(store.delete_authenticated_push_routes_at(&owner, None, Some(5))?, 1);
    assert_eq!(routes_now(&store, now)?.len(), 0);
    drop(store);
    let mut store = NotifyRedbStore::open_with_route_key(&path, key)?;
    store.set_push_route_authorizer(|_| Ok(true));
    assert!(!store.register_authenticated_push_route_at(&owner, &rotated, Some(3))?);
    assert!(!store.register_authenticated_push_route_at(&owner, &voip, Some(2))?);
    assert_eq!(routes_now(&store, now)?.len(), 0);
    Ok(())
}
