// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Review r2 regressions: revoked push owners and pre-deadline mailbox rows.
//!
//! These use only APIs that exist at the previous revision, so they also run against it.
use super::*;

fn wall_clock() -> i64 {
    i64::try_from(now_unix_seconds()).unwrap_or(i64::MAX)
}

/// Production comparator fed by the router's own device record, as notify's lookup does.
fn router_backed_authorizer(
    router: std::sync::Arc<RouterCore>,
) -> impl Fn(&DeviceAuthKeyResponse) -> Result<bool, NodeCoreError> + Send + Sync + 'static {
    move |owner| {
        let identity = owner.authenticated_device_identity()?;
        let qualified =
            ramflux_protocol::qualified_device_id(identity.root_commitment(), identity.device_id())
                .map_err(|error| NodeCoreError::ItestHttp(error.to_string()))?;
        let current = router.mvp1_device_auth_key_checked(&qualified)?;
        Ok(push_route_owner_is_current(owner, current.as_ref()))
    }
}

/// Uses the router's real revoked record shape (`revoked: true`, unchanged keys and target).
#[test]
fn revoked_device_is_not_a_current_push_owner_and_its_route_is_deleted()
-> Result<(), Box<dyn std::error::Error>> {
    let router = std::sync::Arc::new(RouterCore::new());
    let router_store = RouterRedbStore::open_without_wal(temp_store_path("r3_revoked_router")?)?;
    let principal = "principal_revoked_push";
    let request =
        registration_request(&router, principal, "lost-phone", 921, None, "ip_revoked_push")?;
    router.mvp1_register_identity(&request)?;
    let root = ramflux_crypto::create_identity_root(
        principal,
        ramflux_crypto::blake3_256("ramflux.test.registration_root.v1", principal.as_bytes()),
    );
    let commitment = ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
    let qualified = ramflux_protocol::qualified_device_id(&commitment, "lost-phone")?;
    let owner = router.mvp1_device_auth_key_checked(&qualified)?.ok_or("registered device")?;
    assert!(!owner.revoked);

    let mut store = NotifyRedbStore::open_with_route_key(
        temp_store_path("r3_revoked_notify")?,
        NodeSecret::ephemeral()?,
    )?;
    store.set_push_route_authorizer(router_backed_authorizer(std::sync::Arc::clone(&router)));
    let now = now_unix_seconds();
    let mut route = notify_webpush_route(&owner.target_delivery_id, "web");
    route.registered_at = now;
    route.expires_at = now + PUSH_ROUTE_TTL_SECONDS;
    store.register_authenticated_push_route(&owner, &route)?;
    store.sweep_push_route_revocations()?;
    assert_eq!(
        store.load_state()?.unwrap_or_default().push_routes(&owner.target_delivery_id, now).len(),
        1
    );

    // Revoke through a newer root-signed device set, as the owner's other device would.
    let mut next = router.signed_device_set(&commitment).ok_or("signed set")?;
    next.device_set_epoch += 1;
    let entry =
        next.devices.iter_mut().find(|device| device.device_id == "lost-phone").ok_or("entry")?;
    entry.status = ramflux_protocol::DeviceSetStatus::Revoked;
    entry.revoked_at = Some(request.now + 1);
    let record = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: next.principal_kind,
            device_set_epoch: next.device_set_epoch,
            devices: next.devices,
        },
    )?;
    router.publish_signed_device_set(
        &crate::DeviceSetPublishRequest {
            root_public_key: request.root_public_key.clone(),
            record,
        },
        &router_store,
    )?;

    // The router keeps the record, marked revoked, with unchanged keys and target.
    let current = router.mvp1_device_auth_key_checked(&qualified)?.ok_or("revoked record")?;
    assert!(current.revoked);
    assert_eq!(current.branch_public_key, owner.branch_public_key);
    assert!(
        !push_route_owner_is_current(&owner, Some(&current)),
        "revoked owner treated as current"
    );
    store.sweep_push_route_revocations()?;
    assert_eq!(
        store.load_state()?.unwrap_or_default().push_routes(&owner.target_delivery_id, now).len(),
        0,
        "a revoked device's route must be deleted"
    );
    Ok(())
}

#[test]
fn far_future_rows_from_older_builds_expire_seven_days_after_upgrade()
-> Result<(), Box<dyn std::error::Error>> {
    const FORMAT: redb::TableDefinition<&str, u8> =
        redb::TableDefinition::new("router_expiry_index_format_v1");
    let path = temp_store_path("r3_legacy_rows")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    store.save_router(&RouterCore::new())?;
    drop(store);
    // A row written by an older build: no stored deadline, created ten years ahead.
    let mut envelope = envelope("legacy-future", "legacy-mailbox", DeliveryClass::OpaqueEvent);
    envelope.created_at = wall_clock() + 10 * 365 * 86_400;
    envelope.ttl = 604_800;
    let entry = InboxEntry { inbox_seq: 1, target_delivery_id: "legacy-mailbox".into(), envelope };
    {
        let db = redb::Database::create(&path)?;
        let txn = db.begin_write()?;
        txn.open_table(crate::ROUTER_INBOX_ENTRY_TABLE)?.insert(
            format!(
                "delivery/v1/{}/{:020}",
                ramflux_protocol::encode_base64url("legacy-mailbox"),
                1
            )
            .as_str(),
            serde_json::to_vec(&entry)?.as_slice(),
        )?;
        txn.open_table(FORMAT)?.remove("version")?;
        txn.commit()?;
    }
    let store = RouterRedbStore::open_without_wal(&path)?;
    let later = wall_clock() + 604_800 + 60;
    store.sweep_delivery_retention(later, false)?;
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let restored = store.load_router()?.unwrap_or_default();
    assert_eq!(restored.resume("legacy-mailbox", 0, 10).len(), 0, "legacy row never expired");
    Ok(())
}
