// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypt provider tokens and `WebPush` keys with a mounted node secret, bound to delivery id.
use super::{DevicePushRoute, NOTIFY_ROUTE_TABLE, NodeCoreError};
use crate::NodeSecret;
use redb::{ReadableDatabase, ReadableTable};
fn error(value: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(value.to_string())
}
fn context(device: &str) -> Vec<u8> {
    let mut bytes = b"ramflux.notify.routes.v1\0".to_vec();
    bytes.extend_from_slice(device.as_bytes());
    bytes
}
pub(super) fn seal(
    key: &NodeSecret,
    device: &str,
    routes: &[DevicePushRoute],
) -> Result<Vec<u8>, NodeCoreError> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(routes).map_err(error)?);
    key.seal(&context(device), &bytes)
}
pub(super) fn open(
    key: &NodeSecret,
    device: &str,
    bytes: &[u8],
) -> Result<Vec<DevicePushRoute>, NodeCoreError> {
    serde_json::from_slice(&key.open(&context(device), bytes)?).map_err(error)
}
pub(super) fn configured_key() -> Result<NodeSecret, NodeCoreError> {
    if let Some(path) = crate::environment::var_os("RAMFLUX_NOTIFY_ROUTE_KEY_FILE") {
        NodeSecret::from_file(path)
    } else {
        Ok(NodeSecret::process_key().clone())
    }
}
pub(super) fn validate(db: &redb::Database, key: &NodeSecret) -> Result<(), NodeCoreError> {
    let txn = db.begin_read().map_err(error)?;
    let routes = match txn.open_table(NOTIFY_ROUTE_TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(source) => return Err(error(source)),
    };
    let owners = match txn.open_table(super::route_authority::OWNERS) {
        Ok(table) => Some(table),
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(source) => return Err(error(source)),
    };
    for row in routes.iter().map_err(error)? {
        let (device, value) = row.map_err(error)?;
        if value.value().first() == Some(&b'[') {
            return Err(NodeCoreError::UnsupportedPersistedFormat("notify plaintext routes"));
        }
        let _routes = open(key, device.value(), value.value())?;
        let binding = owners
            .as_ref()
            .map(|owners| owners.get(device.value()).map_err(error))
            .transpose()?
            .flatten()
            .ok_or(NodeCoreError::UnsupportedPersistedFormat("notify unowned route"))?;
        let authority: crate::DeviceAuthKeyResponse = serde_json::from_slice(&key.open(
            format!("ramflux.notify.route_owner.v1\0{}", device.value()).as_bytes(),
            binding.value(),
        )?)
        .map_err(error)?;
        authority.authenticated_device_identity()?;
        if authority.target_delivery_id != device.value() {
            return Err(NodeCoreError::UnsupportedPersistedFormat("notify route owner binding"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{NotifyRedbStore, PushProviderKind};
    use super::*;
    use crate::tests::persisted_image::image;

    #[test]
    fn invalid_plaintext_owner_binding_and_snapshot_refuse_real_open_without_writes()
    -> Result<(), Box<dyn std::error::Error>> {
        for expected in
            ["notify plaintext routes", "notify route owner binding", "notify bounded snapshot"]
        {
            let directory = tempfile::TempDir::new()?;
            let path = directory.path().join("notify.redb");
            let wal = directory.path().join("wal");
            drop(NotifyRedbStore::open_with_wal_root(&path, Some(&wal))?);
            let db = redb::Database::open(&path)?;
            let txn = db.begin_write()?;
            if expected == "notify bounded snapshot" {
                txn.open_table(super::super::NOTIFY_QUEUE_TABLE)?
                    .insert(super::super::NOTIFY_QUEUE_KEY, b"not-json".as_slice())?;
            } else {
                let target = "wrong-target";
                let now = crate::now_unix_seconds();
                let route = DevicePushRoute {
                    device_delivery_id: target.into(),
                    provider: PushProviderKind::Apns,
                    credential_id: None,
                    token: "token".into(),
                    endpoint: "endpoint".into(),
                    webpush_p256dh: None,
                    webpush_auth: None,
                    registered_at: now,
                    expires_at: now + 60,
                    route_generation: 0,
                };
                let rows = [route];
                let bytes = if expected == "notify plaintext routes" {
                    serde_json::to_vec(&rows)?
                } else {
                    let open = crate::test_support::federation_fixtures::gateway_open_frame(
                        "device", "route",
                    );
                    let authority =
                        crate::test_support::federation_fixtures::gateway_registered_key(&open)?;
                    let owner = NodeSecret::process_key().seal(
                        format!("ramflux.notify.route_owner.v1\0{target}").as_bytes(),
                        &serde_json::to_vec(&authority)?,
                    )?;
                    txn.open_table(super::super::route_authority::OWNERS)?
                        .insert(target, owner.as_slice())?;
                    seal(NodeSecret::process_key(), target, &rows)?
                };
                txn.open_table(NOTIFY_ROUTE_TABLE)?.insert(target, bytes.as_slice())?;
            }
            txn.commit()?;
            drop(db);
            let before = image(directory.path())?;
            assert!(
                matches!(NotifyRedbStore::open_with_wal_root(&path, Some(&wal)), Err(NodeCoreError::UnsupportedPersistedFormat(label)) if label == expected),
                "startup must identify the exact rejected notify format: {expected}"
            );
            assert_eq!(
                image(directory.path())?,
                before,
                "notify refusal must preserve every table and WAL file: {expected}"
            );
        }
        Ok(())
    }

    #[test]
    fn startup_refuses_ownerless_encrypted_routes_before_initialization_or_wal_writes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("notify.redb");
        let wal = directory.path().join("wal");
        drop(NotifyRedbStore::open_with_wal_root(&path, Some(&wal))?);
        let now = crate::now_unix_seconds();
        let route = DevicePushRoute {
            device_delivery_id: "target".into(),
            provider: PushProviderKind::Apns,
            credential_id: None,
            token: "token".into(),
            endpoint: "endpoint".into(),
            webpush_p256dh: None,
            webpush_auth: None,
            registered_at: now,
            expires_at: now + 60,
            route_generation: 0,
        };
        let db = redb::Database::open(&path)?;
        let write = db.begin_write()?;
        write
            .open_table(NOTIFY_ROUTE_TABLE)?
            .insert("target", seal(NodeSecret::process_key(), "target", &[route])?.as_slice())?;
        // Current bookkeeping alongside the retired ownerless row must also stay unchanged.
        write
            .open_table(redb::TableDefinition::<&str, (u64, u64)>::new("notify_route_fence_v2"))?
            .insert("target", (1, now))?;
        write.commit()?;
        drop(db);
        let before = image(directory.path())?;
        assert!(
            matches!(
                NotifyRedbStore::open_with_wal_root(&path, Some(&wal)),
                Err(NodeCoreError::UnsupportedPersistedFormat("notify unowned route"))
            ),
            "ownerless encrypted routes must fail during startup preflight"
        );
        assert_eq!(
            image(directory.path())?,
            before,
            "notify refusal changed a table, fence or WAL file"
        );
        Ok(())
    }

    #[test]
    fn current_bound_encrypted_route_survives_startup_preflight()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("notify.redb");
        let mut store = NotifyRedbStore::open_without_wal(&path)?;
        let open = crate::test_support::federation_fixtures::gateway_open_frame("device", "route");
        let authority = crate::test_support::federation_fixtures::gateway_registered_key(&open)?;
        store.set_push_route_authorizer(|_| Ok(true));
        let now = crate::now_unix_seconds();
        let route = DevicePushRoute {
            device_delivery_id: authority.target_delivery_id.clone(),
            provider: PushProviderKind::Apns,
            credential_id: None,
            token: "token".into(),
            endpoint: "endpoint".into(),
            webpush_p256dh: None,
            webpush_auth: None,
            registered_at: now,
            expires_at: now + 60,
            route_generation: 0,
        };
        store.register_authenticated_push_route(&authority, &route)?;
        let expected = store.load_notify_routes(&authority.target_delivery_id)?;
        drop(store);
        let store = NotifyRedbStore::open_without_wal(&path)?;
        assert_eq!(
            store
                .load_state()?
                .ok_or("route state missing")?
                .routes_by_device
                .get(&authority.target_delivery_id),
            Some(&expected),
            "current encrypted routes and authenticated owner bindings must survive reopen"
        );
        Ok(())
    }
}
