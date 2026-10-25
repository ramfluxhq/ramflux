// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypt provider tokens and WebPush keys with a mounted node secret, bound to delivery id.
use super::{
    DevicePushRoute, NOTIFY_QUEUE_KEY, NOTIFY_QUEUE_TABLE, NOTIFY_ROUTE_TABLE, NodeCoreError,
    NotifyQueueState, serialize_notify_value,
};
use crate::NodeSecret;
use redb::ReadableTable;
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
    if let Some(path) = std::env::var_os("RAMFLUX_NOTIFY_ROUTE_KEY_FILE") {
        NodeSecret::from_file(path)
    } else {
        Ok(NodeSecret::process_key().clone())
    }
}
pub(super) fn migrate(db: &mut redb::Database, key: &NodeSecret) -> Result<(), NodeCoreError> {
    let txn = db.begin_write().map_err(error)?;
    let mut changed = false;
    {
        let mut routes = txn.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?;
        let mut snapshot = txn.open_table(NOTIFY_QUEUE_TABLE).map_err(error)?;
        let bytes =
            snapshot.get(NOTIFY_QUEUE_KEY).map_err(error)?.map(|value| value.value().to_vec());
        if let Some(bytes) = bytes {
            let mut state: NotifyQueueState = serde_json::from_slice(&bytes).map_err(error)?;
            if !state.routes_by_device.is_empty() {
                for (device, values) in std::mem::take(&mut state.routes_by_device) {
                    if routes.get(device.as_str()).map_err(error)?.is_none() {
                        routes
                            .insert(device.as_str(), seal(key, &device, &values)?.as_slice())
                            .map_err(error)?;
                    }
                }
                snapshot
                    .insert(NOTIFY_QUEUE_KEY, serialize_notify_value(&state)?.as_slice())
                    .map_err(error)?;
                changed = true;
            }
        }
        let mut updates = Vec::new();
        for row in routes.iter().map_err(error)? {
            let (device, value) = row.map_err(error)?;
            if value.value().first() == Some(&b'[') {
                let values: Vec<DevicePushRoute> =
                    serde_json::from_slice(value.value()).map_err(error)?;
                updates.push((device.value().to_owned(), seal(key, device.value(), &values)?));
            } else {
                open(key, device.value(), value.value())?;
            }
        }
        changed |= !updates.is_empty();
        for (device, bytes) in updates {
            routes.insert(device.as_str(), bytes.as_slice()).map_err(error)?;
        }
    }
    txn.commit().map_err(error)?;
    if changed {
        db.compact().map_err(error)?;
    }
    Ok(())
}
