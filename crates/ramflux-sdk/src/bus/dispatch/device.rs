// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::gateway::{GatewayPushProvider, GatewayPushRouteRegistration};
use crate::prelude::*;

pub(crate) async fn dispatch_device_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "device.list" => dispatch_device_list(request, state),
        "push.keyset.get" => dispatch_push_keyset_get(request, state),
        "device.refresh" => {
            super::identity_authority::dispatch_identity_authority(request, state).await
        }
        "device.revoke" => {
            let body: LocalBusDeviceRevokeRequest = serde_json::from_value(request.body.clone())?;
            dispatch_device_revoke(request, state, body).await
        }
        "device.push_route.set" => Box::pin(dispatch_push_route_set(request, state)).await,
        "device.sync.export" => {
            let body: LocalBusDeviceSyncExportRequest =
                serde_json::from_value(request.body.clone())?;
            dispatch_device_sync_export(request, state, &body)
        }
        "device.pair.begin"
        | "device.pair.join"
        | "device.pair.confirm"
        | "device.pair.approve"
        | "device.pair.cancel"
        | "device.transfer.begin"
        | "device.transfer.join"
        | "device.transfer.confirm"
        | "device.transfer.cancel"
        | "device.transfer.tail_abandon"
        | "device.transfer.prepare"
        | "device.transfer.affirm"
        | "device.transfer.status"
        | "device.pair.status" => dispatch_device_pair(request, state).await,
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

/// Checkpoint holding this device's push route; restored into the gateway config at startup.
pub(crate) const PUSH_ROUTE_CHECKPOINT: &str = "gateway.push_route.v1";

/// Canonical empty book. A confirmed deregistration stores this shape; `""` is not a sentinel.
pub(crate) const EMPTY_PUSH_ROUTE_BOOK: &str = r#"{"routes":{},"clears":[],"clear_all":false}"#;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalBusPushRouteSetRequest {
    registration: Option<GatewayPushRouteRegistration>,
}

/// Checkpoint holding the last push route control sequence, so a restart never reuses one.
pub(crate) const PUSH_ROUTE_SEQ_CHECKPOINT: &str = "gateway.push_route_seq.v1";

/// Last persisted push route control sequence (0 when none was saved).
pub(crate) fn stored_push_route_seq(client: &RamfluxClient) -> Result<u64, SdkError> {
    Ok(client
        .projection_checkpoint(PUSH_ROUTE_SEQ_CHECKPOINT)?
        .and_then(|value| value.parse().ok())
        .unwrap_or(0))
}

/// Persisted push route state restored into the gateway config at startup.
pub(crate) struct StoredPushRoute {
    pub(crate) routes: BTreeMap<GatewayPushProvider, GatewayPushRouteRegistration>,
    pub(crate) clears: BTreeSet<GatewayPushProvider>,
    pub(crate) clear_pending: bool,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct StoredPushBook {
    routes: BTreeMap<GatewayPushProvider, GatewayPushRouteRegistration>,
    clears: BTreeSet<GatewayPushProvider>,
    clear_all: bool,
}

/// Restores the persisted push-route book. A missing checkpoint is no routes.
/// A present empty string, or any other non-book, is invalid.
///
/// # Errors
/// Returns an error when the checkpoint is present and is not the book.
pub(crate) fn stored_push_route(client: &RamfluxClient) -> Result<StoredPushRoute, SdkError> {
    let Some(value) = client.projection_checkpoint(PUSH_ROUTE_CHECKPOINT)? else {
        return Ok(empty_stored_push());
    };
    if value.is_empty() {
        return Err(SdkError::LocalBus("invalid push route checkpoint".to_owned()));
    }
    let parsed: serde_json::Value = serde_json::from_str(&value)?;
    if parsed.get("routes").is_none() {
        return Err(SdkError::LocalBus("invalid push route checkpoint".to_owned()));
    }
    let book: StoredPushBook = serde_json::from_value(parsed)?;
    Ok(StoredPushRoute { routes: book.routes, clears: book.clears, clear_pending: book.clear_all })
}

fn empty_stored_push() -> StoredPushRoute {
    StoredPushRoute { routes: BTreeMap::new(), clears: BTreeSet::new(), clear_pending: false }
}

fn encode_stored_push(stored: &StoredPushRoute) -> Result<String, SdkError> {
    Ok(serde_json::to_string(&StoredPushBook {
        routes: stored.routes.clone(),
        clears: stored.clears.clone(),
        clear_all: stored.clear_pending,
    })?)
}

/// Sets the push route after a token change and registers it now, or clears it and deletes
/// the node route; reconnects and liveness checks re-register and renew a set route, and keep
/// retrying an unconfirmed deregistration with backoff.
async fn dispatch_push_route_set(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusPushRouteSetRequest = serde_json::from_value(request.body.clone())?;
    let account_id = request_account_id(request)?.to_owned();
    let account = local_bus_account_mut(state, &account_id)?;
    let mut stored = stored_push_route(&account.client)?;
    let cleared = body.registration.is_none();
    if let Some(registration) = &body.registration {
        stored.clears.remove(&registration.provider);
        stored.clear_pending = false;
        stored.routes.insert(registration.provider, registration.clone());
    } else {
        stored.routes.clear();
        stored.clears.clear();
        stored.clear_pending = true;
    }
    let encoded = encode_stored_push(&stored)?;
    account.client.set_projection_checkpoint(PUSH_ROUTE_CHECKPOINT, &encoded)?;
    account.gateway_config.push_routes.clone_from(&stored.routes);
    account.gateway_config.push_route_clears.clone_from(&stored.clears);
    account.gateway_config.push_route_clear_pending = stored.clear_pending;
    let mut engine = account.session_client().await?;
    let outcome = engine.set_push_route(body.registration).await;
    account.apply_session_metadata(engine);
    account.persist_push_route_seq();
    crate::push_keyset::save_keysets(&account.client, &mut account.gateway_config.push);
    let expires_at = outcome?;
    if cleared {
        account.client.set_projection_checkpoint(PUSH_ROUTE_CHECKPOINT, EMPTY_PUSH_ROUTE_BOOK)?;
    }
    Ok(local_bus_ok(serde_json::json!({
        "registered": expires_at.is_some(),
        "deregistered": cleared,
        "expires_at": expires_at,
    })))
}

/// Local read of the central push key set state: mode, verified key set and its status.
fn dispatch_push_keyset_get(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account(state, account_id)?;
    let config = &account.gateway_config;
    let now = crate::push_keyset::unix_millis_now();
    let mode = config.push.mode.clone().unwrap_or_else(|| "unknown".to_owned());
    let pin = crate::push_keyset::configured_push_centre();
    let held = pin.as_ref().and_then(|pin| {
        config.push.keysets.iter().find(|record| record.centre_id == pin.centre_id)
    });
    let (status, record) = match (&pin, held, now) {
        (None, _, _) => ("no_pin", None),
        (Some(_), None, _) => ("missing", None),
        (Some(_), Some(record), None) => ("no_clock", Some(record)),
        (Some(_), Some(record), Some(now)) if record.expires_at <= now => ("expired", Some(record)),
        (Some(pin), Some(record), Some(now)) => {
            if crate::push_keyset::offer(pin, &record.doc, None, now).is_ok() {
                ("ok", Some(record))
            } else {
                ("invalid", Some(record))
            }
        }
    };
    Ok(local_bus_ok(serde_json::json!({
        "mode": mode,
        "status": status,
        "centre_id": record.map(|record| record.centre_id.clone()),
        "seq": record.map(|record| record.seq),
        "active_kid": record.map(|record| record.active_kid.clone()),
        "expires_at": record.map(|record| record.expires_at),
    })))
}

async fn dispatch_device_pair(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    Box::pin(crate::bus::pairing::ensure_actor(state, account_id, request)).await?;
    let result = {
        let work = crate::custody::pairing::handle_bus(
            &state.config.data_root,
            account_id,
            &request.method,
            request.body.clone(),
        );
        tokio::pin!(work);
        loop {
            let signal = crate::custody::pairing::work_signal(&state.config.data_root, account_id);
            tokio::select! {
                result = &mut work => break result,
                () = async {
                    match signal {
                        Some(signal) => signal.notified().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(account) = state.accounts.get_mut(account_id) {
                        crate::custody::pairing::service_frontend(
                            &state.config.data_root, account_id, &mut account.client,
                        )?;
                    }
                }
            }
        }
    };
    if result.is_ok()
        && let Some(account) = state.accounts.get_mut(account_id)
    {
        crate::bus::pairing::refresh_source_role(account)?;
    }
    match result {
        Ok(result) => Ok(local_bus_ok(serde_json::to_value(result)?)),
        Err(SdkError::PairingCode("NotFound")) => {
            Err(SdkError::LocalBus(format!("unsupported local bus method: {}", request.method)))
        }
        Err(error) => Err(error),
    }
}

fn dispatch_device_list(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account(state, account_id)?;
    let devices = account_known_devices(account)?;
    Ok(local_bus_ok(serde_json::to_value(LocalBusDeviceListResponse {
        a2ui_renderer_capabilities: ramflux_protocol::renderer_capabilities(),
        principal_id: account.gateway_config.principal_id.clone(),
        local_device_id: account.gateway_config.device_id.clone(),
        devices,
    })?))
}

async fn dispatch_device_revoke(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    body: LocalBusDeviceRevokeRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?.to_owned();
    let account = local_bus_account_mut(state, &account_id)?;
    if account.client.born_v3_account.is_none() {
        return Err(SdkError::PairingCode("UpdateRequired"));
    }
    Box::pin(native_revoke::dispatch(account, &body.device_id)).await
}

fn dispatch_device_sync_export(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    body: &LocalBusDeviceSyncExportRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    crate::object::reject_retired_relay_service_key(body.relay_service_key_base64.is_some())?;
    let account = local_bus_account_mut(state, request_account_id(request)?)?;
    let root = account.client.own_account_anchor()?;
    account.client.require_native_publication_settled(&root)?;
    let staged = account.client.start_generated_history_transfer(&body.target_device_id)?;
    Ok(local_bus_ok(serde_json::json!({"target_device_id":body.target_device_id,"staged":staged})))
}

pub(crate) fn account_known_devices(
    account: &LocalBusAccountState,
) -> Result<Vec<LocalBusDeviceRecord>, SdkError> {
    let Some(native) = &account.client.born_v3_account else {
        return Err(SdkError::IdentityRootMissing);
    };
    let local = native.local_device_id()?;
    native
        .record()
        .body
        .devices
        .iter()
        .filter(|device| device.status == ramflux_protocol::DeviceSetStatus::Active)
        .map(|device| {
            Ok(LocalBusDeviceRecord {
                device_id: device.device_id.clone(),
                device_epoch: device.device_epoch,
                target_delivery_id: ramflux_protocol::qualified_device_id(
                    &native.record().body.account_anchor,
                    &device.device_id,
                )?,
                capability_scope: device
                    .branch_certificate
                    .as_ref()
                    .map_or_else(Vec::new, |certificate| certificate.body.capabilities.clone()),
                is_local: device.device_id == local,
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/native_device.rs"]
mod native_tests;

pub(crate) mod native_revoke;
