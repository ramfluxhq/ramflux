// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::gateway::GatewayPushRouteRegistration;
use crate::prelude::*;

pub(crate) async fn dispatch_device_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "device.list" => dispatch_device_list(request, state),
        "device.authorize" | "device.migrate" | "device.refresh" => {
            super::identity_authority::dispatch_identity_authority(request, state).await
        }
        "device.activate" => {
            let body: LocalBusDeviceActivateRequest = serde_json::from_value(request.body.clone())?;
            dispatch_device_activate(request, state, body).await
        }
        "device.revoke" => {
            let body: LocalBusDeviceRevokeRequest = serde_json::from_value(request.body.clone())?;
            dispatch_device_revoke(request, state, body).await
        }
        "device.push_route.set" => Box::pin(dispatch_push_route_set(request, state)).await,
        "device.sync.export" => {
            let body: LocalBusDeviceSyncExportRequest =
                serde_json::from_value(request.body.clone())?;
            Box::pin(dispatch_device_sync_export(request, state, body)).await
        }
        "device.sync.import" => {
            let body: LocalBusDeviceSyncImportRequest =
                serde_json::from_value(request.body.clone())?;
            Box::pin(dispatch_device_sync_import(request, state, body)).await
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

/// Checkpoint holding this device's push route; restored into the gateway config at startup.
pub(crate) const PUSH_ROUTE_CHECKPOINT: &str = "gateway.push_route.v1";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalBusPushRouteSetRequest {
    registration: Option<GatewayPushRouteRegistration>,
}

/// Restores the persisted push route so every reconnect re-registers it.
pub(crate) fn stored_push_route(
    client: &RamfluxClient,
) -> Result<Option<GatewayPushRouteRegistration>, SdkError> {
    Ok(match client.projection_checkpoint(PUSH_ROUTE_CHECKPOINT)? {
        Some(value) if !value.is_empty() => Some(serde_json::from_str(&value)?),
        _ => None,
    })
}

/// Sets or clears the push route after a token change and registers it now; reconnects and
/// liveness checks re-register and renew it from then on.
async fn dispatch_push_route_set(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusPushRouteSetRequest = serde_json::from_value(request.body.clone())?;
    let account_id = request_account_id(request)?.to_owned();
    let account = local_bus_account_mut(state, &account_id)?;
    let stored = body.registration.as_ref().map(serde_json::to_string).transpose()?;
    account
        .client
        .set_projection_checkpoint(PUSH_ROUTE_CHECKPOINT, stored.as_deref().unwrap_or(""))?;
    account.gateway_config.push_route.clone_from(&body.registration);
    let expires_at = if let Some(engine) = account.engine.as_mut() {
        engine.set_push_route(body.registration).await?
    } else {
        account.ensure_gateway_live().await?;
        account.engine.as_ref().and_then(GatewaySessionEngine::push_route_expires_at)
    };
    Ok(local_bus_ok(serde_json::json!({
        "registered": expires_at.is_some(),
        "expires_at": expires_at,
    })))
}

fn dispatch_device_list(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account(state, account_id)?;
    let devices = account_known_devices(state, account_id, account)?;
    Ok(local_bus_ok(serde_json::to_value(LocalBusDeviceListResponse {
        principal_id: account.gateway_config.principal_id.clone(),
        local_device_id: account.gateway_config.device_id.clone(),
        devices,
    })?))
}

async fn dispatch_device_activate(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    body: LocalBusDeviceActivateRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?.to_owned();
    let data_root = state.config.data_root.clone();
    let manifest_path = local_bus_account_manifest_path(&data_root, &account_id);
    let mut manifest = read_local_bus_account_manifest(&manifest_path)?;
    if let Some(id) = body.node_id.as_deref()
        && manifest.node_id.as_deref().is_some_and(|bound| bound != id)
    {
        return Err(crate::node::node_error(
            "device activation cannot change the account node binding",
        ));
    }
    let mut relay_options = None;
    if let Some(id) = body.node_id.as_deref() {
        let profile = state
            .nodes
            .selected(Some(id), manifest.node_id.is_some())?
            .ok_or_else(|| crate::node::node_error("unknown node"))?;
        manifest.gateway = profile.gateway_config(&data_root, manifest.gateway).await?;
        manifest.node_tcp_addr =
            Some(crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?);
        manifest.node_relay = Some(profile.relay.clone());
        manifest.node_id = Some(id.to_owned());
        relay_options = Some(profile.relay_options(&data_root, &manifest.principal_id).await?);
    }
    let account = local_bus_account_mut(state, &account_id)?;
    if let Some(options) = relay_options {
        account.client.node_relay_options = Some(options);
        account.relay_quic_pool = None;
    }
    if manifest.principal_id != account.gateway_config.principal_id {
        return Err(SdkError::LocalBus("account manifest principal mismatch".to_owned()));
    }
    let device_epoch = body.device_epoch.unwrap_or(1);
    let branch = account.client.create_device_branch(
        &manifest.principal_id,
        &body.device_id,
        device_epoch,
        body.device_seed,
    );
    let now = now_unix_timestamp();
    let branch_authorized_event_id =
        append_device_branch_authorized_event(account, &body.device_id, device_epoch, now)?;
    let mut endpoint = manifest.gateway.clone();
    endpoint.principal_id.clone_from(&manifest.principal_id);
    endpoint.device_id.clone_from(&body.device_id);
    endpoint.target_delivery_id.clone_from(&body.target_delivery_id);
    let mut gateway = GatewaySessionConfig::auto(endpoint.clone()).with_owned_device(
        account.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        branch,
    )?;
    if let Some(addr) = manifest.node_tcp_addr {
        gateway = gateway.with_tcp_gateway_addr(addr);
    }
    account
        .client
        .initialize_and_publish_prekey_bundle_via_gateway_request(
            &gateway,
            &manifest.principal_commitment,
            &body.device_id,
            &body.target_delivery_id,
            body.device_seed,
        )
        .await?;
    assert_manifest_active_device(&gateway, &manifest.principal_commitment, &body.device_id)
        .await?;

    // C2 intentionally keeps gateway mesh re-join/session-resume tokens out of device activation.
    // Fresh-session-per-connect already resumes delivery through durable gateway cursors; re-join
    // tokens are a transport optimization and will be handled in a dedicated slice.
    let engine = account.client.connect_gateway_session(gateway).await?;
    account.put_engine(engine);
    update_manifest_for_activated_device(&mut manifest, &body, device_epoch, endpoint);
    write_local_bus_account_manifest(&data_root, &manifest)?;
    let devices = manifest.devices.clone();
    device_activate_response(
        account,
        DeviceActivateResult {
            account_id,
            principal_id: manifest.principal_id,
            body,
            device_epoch,
            branch_authorized_event_id,
            devices,
        },
    )
}

async fn dispatch_device_revoke(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    body: LocalBusDeviceRevokeRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?.to_owned();
    let data_root = state.config.data_root.clone();
    let manifest_path = local_bus_account_manifest_path(&data_root, &account_id);
    let mut manifest = read_local_bus_account_manifest(&manifest_path)?;
    let account = local_bus_account_mut(state, &account_id)?;
    let root = ramflux_crypto::create_identity_root(&manifest.principal_id, manifest.root_seed);
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let derived_commitment = identity_root_public_key_commitment(&root_public_key)?;
    if derived_commitment != manifest.principal_commitment {
        return Err(SdkError::LocalBus("account manifest root commitment mismatch".to_owned()));
    }
    let revoked_at = now_unix_timestamp();
    let mut gateway = GatewaySessionConfig::auto(manifest.gateway.clone());
    if let Some(addr) = manifest.node_tcp_addr {
        gateway = gateway.with_tcp_gateway_addr(addr);
    }
    let record = account.client.revoke_owned_device(&gateway, &body.device_id).await?;
    manifest.devices.retain(|device| device.device_id != body.device_id);
    write_local_bus_account_manifest(&data_root, &manifest)?;
    account.client.append_event(
        &format!("device.branch_revoked:{}", body.device_id),
        "identity.device_branch.revoked",
        &serde_json::to_vec(&serde_json::json!({
            "device_id": body.device_id,
            "revoked_at": revoked_at,
        }))?,
    )?;
    Ok(local_bus_ok(
        serde_json::json!({"device_id":body.device_id,"revoked":true,"publication_state":"submitted","device_set_epoch":record.device_set_epoch}),
    ))
}

async fn dispatch_device_sync_export(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    body: LocalBusDeviceSyncExportRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?.to_owned();
    let manifest_path = local_bus_account_manifest_path(&state.config.data_root, &account_id);
    let manifest = read_local_bus_account_manifest(&manifest_path)?;
    let account = local_bus_account_mut(state, &account_id)?;
    let mut engine = account.take_live_engine().await?;
    let pool = account.relay_quic_pool()?;
    let response = account
        .client
        .export_own_device_sync(
            &mut engine,
            &pool,
            &manifest.principal_commitment,
            &body.target_device_id,
            &body.relay_endpoint,
            body.relay_service_key_base64,
            body.chunk_size.unwrap_or(64 * 1024),
        )
        .await;
    account.put_engine(engine);
    Ok(local_bus_ok(serde_json::to_value(response?)?))
}

async fn dispatch_device_sync_import(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    body: LocalBusDeviceSyncImportRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?.to_owned();
    let manifest_path = local_bus_account_manifest_path(&state.config.data_root, &account_id);
    let manifest = read_local_bus_account_manifest(&manifest_path)?;
    let account = local_bus_account_mut(state, &account_id)?;
    let envelope: SdkOwnDeviceSyncEnvelope = serde_json::from_value(body.envelope)?;
    let mut engine = account.take_live_engine().await?;
    let pool = account.relay_quic_pool()?;
    let response = account
        .client
        .import_own_device_sync(
            &mut engine,
            &pool,
            &manifest.principal_commitment,
            &envelope,
            body.relay_service_key_base64,
        )
        .await;
    account.put_engine(engine);
    Ok(local_bus_ok(serde_json::to_value(response?)?))
}

fn append_device_branch_authorized_event(
    account: &LocalBusAccountState,
    device_id: &str,
    device_epoch: u64,
    now: i64,
) -> Result<String, SdkError> {
    let proof = account.client.authorize_current_device(
        "ramflux-node",
        default_device_capability_scope(),
        now,
        now.saturating_add(
            crate::client::identity_authority::registration::proof_lifetime_seconds()?,
        ),
    )?;
    let branch_authorized_event_id = format!("device.branch_authorized:{device_id}:{device_epoch}");
    let branch_proof_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.sdk.device.branch_authorized.v1",
        &serde_json::to_vec(&proof)?,
    );
    let event = ramflux_protocol::IdentityEventBody::DeviceBranchAuthorized {
        device_id: device_id.to_owned(),
        device_epoch,
        branch_proof_hash,
        capability_scope: default_device_capability_scope(),
    };
    account.client.append_event(
        &branch_authorized_event_id,
        "identity.device_branch.authorized",
        &serde_json::to_vec(&event)?,
    )?;
    Ok(branch_authorized_event_id)
}

fn update_manifest_for_activated_device(
    manifest: &mut LocalBusPersistedAccount,
    body: &LocalBusDeviceActivateRequest,
    device_epoch: u64,
    endpoint: GatewayQuicEndpointConfig,
) {
    let previous_devices = normalize_manifest_devices(
        std::mem::take(&mut manifest.devices),
        &LocalBusDeviceRecord {
            device_id: manifest.device_id.clone(),
            device_epoch: 1,
            target_delivery_id: manifest.target_delivery_id.clone(),
            capability_scope: default_device_capability_scope(),
            is_local: false,
        },
    );
    manifest.device_id.clone_from(&body.device_id);
    manifest.target_delivery_id.clone_from(&body.target_delivery_id);
    manifest.device_seed = body.device_seed;
    manifest.gateway = endpoint;
    manifest.devices = merge_manifest_device(
        previous_devices,
        LocalBusDeviceRecord {
            device_id: body.device_id.clone(),
            device_epoch,
            target_delivery_id: body.target_delivery_id.clone(),
            capability_scope: default_device_capability_scope(),
            is_local: true,
        },
        &body.device_id,
    );
}

struct DeviceActivateResult {
    account_id: String,
    principal_id: String,
    body: LocalBusDeviceActivateRequest,
    device_epoch: u64,
    branch_authorized_event_id: String,
    devices: Vec<LocalBusDeviceRecord>,
}

fn device_activate_response(
    account: &LocalBusAccountState,
    result: DeviceActivateResult,
) -> Result<LocalBusDispatchResult, SdkError> {
    Ok(local_bus_ok(serde_json::to_value(LocalBusDeviceActivateResponse {
        local_account_id: result.account_id,
        principal_id: result.principal_id,
        device_id: result.body.device_id,
        device_epoch: result.device_epoch,
        target_delivery_id: result.body.target_delivery_id,
        branch_authorized_event_id: result.branch_authorized_event_id,
        session_id: account.engine.as_ref().map_or_else(
            || "disconnected".to_owned(),
            |engine| engine.session().session_id.clone(),
        ),
        active_transport_kind: account.engine.as_ref().map_or_else(
            || "disconnected".to_owned(),
            |engine| engine.active_transport_kind().wire_name().to_owned(),
        ),
        devices: result.devices,
    })?))
}

pub(crate) fn account_known_devices(
    state: &LocalBusDaemonState,
    account_id: &str,
    account: &LocalBusAccountState,
) -> Result<Vec<LocalBusDeviceRecord>, SdkError> {
    let manifest_path = local_bus_account_manifest_path(&state.config.data_root, account_id);
    let manifest = read_local_bus_account_manifest(&manifest_path)?;
    let current = LocalBusDeviceRecord {
        device_id: account.gateway_config.device_id.clone(),
        device_epoch: account.gateway_config.device_epoch,
        target_delivery_id: account.target_delivery_id.clone(),
        capability_scope: default_device_capability_scope(),
        is_local: true,
    };
    Ok(normalize_manifest_devices(manifest.devices, &current))
}

pub(crate) fn normalize_manifest_devices(
    devices: Vec<LocalBusDeviceRecord>,
    current: &LocalBusDeviceRecord,
) -> Vec<LocalBusDeviceRecord> {
    merge_manifest_device(devices, current.clone(), &current.device_id)
}

fn merge_manifest_device(
    devices: Vec<LocalBusDeviceRecord>,
    mut current: LocalBusDeviceRecord,
    local_device_id: &str,
) -> Vec<LocalBusDeviceRecord> {
    let mut rows = Vec::<LocalBusDeviceRecord>::new();
    for mut device in devices {
        device.is_local = device.device_id == local_device_id;
        rows.retain(|row| row.device_id != device.device_id);
        rows.push(device);
    }
    current.is_local = true;
    rows.retain(|row| row.device_id != current.device_id);
    rows.push(current);
    rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    rows
}
