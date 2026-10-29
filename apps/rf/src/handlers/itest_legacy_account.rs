// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Seed-taking CLI setup restricted to explicitly enabled integration fixtures.
use super::account::{store_keychain_secret, with_keychain_store_result};
use super::{
    GatewayQuicEndpointConfig, ItestLegacyAccountCreate, LocalBusAccountCreateRequest,
    LocalBusClient, RfError, SocketAddr, print_json, resolve_seed,
};
use crate::keychain::{KeychainSecret, OsKeychain};

pub(super) async fn create(
    bus: &mut LocalBusClient,
    create: Box<ItestLegacyAccountCreate>,
) -> Result<(), RfError> {
    let use_keychain = create.use_keychain;
    let request = local_bus_account_create_request(*create)?;
    let keychain_secret =
        KeychainSecret::new(request.account_secret.clone(), Some(request.device_seed));
    let account_id = request.local_account_id.clone();
    let response = bus
        .request(None, "account", "account.itest_legacy.create", serde_json::to_value(request)?)
        .await?;
    if response.is_null() {
        return Err(RfError::Message("account.create returned an empty response".to_owned()));
    }
    let response = if use_keychain {
        with_keychain_store_result(
            response,
            store_keychain_secret(&OsKeychain, &account_id, &keychain_secret),
        )
    } else {
        response
    };
    print_json(&response)
}

pub(crate) fn local_bus_account_create_request(
    create: ItestLegacyAccountCreate,
) -> Result<LocalBusAccountCreateRequest, RfError> {
    let root_seed = resolve_seed(create.root_seed_byte_hex.as_deref())?;
    let principal_commitment =
        ramflux_sdk::identity_root_public_key_commitment_for_seed(&create.principal, root_seed);
    if let Some(expected) = create.expected_commitment.as_ref()
        && expected != &principal_commitment
    {
        return Err(RfError::Message(format!(
            "expected commitment mismatch: derived {principal_commitment}"
        )));
    }
    Ok(LocalBusAccountCreateRequest {
        label: None,
        kind: None,
        node_id: create.node,
        local_account_id: create.account,
        principal_id: create.principal.clone(),
        principal_commitment,
        device_id: create.device.clone(),
        target_delivery_id: create.target.clone(),
        account_secret: create.secret,
        root_seed,
        device_seed: resolve_seed(create.device_seed_byte_hex.as_deref())?,
        client_mode: parse_client_mode(&create.client_mode)?,
        gateway: GatewayQuicEndpointConfig {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            gateway_addr: create.gateway_addr.parse()?,
            server_name: create.server_name,
            ca_cert: create.ca_cert.unwrap_or_default(),
            principal_id: create.principal,
            device_id: create.device,
            target_delivery_id: create.target,
            prekey_http_url: create.prekey_http_url,
        },
    })
}

fn parse_client_mode(value: &str) -> Result<ramflux_sdk::LocalBusClientMode, RfError> {
    match value {
        "attended_cli" => Ok(ramflux_sdk::LocalBusClientMode::AttendedCli),
        "headless_ai" => Ok(ramflux_sdk::LocalBusClientMode::HeadlessAi),
        _ => Err(RfError::Message("invalid fixture client mode".into())),
    }
}
