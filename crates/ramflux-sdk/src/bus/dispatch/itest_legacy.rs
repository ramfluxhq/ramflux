// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit seed-taking account setup for unmigrated integration fixtures only.
#![cfg(feature = "itest-legacy-accounts")]
use crate::bus::daemon::restore_local_bus_account_with_passphrase;
use crate::prelude::*;

pub(crate) async fn local_bus_account_create(
    state: &mut LocalBusDaemonState,
    mut body: LocalBusAccountCreateRequest,
) -> Result<LocalBusAccountCreateResponse, SdkError> {
    if crate::custody::account_exists(&state.config.data_root, &body.local_account_id)? {
        return Err(SdkError::NetworkingPending);
    }
    if let Some(label) = &body.label {
        crate::bus::metadata::validate_label(label)
            .map_err(|message| SdkError::LocalBus(message.to_owned()))?;
    }
    let data_root = state.config.data_root.clone();
    let manifest_path = local_bus_account_manifest_path(&data_root, &body.local_account_id);
    if crate::bus::daemon::account_manifest_available(&manifest_path) {
        let manifest = read_local_bus_account_manifest(&manifest_path)?;
        if body.node_id.is_some() && body.node_id != manifest.node_id {
            return Err(crate::node::node_error("account node binding cannot be changed"));
        }
        if let Some(account) = state.accounts.get_mut(&manifest.local_account_id) {
            account.client.verify_active_account_secret(
                &manifest.local_account_id,
                body.account_secret.as_bytes(),
            )?;
            if let Err(error) = account.ensure_gateway_live().await {
                tracing::warn!(%error,"account restored without a live gateway session");
            }
            return Ok(local_bus_account_response(&manifest, account));
        }
        let response =
            restore_local_bus_account_with_passphrase(state, &manifest, &body.account_secret)
                .await?;
        state.active_account_id = Some(response.local_account_id.clone());
        return Ok(response);
    }
    let profile = state.nodes.selected(body.node_id.as_deref(), false)?;
    let mut client = RamfluxClient::new();
    client.account_index = state.account_index.clone();
    if state.account_index.is_some() {
        client.object_store.set_cache_capacity(8);
    }
    let node_relay = profile.as_ref().map(|profile| profile.relay.clone());
    let mut node_tcp_addr = None;
    if let Some(profile) = profile {
        body.node_id = Some(profile.node_id.clone());
        body.gateway = profile.gateway_config(&data_root, body.gateway).await?;
        node_tcp_addr = Some(crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?);
        client.node_relay_options =
            Some(profile.relay_options(&data_root, &body.principal_id).await?);
    }
    if body.gateway.ca_cert.as_os_str().is_empty() {
        return Err(crate::node::node_error(
            "node_id, a default node, or gateway configuration is required",
        ));
    }
    body.gateway.principal_id.clone_from(&body.principal_id);
    body.gateway.device_id.clone_from(&body.device_id);
    body.gateway.target_delivery_id.clone_from(&body.target_delivery_id);
    initialize_created_account(&mut client, &mut body)?;
    client.open_account_index(&data_root)?;
    if client.account_index()?.account(&body.local_account_id).is_ok() {
        return Err(SdkError::LocalBus(
            "account creation requires reconciliation: index exists without a manifest".to_owned(),
        ));
    }
    client.create_account(&body.local_account_id, &body.principal_commitment)?;
    if state.account_index.is_none() {
        client.set_active_account(&body.local_account_id)?;
    }
    client.unlock_account(&body.local_account_id, body.account_secret.as_bytes())?;
    record_initial_branch(&client, &body)?;
    let mut gateway = GatewaySessionConfig::auto(body.gateway.clone()).with_owned_device(
        client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
    )?;
    if let Some(addr) = node_tcp_addr {
        gateway = gateway.with_tcp_gateway_addr(addr);
    }
    let mut manifest = LocalBusPersistedAccount::from_create_request(&body);
    manifest.node_tcp_addr = node_tcp_addr;
    manifest.node_relay = node_relay;
    // Persist recovery credentials before any remote registration/publish can be acknowledged.
    write_local_bus_account_manifest(&data_root, &manifest)?;
    let id = body.local_account_id;
    state.accounts.insert(
        id.clone(),
        LocalBusAccountState::disconnected(client, gateway, body.principal_commitment),
    );
    let account = local_bus_account_mut(state, &id)?;
    account.activation_pending = true;
    account.ensure_gateway_live().await?;
    state.active_account_id = Some(id.clone());
    Ok(local_bus_account_response(&manifest, local_bus_account(state, &id)?))
}

fn initialize_created_account(
    client: &mut RamfluxClient,
    body: &mut LocalBusAccountCreateRequest,
) -> Result<(), SdkError> {
    if body.client_mode == LocalBusClientMode::HeadlessAi
        && body.kind == Some(ramflux_protocol::PrincipalKind::Human)
    {
        return Err(SdkError::InboundRejected("headless account cannot claim human kind".into()));
    }
    let root = client.create_identity_root(&body.principal_id, body.root_seed);
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let derived_commitment = identity_root_public_key_commitment(&root_public_key)?;
    if body.principal_commitment.is_empty() {
        body.principal_commitment.clone_from(&derived_commitment);
    } else if body.principal_commitment != derived_commitment {
        return Err(SdkError::LocalBus(format!(
            "principal_commitment mismatch: expected {derived_commitment}"
        )));
    }
    client.create_device_branch(&body.principal_id, &body.device_id, 1, body.device_seed);
    Ok(())
}

fn record_initial_branch(
    client: &RamfluxClient,
    body: &LocalBusAccountCreateRequest,
) -> Result<(), SdkError> {
    client.set_contact_request_policy(if body.client_mode == LocalBusClientMode::HeadlessAi {
        "auto_accept"
    } else {
        "manual"
    })?;
    let mode = body.client_mode.clone();
    let device_state = serde_json::json!({
        "device_kind": "cli",
        "client_mode": mode,
        "device_id": body.device_id,
        "target_delivery_id": body.target_delivery_id,
    });
    client.append_event(
        &format!("device.branch.created:{}", body.device_id),
        "device.branch.created",
        &serde_json::to_vec(&device_state)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(root: &Path) -> LocalBusDaemonState {
        LocalBusDaemonState {
            config: LocalBusConfig::new(root.join("bus.sock"), root),
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::new(),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn itest_legacy_namespace_requires_runtime_opt_in_and_cannot_replace_native()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let vault = crate::custody::tests::TestVault::default();
        crate::custody::tests::create(&root.0, "alice", &vault, crate::custody::network_now()?)?;
        let authority = root.0.join("custody_accounts/alice/authority.json");
        let before = std::fs::read(&authority)?;
        let mut daemon = state(&root.0);
        let request = LocalBusFrame::request(
            "fixture",
            None,
            "account",
            "account.itest_legacy.create",
            serde_json::json!({}),
        );
        let error = super::super::account::dispatch_account_bus_request(&request, &mut daemon)
            .await
            .err()
            .ok_or("fixture namespace accepted without opt-in")?;
        assert!(error.to_string().contains("unsupported local bus method"));
        daemon.config.itest_legacy_accounts = true;
        let body = LocalBusAccountCreateRequest {
            label: None,
            kind: None,
            node_id: None,
            local_account_id: "alice".into(),
            principal_id: "legacy-alice".into(),
            principal_commitment: String::new(),
            device_id: "legacy-device".into(),
            target_delivery_id: "legacy-target".into(),
            account_secret: "fixture account password".into(),
            root_seed: [41; 32],
            device_seed: [42; 32],
            client_mode: LocalBusClientMode::AttendedCli,
            gateway: GatewayQuicEndpointConfig {
                bind_addr: "127.0.0.1:0".parse()?,
                gateway_addr: "127.0.0.1:1".parse()?,
                server_name: "fixture.invalid".into(),
                ca_cert: root.0.join("unused.pem"),
                principal_id: "legacy-alice".into(),
                device_id: "legacy-device".into(),
                target_delivery_id: "legacy-target".into(),
                prekey_http_url: None,
            },
        };
        let mut request = request;
        request.body = serde_json::to_value(body)?;
        assert!(matches!(
            super::super::account::dispatch_account_bus_request(&request, &mut daemon).await,
            Err(SdkError::NetworkingPending)
        ));
        assert_eq!(std::fs::read(authority)?, before);
        assert!(!local_bus_account_manifest_path(&root.0, "alice").exists());
        assert!(daemon.accounts.is_empty());
        Ok(())
    }
}
