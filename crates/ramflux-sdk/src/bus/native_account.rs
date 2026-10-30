// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary unlocked account state using public native authority and independent node pins.
use super::state::{LocalBusAccountState, LocalBusDaemonState};
use crate::{
    AccountNetworkingReason, GatewayCustodyConfig, GatewayQuicEndpointConfig, GatewaySessionConfig,
    LocalBusCreatedAccount, LocalBusCreatedAccountState, RamfluxClient, SdkError,
};
use ramflux_protocol::custody::CustodyRefusal;
use std::{net::SocketAddr, path::PathBuf};
use zeroize::Zeroizing;

pub(super) async fn unlock(
    state: &mut LocalBusDaemonState,
    id: &str,
    passphrase: Zeroizing<String>,
    home_node_id: Option<String>,
) -> Result<LocalBusCreatedAccount, SdkError> {
    if let Some(account) = state.accounts.get(id) {
        account.client.verify_active_account_secret(id, passphrase.as_bytes())?;
        return response(account);
    }
    let root = state.config.data_root.clone();
    let mut client = RamfluxClient::new();
    client.open_account_index(&root)?;
    client.unlock_account(id, passphrase.as_bytes())?;
    if let Some(node_id) = home_node_id {
        client.account_db()?.persist_actor_state("account/node-id", &node_id)?;
        client.account_db()?.persist_actor_state("sync/node-id", &Some(&node_id))?;
    }
    drop(passphrase);
    let native = client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
    let anchor = native.record().body.account_anchor.clone();
    if native.recovery_publication_pending(&root)? {
        client.account_db()?.retire_outbound_for_recovery(
            &ramflux_protocol::custody::object_hash(native.record())?,
        )?;
    }
    let device = native.local_device_id()?.to_owned();
    // Pending restore branches are only local data selectors until recovery certifies them.
    let delivery = if native.branch_pending() {
        ramflux_protocol::qualified_device_id(&anchor, &device)?
    } else {
        client.owned_device_identity()?.storage_key().to_owned()
    };
    let publication = native.publication();
    let custodian_publication =
        native.custodian_publication(&root, crate::custody::network_now()?)?;
    if !native.authority_blocked() && !native.branch_pending() {
        client.observe_custody_manifest(
            &ramflux_protocol::custody::CustodyManifest {
                publication,
                custodian_publication,
                devices: Vec::new(),
            },
            &anchor,
            crate::custody::network_now()?,
        )?;
    }
    let endpoint = GatewayQuicEndpointConfig {
        bind_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
        gateway_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
        server_name: String::new(),
        ca_cert: PathBuf::new(),
        principal_id: client
            .born_v3_account
            .as_ref()
            .ok_or(SdkError::CustodySetupInvalid)?
            .record()
            .body
            .principal_id
            .clone(),
        device_id: device,
        target_delivery_id: delivery,
        prekey_http_url: None,
    };
    let gateway = GatewaySessionConfig::auto(endpoint).with_born_v3_account(
        client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?,
    );
    let mut account = LocalBusAccountState::disconnected(client, gateway, anchor);
    account.activation_pending = true;
    account.native_setup = Some(state.config.clone());
    if let Err(error) = account.ensure_gateway_live().await {
        let _ = error;
        tracing::debug!("native account data unlocked; networking pending");
    }
    let result = response(&account)?;
    state.accounts.insert(id.into(), account);
    state.active_account_id = Some(id.into());
    Ok(result)
}

pub(super) fn response(account: &LocalBusAccountState) -> Result<LocalBusCreatedAccount, SdkError> {
    let native = account.client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
    Ok(LocalBusCreatedAccount {
        account_id: native.local_account_id().into(),
        display_name: native.record().body.profile.display_name.clone(),
        state: LocalBusCreatedAccountState::Unlocked,
        networking: native.state(),
    })
}

pub(super) fn status(
    account: &LocalBusAccountState,
    account_id: &str,
) -> Result<serde_json::Value, SdkError> {
    let native = account.client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
    Ok(serde_json::json!({
        "account_id":account_id,"local_account_id":account_id,"state":"unlocked","networking":native.state(),
        "networking_reason":native.networking_reason(),
        "display_name":native.record().body.profile.display_name,"principal_id":native.record().body.principal_id,
        "authority_blocked":native.authority_blocked(),
        "principal_commitment":native.record().body.account_anchor,"device_id":account.gateway_config.device_id,
        "target_delivery_id":account.target_delivery_id,
        "node_id":account.client.account_db()?.load_actor_state::<String>("account/node-id")?,
        "session_id":account.engine.as_ref().map(|engine|engine.session().session_id.clone()),
        "active_transport_kind":account.engine.as_ref().map(|engine|engine.active_transport_kind().wire_name()),
        "pending_deliveries":account.pending_deliveries.len(),
    }))
}

pub(super) async fn unlock_request(
    state: &mut LocalBusDaemonState,
    id: &str,
    request: &crate::LocalBusFrame,
) -> Result<LocalBusCreatedAccount, SdkError> {
    let passphrase = request
        .body
        .as_object()
        .filter(|body| body.len() == 1)
        .and_then(|body| body.get("passphrase"))
        .and_then(serde_json::Value::as_str)
        .ok_or(SdkError::CustodySetupInvalid)?;
    unlock(state, id, Zeroizing::new(passphrase.to_owned()), None).await
}

pub(super) async fn finish_connection(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    if let Some(engine) = &account.engine {
        account.gateway_config = engine.config.clone();
        engine.target_delivery_id().clone_into(&mut account.target_delivery_id);
    }
    account.client.born_v3_account = Some(Box::new(crate::custody::load_account(
        account.client.account_index()?.root(),
        &account.client.account_db()?.local_account_id,
        crate::custody::network_now()?,
    )?));
    let native = account.client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
    if account
        .client
        .require_fresh_custody_head(&native.record().body.account_anchor, native.record())
        .is_err()
    {
        let anchor = native.record().body.account_anchor.clone();
        account
            .client
            .cache_verified_device_manifest(
                &account.gateway_config,
                &anchor,
                "native_session_current_head",
            )
            .await?;
    }
    account.client.born_v3_account = Some(Box::new(crate::custody::load_account(
        account.client.account_index()?.root(),
        &account.client.account_db()?.local_account_id,
        crate::custody::network_now()?,
    )?));
    account.activation_pending = false;
    if let Some(custody) = &account.gateway_config.custody {
        crate::custody::finish_recovery(
            &custody.account_root,
            &custody.account_id,
            custody.vault.as_ref(),
            crate::custody::network_now()?,
        )?;
    }
    Ok(())
}

pub(super) async fn refresh_public_authority(
    account: &mut LocalBusAccountState,
) -> Result<(), SdkError> {
    let root = account.client.account_index()?.root();
    let id = &account.client.account_db()?.local_account_id;
    let native = crate::custody::load_account(root, id, crate::custody::network_now()?)?;
    if native.branch_pending() {
        return Err(SdkError::NetworkingPending);
    }
    // Only an explicitly journaled master-certified replacement may precede directory publication.
    if native.recovery_publication_pending(root)? {
        account.client.born_v3_account = Some(Box::new(native));
        return Ok(());
    }
    let anchor = native.record().body.account_anchor.clone();
    if account.client.require_fresh_custody_head(&anchor, native.record()).is_err() {
        let manifest = crate::prekey::sdk_gateway_get_json::<
            Option<crate::prekey::SdkDeviceManifestResponse>,
        >(
            &account.gateway_config, &format!("/mvp1/device-manifest/{anchor}")
        )
        .await?;
        if let Some(manifest) = manifest {
            if manifest.principal_commitment != anchor || manifest.custody.is_none() {
                return Err(SdkError::CustodyModeDowngrade);
            }
            account.client.persist_fetched_identity_directory(&manifest)?;
        } else if native.state() == crate::custody::CreationState::Live {
            return Err(SdkError::InboundPending("native current head unavailable".into()));
        }
    }
    account.client.born_v3_account = Some(Box::new(crate::custody::load_account(
        account.client.account_index()?.root(),
        &account.client.account_db()?.local_account_id,
        crate::custody::network_now()?,
    )?));
    Ok(())
}

pub(super) async fn configure_pending(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    if account.gateway_config.custody.is_some() {
        return Ok(());
    }
    let setup = account.native_setup.as_ref().ok_or(SdkError::NetworkingPending)?;
    let root = &setup.data_root;
    let saved = account.client.account_db()?.load_actor_state::<String>("account/node-id")?;
    let nodes = crate::node::NodeStore::load(root, &setup.builtin_nodes)?;
    let profile = if let Some(id) = saved.as_deref() {
        nodes.profiles.get(id).cloned().ok_or(SdkError::NoNodeSelected)?
    } else {
        nodes.selected(None, false)?.ok_or(SdkError::NoNodeSelected)?
    };
    let old = &account.gateway_config;
    let endpoint = GatewayQuicEndpointConfig {
        bind_addr: old.bind_addr,
        gateway_addr: old.gateway_addr,
        server_name: old.server_name.clone(),
        ca_cert: old.ca_cert.clone(),
        principal_id: old.principal_id.clone(),
        device_id: old.device_id.clone(),
        target_delivery_id: old.target_delivery_id.clone(),
        prekey_http_url: None,
    };
    let endpoint = profile.gateway_config(root, endpoint).await?;
    let tcp = crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?;
    let gateway = GatewaySessionConfig::auto(endpoint)
        .with_tcp_gateway_addr(tcp)
        .with_native_custody(GatewayCustodyConfig {
            account_root: root.clone(),
            account_id: account.client.account_db()?.local_account_id.clone(),
            node_id: profile.node_id.clone(),
            node_public_key: profile.node_public_key.clone(),
            vault: super::custody_setup::primary_provider(setup),
        })
        .with_account_identity(&account.client)?;
    let relay = profile.relay_options(root, &gateway.principal_id).await?;
    account.client.account_db()?.persist_actor_state("account/node-id", &profile.node_id)?;
    account.client.account_db()?.persist_actor_state("sync/node-id", &Some(&profile.node_id))?;
    account.client.node_relay_options = Some(relay);
    account.gateway_config = gateway;
    Ok(())
}

const NODE_BUSY_RETRY_AFTER_MS: u64 = 16_000;
const NODE_UNREACHABLE_RETRY_AFTER_MS: u64 = 5_000;

pub(super) fn networking_reason(error: &SdkError) -> Option<AccountNetworkingReason> {
    match error {
        SdkError::NoNodeSelected => Some(AccountNetworkingReason::NoNodeSelected),
        SdkError::NodeUnreachable { retry_after_ms, .. }
        | SdkError::NodeTimeout { retry_after_ms } => {
            Some(AccountNetworkingReason::NodeUnreachable { retry_after_ms: *retry_after_ms })
        }
        SdkError::CustodyNetwork(CustodyRefusal::Unsupported) => {
            Some(AccountNetworkingReason::NodeCustodyUnavailable)
        }
        SdkError::CustodyNetwork(CustodyRefusal::Busy | CustodyRefusal::Capacity) => {
            Some(AccountNetworkingReason::NodeBusy { retry_after_ms: NODE_BUSY_RETRY_AFTER_MS })
        }
        SdkError::CustodyNetwork(
            CustodyRefusal::ChallengeExpired | CustodyRefusal::SessionExpired,
        )
        | SdkError::CustodyExpired => Some(AccountNetworkingReason::CustodyExpired),
        SdkError::CustodyNetwork(code) => {
            Some(AccountNetworkingReason::RegistrationRefused { code: code.clone() })
        }
        SdkError::Transport(error) if transport_is_unreachable(error) => {
            Some(AccountNetworkingReason::NodeUnreachable {
                retry_after_ms: NODE_UNREACHABLE_RETRY_AFTER_MS,
            })
        }
        _ => None,
    }
}

fn transport_is_unreachable(error: &ramflux_transport::TransportError) -> bool {
    match error {
        ramflux_transport::TransportError::NotOpen
        | ramflux_transport::TransportError::Io(_)
        | ramflux_transport::TransportError::Quic(_)
        | ramflux_transport::TransportError::RetryExhausted { .. } => true,
        ramflux_transport::TransportError::HttpClient(error) => {
            error.is_connect() || error.is_timeout()
        }
        _ => false,
    }
}

pub(super) fn record_networking(
    account: &mut LocalBusAccountState,
    error: Option<&SdkError>,
) -> Result<(), SdkError> {
    let root = account.client.account_index()?.root().to_path_buf();
    let id = account.client.account_db()?.local_account_id.clone();
    let now = crate::custody::network_now()?;
    let mut native = crate::custody::load_account(&root, &id, now)?;
    if native.state() == crate::custody::CreationState::NetworkingPending {
        if let Some(error) = error {
            native.set_networking_reason(&root, networking_reason(error))?;
        }
        native = crate::custody::load_account(&root, &id, now)?;
    }
    let body = serde_json::json!({
        "account_id": id,
        "state": native.state(),
        "networking_reason": native.networking_reason(),
    });
    let db = account.client.account_db()?;
    if db.load_actor_state::<serde_json::Value>("account/networking")?.as_ref() != Some(&body) {
        db.persist_actor_state("account/networking", &body)?;
    }
    account.client.born_v3_account = Some(Box::new(native));
    Ok(())
}
