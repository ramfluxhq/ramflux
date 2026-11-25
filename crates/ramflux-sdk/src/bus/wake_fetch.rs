// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-account, one-page receive host. No supervisor, actors or background workers.

use crate::custody::PrimaryVault;
use crate::{GatewayCustodyConfig, GatewaySessionConfig, GatewaySessionEngine, LocalBusConfig};
use crate::{GatewayTcpTlsEndpointConfig, RamfluxClient, SdkError};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

const PAGE_LIMIT: usize = 32;

mod notification;
mod receive;

/// Host result. Every field is always present; unknown fields are null on non-fetched outcomes.
#[derive(Serialize)]
pub(crate) struct Wire {
    outcome: &'static str,
    show: Option<bool>,
    unread_total: Option<String>,
    clears: Vec<&'static str>,
    calls: Vec<serde_json::Value>,
    receipts_sent: &'static str,
}

impl Wire {
    /// Unknown on busy, locked and deadline: no decision was consumed.
    fn unknown(outcome: &'static str) -> Self {
        Self {
            outcome,
            show: None,
            unread_total: None,
            clears: Vec::new(),
            calls: Vec::new(),
            receipts_sent: "0",
        }
    }

    fn fetched(decision: notification::Decision) -> Self {
        Self {
            outcome: "fetched",
            show: Some(decision.show),
            unread_total: Some(decision.unread_total.to_string()),
            clears: if decision.clears { vec!["messages"] } else { Vec::new() },
            calls: Vec::new(),
            receipts_sent: "0",
        }
    }
}

pub(crate) fn run(
    config: &LocalBusConfig,
    account_id: &str,
    vault: Arc<dyn PrimaryVault + Send + Sync>,
    deadline: std::time::Instant,
    lease_wait: Duration,
) -> Result<Wire, SdkError> {
    if std::time::Instant::now() >= deadline {
        return Ok(Wire::unknown("deadline"));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("ramflux-wake-io")
        .max_blocking_threads(2)
        .build()?;
    let acquired = runtime.block_on(async {
        tokio::time::timeout_at(Instant::from_std(deadline), async {
            super::session_lease::acquire(
                &config.data_root,
                super::session_lease::SessionLeaseConfig {
                    priority: crate::SessionLeasePriority::Notification,
                    wait: lease_wait,
                },
            )
            .await
        })
        .await
    });
    let lease = match acquired {
        Err(_) => return Ok(Wire::unknown("deadline")),
        Ok(Err(error)) => return classify(error),
        Ok(Ok(lease)) => lease,
    };
    let result = runtime.block_on(async {
        match tokio::time::timeout_at(
            Instant::from_std(deadline),
            Box::pin(fetch(config, account_id, vault)),
        )
        .await
        {
            Err(_) => Ok(Wire::unknown("deadline")),
            Ok(Err(error)) => classify(error),
            Ok(Ok(decision)) => Ok(Wire::fetched(decision)),
        }
    });
    // Join custody's blocking jobs before releasing ownership, including on timeout.
    // Host custody callbacks must return promptly; no runtime can interrupt host code.
    drop(runtime);
    drop(lease);
    result
}

fn classify(error: SdkError) -> Result<Wire, SdkError> {
    match &error {
        SdkError::DataRootInUse => Ok(Wire::unknown("busy")),
        SdkError::Storage(cause) if cause.is_writer_busy() => Ok(Wire::unknown("busy")),
        SdkError::CustodyVault(crate::custody::CustodyVaultReason::Locked) => {
            Ok(Wire::unknown("locked"))
        }
        SdkError::LocalBusRefused { code, .. } if code == "SessionLeaseBusy" => {
            Ok(Wire::unknown("busy"))
        }
        SdkError::LocalBusRefused { code, .. }
            if matches!(code.as_str(), "AccountCodeRequired" | "DeviceUnlockUnavailable") =>
        {
            Ok(Wire::unknown("locked"))
        }
        _ => Err(error),
    }
}

async fn fetch(
    config: &LocalBusConfig,
    account_id: &str,
    vault: Arc<dyn PrimaryVault + Send + Sync>,
) -> Result<notification::Decision, SdkError> {
    vault.preflight()?;
    let mut client = RamfluxClient::new();
    client.open_account_index(&config.data_root)?;
    client.bind_device_unlock(
        &config.data_root,
        vault.as_ref(),
        account_id,
        crate::client::device_unlock::DeviceSecret::Load,
    )?;
    client.unlock_account_with_device(account_id)?;
    if !crate::custody::pairing::recipient::ordinary_session_admitted(&client, account_id)? {
        return Err(SdkError::PairingCode("PublicationPending"));
    }
    let gateway = connection_config(config, &client, vault).await?;
    if super::host_branch::marked_on(&gateway) {
        return Err(SdkError::PairingCode("PublicationPending"));
    }
    let engine = GatewaySessionEngine::connect(gateway).await?;
    let anchor = client
        .born_v3_account
        .as_ref()
        .ok_or(SdkError::CustodySetupInvalid)?
        .record()
        .body
        .account_anchor
        .clone();
    let mut account =
        super::state::LocalBusAccountState::disconnected(client, engine.config.clone(), anchor);
    account.engine = Some(engine);
    // Data unlock clears branch credentials. Receive needs the same current-head
    // refresh and certified branch/prekey installation as the ordinary account writer.
    account.prepare_native_branch().await?;
    let page = receive::run(&mut account).await;
    // TCP/TLS only: dropping a cancelled future closes its sole session socket directly.
    if let Some(engine) = account.engine.take() {
        engine.shutdown_transport().await;
    }
    // Decide only after the whole page is durably applied; a failed page consumes nothing.
    page?;
    notification::decide(&account.client)
}

async fn connection_config(
    config: &LocalBusConfig,
    client: &RamfluxClient,
    vault: Arc<dyn PrimaryVault + Send + Sync>,
) -> Result<GatewaySessionConfig, SdkError> {
    let db = client.account_db()?;
    let native = client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
    let nodes = crate::node::NodeStore::load(&config.data_root, &config.builtin_nodes)?;
    let saved = db.load_actor_state::<String>("account/node-id")?;
    let profile = nodes.selected(saved.as_deref(), false)?.ok_or(SdkError::NoNodeSelected)?;
    let device = native.local_device_id()?.to_owned();
    let target = client.owned_device_identity()?.storage_key().to_owned();
    let gateway = GatewaySessionConfig::tcp_tls(GatewayTcpTlsEndpointConfig {
        bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        gateway_addr: crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?,
        server_name: profile.gateway.server_name.clone(),
        ca_cert: profile.write_ca(&config.data_root)?,
        principal_id: native.record().body.principal_id.clone(),
        device_id: device,
        target_delivery_id: target.clone(),
        prekey_http_url: Some(profile.prekey_http_url.clone()),
    })
    .with_host_network(config)
    .with_native_custody(GatewayCustodyConfig {
        account_root: config.data_root.clone(),
        account_id: db.local_account_id.clone(),
        node_id: profile.node_id,
        node_public_key: profile.node_public_key,
        vault,
    })
    .with_account_identity(client)?;
    // Use the same activation-based cursor as the ordinary authoritative receive path.
    let mut gateway = gateway;
    gateway.last_seen_inbox_seq = super::push_receiver::apply_w1::read_cursor(db, &target)?;
    crate::gateway::apply_session_push_advertise(&mut gateway, db.receive_activation()?);
    Ok(gateway)
}
