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

mod receive;

#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum Outcome {
    Fetched { items: Vec<FetchedItem> },
    Busy,
    Locked,
    Deadline,
}

/// Identifies fetched entries; ordinary receive policy determines projection or durable hold.
#[derive(Serialize)]
pub(crate) struct FetchedItem {
    envelope_id: String,
    inbox_seq: String,
}

pub(crate) fn run(
    config: &LocalBusConfig,
    account_id: &str,
    vault: Arc<dyn PrimaryVault + Send + Sync>,
    deadline: std::time::Instant,
    lease_wait: Duration,
) -> Result<Outcome, SdkError> {
    if std::time::Instant::now() >= deadline {
        return Ok(Outcome::Deadline);
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
        Err(_) => return Ok(Outcome::Deadline),
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
            Err(_) => Ok(Outcome::Deadline),
            Ok(Err(error)) => classify(error),
            Ok(Ok(items)) => Ok(Outcome::Fetched { items }),
        }
    });
    // Join custody's blocking jobs before releasing ownership, including on timeout.
    // Host custody callbacks must return promptly; no runtime can interrupt host code.
    drop(runtime);
    drop(lease);
    result
}

fn classify(error: SdkError) -> Result<Outcome, SdkError> {
    match &error {
        SdkError::DataRootInUse => Ok(Outcome::Busy),
        SdkError::Storage(cause) if cause.is_writer_busy() => Ok(Outcome::Busy),
        SdkError::CustodyVault(crate::custody::CustodyVaultReason::Locked) => Ok(Outcome::Locked),
        SdkError::LocalBusRefused { code, .. } if code == "SessionLeaseBusy" => Ok(Outcome::Busy),
        SdkError::LocalBusRefused { code, .. }
            if matches!(code.as_str(), "AccountCodeRequired" | "DeviceUnlockUnavailable") =>
        {
            Ok(Outcome::Locked)
        }
        _ => Err(error),
    }
}

async fn fetch(
    config: &LocalBusConfig,
    account_id: &str,
    vault: Arc<dyn PrimaryVault + Send + Sync>,
) -> Result<Vec<FetchedItem>, SdkError> {
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
    let page = receive::run(&mut account).await;
    // TCP/TLS only: dropping a cancelled future closes its sole session socket directly.
    if let Some(engine) = account.engine.take() {
        engine.shutdown_transport().await;
    }
    let page = page?;
    Ok(page
        .into_iter()
        .map(|entry| FetchedItem {
            envelope_id: entry.envelope.envelope_id,
            inbox_seq: entry.inbox_seq.to_string(),
        })
        .collect())
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
