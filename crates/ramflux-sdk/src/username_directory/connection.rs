// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One account-owned live transport, never a response or authority cache.
use crate::{
    SdkError,
    custody::{CustodyConnection, CustodyNetworkConfig, PrimaryVault},
};
use ramflux_protocol::custody::BindingMode;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Clone, PartialEq, Eq)]
struct Key {
    root: PathBuf,
    account: String,
    device: String,
    endpoint: std::net::SocketAddr,
    server: String,
    ca: PathBuf,
    node: String,
    public: String,
    audience: String,
    binding: BindingMode,
    unbound: bool,
    timeout: std::time::Duration,
}
impl From<&CustodyNetworkConfig> for Key {
    fn from(config: &CustodyNetworkConfig) -> Self {
        Self {
            root: config.account_root.clone(),
            account: config.account_id.clone(),
            device: config.device_id.clone(),
            endpoint: config.gateway_address,
            server: config.server_name.clone(),
            ca: config.ca_certificate.clone(),
            node: config.node_id.clone(),
            public: config.node_public_key.clone(),
            audience: config.audience.clone(),
            binding: config.binding_mode,
            unbound: config.allow_no_channel_binding,
            timeout: config.timeout,
        }
    }
}
struct Live {
    key: Key,
    connection: CustodyConnection,
}
#[derive(Clone, Default)]
pub(crate) struct UsernameConnection(Arc<Mutex<Option<Live>>>);
impl UsernameConnection {
    pub(crate) fn clear(&self) {
        if let Ok(mut live) = self.0.lock() {
            live.take();
        }
    }

    pub(crate) async fn open(
        &self,
        config: CustodyNetworkConfig,
        vault: Arc<dyn PrimaryVault>,
    ) -> Result<CustodyConnection, SdkError> {
        // Take ownership before any await. Cancellation or any failed request closes this
        // stream instead of leaving a partially consumed frame for a later command.
        let saved = self.0.lock().map_err(|_| unavailable())?.take();
        if let Some(saved) = saved
            && saved.key == Key::from(&config)
            && saved.connection.session().is_some_and(|session| {
                crate::custody::network_now().is_ok_and(|now| {
                    now.checked_add(30).is_some_and(|end| end < session.expires_at)
                })
            })
        {
            let local = current_record(config.clone(), Arc::clone(&vault)).await?;
            if saved.connection.account().record() == &local {
                tracing::debug!("username native transport reused");
                return Ok(saved.connection);
            }
        }
        tracing::debug!("username native transport opening");
        CustodyConnection::connect(config, vault).await
    }

    pub(crate) fn retain(
        &self,
        config: &CustodyNetworkConfig,
        connection: CustodyConnection,
    ) -> Result<(), SdkError> {
        let mut slot = self.0.lock().map_err(|_| unavailable())?;
        if slot.is_some() {
            return Err(unavailable());
        }
        *slot = Some(Live { key: Key::from(config), connection });
        Ok(())
    }
}
fn unavailable() -> SdkError {
    ramflux_protocol::username_directory::DirectoryCode::DirectoryUnavailable.into()
}
async fn current_record(
    config: CustodyNetworkConfig,
    vault: Arc<dyn PrimaryVault>,
) -> Result<ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>, SdkError> {
    tokio::task::spawn_blocking(move || {
        let now = crate::custody::network_now()?;
        let mut account =
            crate::custody::load_account(&config.account_root, &config.account_id, now)?;
        crate::custody::pairing::admission::require_network_admission(
            &config,
            &account,
            vault.as_ref(),
            now,
        )?;
        account.bind_capacity_node(
            &config.account_root,
            &config.node_id,
            &config.node_public_key,
            now,
        )?;
        // Recheck actual current branch credentials and persisted capacity on every reuse.
        account.credentials(vault.as_ref(), &config.device_id, now)?;
        account.check_capacity_deadline(now)?;
        Ok(account.record().clone())
    })
    .await
    .map_err(|_| unavailable())?
}
