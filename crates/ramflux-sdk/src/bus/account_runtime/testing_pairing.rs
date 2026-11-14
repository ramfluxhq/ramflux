// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrolled native owners exercise the ordinary history writer and authenticated transport.
use super::{AccountSessionHarness, FixtureCapabilities};
use crate::{GatewaySessionConfig, GatewaySessionState, NodeProfile, RamfluxClient, SdkError};

/// Already initialized independent SDK owner and its authenticated node session.
/// No private account, branch or prekey is created or copied by this adapter.
pub struct NativePairingSessionFixture {
    pub client: RamfluxClient,
    pub config: GatewaySessionConfig,
    pub session: GatewaySessionState,
    pub stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
    pub node: NodeProfile,
}
/// Native pairing account whose production session host opens the configured network.
/// There is no injected transport or invented authenticated session state.
pub struct NativePairingNetworkFixture {
    pub client: RamfluxClient,
    pub config: GatewaySessionConfig,
    pub node: NodeProfile,
}
impl AccountSessionHarness {
    /// Attach the enrolled device's actual writer to the production resident host.
    /// # Errors
    /// Refuses uninstalled authority, a foreign node/directory or a mismatched branch.
    pub async fn attach_pairing(fixture: NativePairingSessionFixture) -> Result<Self, SdkError> {
        let NativePairingSessionFixture { client, config, session, stream, node } = fixture;
        let (client, mut config) = Self::pairing_owner(client, config, &node).await?;
        let index = client.account_index()?.clone();
        let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        config.device_branch = Some(std::sync::Arc::new(branch.clone()));
        config.source_identity = Some(client.owned_device_identity()?);
        Box::pin(Self::attach_initialized(
            index,
            client,
            config,
            session,
            stream,
            FixtureCapabilities { incarnation: None, ephemeral: false },
        ))
        .await
    }

    /// Open the ordinary native network host for an enrolled independently owned client.
    /// # Errors
    /// Returns native admission, configured-node, connection or initial receive failures.
    pub async fn connect_pairing(fixture: NativePairingNetworkFixture) -> Result<Self, SdkError> {
        let NativePairingNetworkFixture { client, config, node } = fixture;
        let (client, config) = Self::pairing_owner(client, config, &node).await?;
        let index = client.account_index()?.clone();
        let principal = client.surface_local_root_commitment()?;
        let account = super::super::super::state::LocalBusAccountState::disconnected(
            client, config, principal,
        );
        Box::pin(Self::start_account(index, account)).await
    }

    async fn pairing_owner(
        mut client: RamfluxClient,
        config: GatewaySessionConfig,
        node: &NodeProfile,
    ) -> Result<(RamfluxClient, GatewaySessionConfig), SdkError> {
        let id = client.account_db()?.local_account_id.clone();
        if client.born_v3_account.is_none()
            || !crate::custody::pairing::ordinary_session_admitted(&client, &id)?
            || config.prekey_http_url.as_deref() != Some(node.prekey_http_url.as_str())
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let custody = config.custody.as_ref().ok_or(SdkError::NetworkingPending)?;
        if custody.node_id != node.node_id || custody.node_public_key != node.node_public_key {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let identity = client.owned_device_identity()?;
        let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if config.device_id != identity.device_id()
            || config.device_epoch != branch.device_epoch
            || config.target_delivery_id != identity.storage_key()
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let config = config.with_account_identity(&client)?;
        client.node_relay_options =
            Some(node.relay_options(client.account_index()?.root(), &config.principal_id).await?);
        client.first_activate_receive_ledger(&config.target_delivery_id, None)?;
        Ok((client, config))
    }

    /// Run the durable post-enrollment history attempt through its production owner.
    /// # Errors
    /// Returns the ordinary account runtime's storage or session error.
    pub async fn pairing_history_attempt(&mut self) -> Result<bool, SdkError> {
        Box::pin(self.runtime.service_pairing_own_sync()).await
    }

    /// Inspect only message presence in this fixture's independently owned account.
    /// # Errors
    /// Returns the actual writer's storage or account error.
    pub fn has_pairing_history(&self, message: &str) -> Result<bool, SdkError> {
        let account = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(account.client.account_db()?.message_content(message)?.is_some())
    }

    /// Service actual writer requests until an imported known message becomes readable.
    /// The surrounding real-component test supplies its existing bounded deadline.
    /// # Errors
    /// Refuses a different plaintext or a closed account/session writer.
    pub async fn wait_pairing_history(
        &mut self,
        message: &str,
        expected: &[u8],
    ) -> Result<(), SdkError> {
        const MAX_WRITER_STEPS: usize = 128;
        for _ in 0..MAX_WRITER_STEPS {
            let account = self
                .runtime
                .state
                .accounts
                .get(&self.runtime.id)
                .ok_or(SdkError::AccountDbNotUnlocked)?;
            if let Some(body) = account.client.account_db()?.message_content(message)? {
                let body = zeroize::Zeroizing::new(body);
                return if body.as_slice() == expected {
                    Ok(())
                } else {
                    Err(SdkError::InboundRejected("paired history plaintext mismatch".into()))
                };
            }
            let work = self
                .runtime
                .connection_work
                .recv()
                .await
                .ok_or(SdkError::GatewaySessionNotEstablished)?;
            Box::pin(self.runtime.apply_connection_work(work)).await?;
        }
        Err(SdkError::PairingCode("TransferCapacity"))
    }
}

#[path = "testing_pairing_media.rs"]
mod media;
