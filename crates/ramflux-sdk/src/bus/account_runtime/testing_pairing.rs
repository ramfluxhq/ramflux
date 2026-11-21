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

    /// Inspect only message presence in this fixture's independently owned account, through the
    /// generation-1 read model.
    /// # Errors
    /// Returns the actual writer's storage or account error.
    pub fn has_pairing_history(&self, conversation: &str, message: &str) -> Result<bool, SdkError> {
        let account = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(account.client.generated_message_detail(conversation, message).is_ok())
    }

    /// Service the actual writers of this device and its source until an imported message is
    /// readable through the generation-1 read model with the expected text. The history courier
    /// of the source runs on the source's own writer, so both are serviced.
    /// The surrounding real-component test supplies its existing bounded deadline.
    /// # Errors
    /// Refuses a different text or a closed account/session writer.
    pub async fn wait_pairing_history(
        &mut self,
        source: &mut Self,
        conversation: &str,
        message: &str,
        expected: &str,
    ) -> Result<(), SdkError> {
        const MAX_WRITER_STEPS: usize = 4096;
        for _ in 0..MAX_WRITER_STEPS {
            let account = self
                .runtime
                .state
                .accounts
                .get(&self.runtime.id)
                .ok_or(SdkError::AccountDbNotUnlocked)?;
            if let Ok(view) = account.client.generated_message_detail(conversation, message) {
                return if view.message.text.as_deref() == Some(expected) {
                    Ok(())
                } else {
                    Err(SdkError::InboundRejected("paired history text mismatch".into()))
                };
            }
            // The enrollment history job re-checks its durable transfer on every pass.
            Box::pin(source.runtime.service_pairing_own_sync()).await?;
            // Either writer may have work; a bounded wait on each keeps both advancing.
            if let Ok(Some(work)) = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                source.runtime.connection_work.recv(),
            )
            .await
            {
                Box::pin(source.runtime.apply_connection_work(work)).await?;
            }
            if let Ok(work) = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                self.runtime.connection_work.recv(),
            )
            .await
            {
                let work = work.ok_or(SdkError::GatewaySessionNotEstablished)?;
                Box::pin(self.runtime.apply_connection_work(work)).await?;
            }
        }
        Err(SdkError::PairingCode("TransferCapacity"))
    }

    /// Counts of own-authored captures, reserved deliveries and sealed deliveries held by this
    /// account, for failure evidence of the authored-history courier.
    /// # Errors
    /// Returns the actual writer's storage or account error.
    pub fn pairing_authored_history_counts(&self) -> Result<(usize, usize, usize), SdkError> {
        let account = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        let db = account.client.account_db()?;
        Ok((
            db.actor_state_keys("own-history/capture/")?.len(),
            db.actor_state_keys("own-history/pending/")?.len(),
            db.actor_state_keys("own-history/staged/")?.len(),
        ))
    }

    /// Whether the account's job ledger still holds an unfinished enrollment history attempt.
    /// # Errors
    /// Returns the actual writer's storage or account error.
    pub fn pairing_history_pending(&self) -> Result<bool, SdkError> {
        let account = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(account.client.account_db()?.next_pairing_own_sync()?.is_some())
    }

    /// Service this writer and run the enrollment history job until the job is finished, which
    /// happens only after the gateway durably accepted every history page.
    /// # Errors
    /// Refuses a job that does not finish within the bounded number of passes.
    pub async fn settle_pairing_history(&mut self) -> Result<(), SdkError> {
        const MAX_PASSES: usize = 256;
        for _ in 0..MAX_PASSES {
            Box::pin(self.runtime.service_pairing_own_sync()).await?;
            if !self.pairing_history_pending()? {
                return Ok(());
            }
            if let Ok(Some(work)) = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                self.runtime.connection_work.recv(),
            )
            .await
            {
                Box::pin(self.runtime.apply_connection_work(work)).await?;
            }
        }
        Err(SdkError::PairingCode("TransferCapacity"))
    }

    /// Pair-session records held by this device (never their secrets).
    /// # Errors
    /// Returns the actual writer's storage or account error.
    pub fn pairing_pair_sessions(&self) -> Result<Vec<String>, SdkError> {
        let account = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(account.client.account_db()?.actor_state_keys("dm-pair/")?)
    }
}
