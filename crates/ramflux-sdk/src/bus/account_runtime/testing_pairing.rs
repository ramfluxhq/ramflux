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
impl AccountSessionHarness {
    /// Attach the enrolled device's actual writer to the production resident host.
    /// # Errors
    /// Refuses uninstalled authority, a foreign node/directory or a mismatched branch.
    pub async fn attach_pairing(fixture: NativePairingSessionFixture) -> Result<Self, SdkError> {
        let NativePairingSessionFixture { mut client, config, session, stream, node } = fixture;
        let index = client.account_index()?.clone();
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
        // Session transport is supplied after real authentication. Preserve the exact
        // originating branch used by that session, never a legacy root fixture key.
        let mut config = config.with_account_identity(&client)?;
        config.device_branch = Some(std::sync::Arc::new(branch.clone()));
        config.source_identity = Some(identity);
        client.node_relay_options =
            Some(node.relay_options(index.root(), &config.principal_id).await?);
        client.first_activate_receive_ledger(&config.target_delivery_id, None)?;
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

    /// Run the durable post-enrollment history attempt through its production owner.
    /// # Errors
    /// Returns the ordinary account runtime's storage or session error.
    pub async fn pairing_history_attempt(&mut self) -> Result<bool, SdkError> {
        Box::pin(self.runtime.service_pairing_own_sync()).await
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
