// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit fixture API: real account writer and resident host, with only transport injected.

use super::*;
use crate::bus::connection_manager::{ConnectionHandle, SessionClient};
use crate::{
    EphemeralConsumer, EphemeralSendOutcome, GatewaySessionAccess, GatewaySessionConfig,
    GatewaySessionEngine, GatewaySessionState, RamfluxClient,
};

/// An account runtime for real-component tests. Every writer message uses the production arm.
/// The account database is owned by this runtime, never by a disconnected test observer.
pub struct AccountSessionHarness {
    runtime: AccountRuntime,
    event_router: tokio::task::JoinHandle<()>,
}

/// Explicit authenticated coordinates supplied by a real-component fixture.
pub struct AccountSessionFixture {
    pub index: AccountIndex,
    pub db: ramflux_storage::AccountDb,
    pub identity: ramflux_crypto::IdentityRoot,
    pub config: GatewaySessionConfig,
    pub session: GatewaySessionState,
    pub stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
    pub incarnation: Option<String>,
    pub ephemeral: bool,
}

impl AccountSessionHarness {
    /// Attach an authenticated session transport to the account's actual writer and host.
    /// # Errors
    /// Returns account, configuration, or connection startup errors.
    pub async fn attach(fixture: AccountSessionFixture) -> Result<Self, SdkError> {
        let AccountSessionFixture {
            index,
            mut db,
            identity,
            config,
            session,
            stream,
            incarnation,
            ephemeral,
        } = fixture;
        let id = db.local_account_id.clone();
        let root = index.root().to_path_buf();
        let mut client = RamfluxClient::new();
        client.identity_root = Some(identity);
        client.device_branch = config.device_branch.as_ref().map(|branch| (**branch).clone());
        if let Some(branch) = &client.device_branch {
            db.set_device_signer(branch.clone());
        }
        client.account_index = Some(index.clone());
        client.active_account_db = Some(db);
        let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let device = branch.device_id.clone();
        let seed = branch.signing_key.to_bytes();
        client.initialize_and_publish_prekey_bundle(
            &client.surface_local_root_commitment()?,
            &device,
            &config.target_delivery_id,
            seed,
            None,
        )?;
        let mut manifest = super::testing_authority::manifest(&client)?;
        manifest.devices[0].target_delivery_id.clone_from(&config.target_delivery_id);
        client.persist_identity_directory(&manifest)?;
        // The transport begins after authentication; initialize the account-side receive
        // epoch with the same operation used by production install_connection.
        client.first_activate_receive_ledger(&config.target_delivery_id, incarnation.as_deref())?;
        let principal = client.surface_local_root_commitment()?;
        let mut engine = GatewaySessionEngine::with_test_transport(config.clone(), stream);
        engine.session = session;
        engine.ephemeral_negotiated = ephemeral;
        engine.mode = match incarnation.as_deref() {
            Some(value) => crate::gateway::session_push::SessionMode::Push {
                incarnation: crate::gateway::session_push::IncarnationId::try_from(
                    value.to_owned(),
                )
                .map_err(|_| SdkError::GatewaySessionNotEstablished)?,
            },
            None => crate::gateway::session_push::SessionMode::Compat,
        };
        let mut account =
            super::super::state::LocalBusAccountState::disconnected(client, config, principal);
        account.engine = Some(engine);
        account.timeouts.receive_min = Duration::from_secs(600);
        account.timeouts.receive_max = Duration::from_secs(600);
        account.timeouts.keepalive_idle = Duration::from_secs(600);
        let timeouts = account.timeouts.clone();
        let state = LocalBusDaemonState {
            account_index: Some(index),
            config: LocalBusConfig::new(root.join("fixture.sock"), &root),
            nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::from([(id.clone(), account)]),
            active_account_id: Some(id.clone()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        };
        let (_, receiver) = mpsc::channel(2);
        let (_, lifecycle) = mpsc::channel(2);
        let (_, preempt) = watch::channel(0);
        let (_, shutdown) = watch::channel(false);
        let (events, mut batches) = mpsc::channel::<super::super::events::EventBatch>(2);
        let event_router = tokio::spawn(async move {
            let mut subscribers = BTreeMap::new();
            while let Some(batch) = batches.recv().await {
                super::super::events::broadcast(&mut subscribers, &batch.events);
                let _ = batch.accepted.send(());
            }
        });
        let (connection_sender, connection_work) = mpsc::channel(2);
        let mut runtime = AccountRuntime {
            timeouts,
            id,
            state,
            receiver,
            lifecycle,
            preempt,
            readers: Arc::new(RoutingMutex::new(None)),
            events,
            shutdown,
            courier: None,
            networking_expiry_pending: None,
            networking_expiry_warned: false,
            networking_observation_warned: false,
            transfers: uploads::Transfers::start(),
            connection_sender,
            connection_work,
            ledger: None,
            #[cfg(test)]
            receive_gate_hook: None,
            #[cfg(test)]
            courier_events: None,
        };
        runtime.start_connection()?;
        let mut harness = Self { runtime, event_router };
        let handle = harness.handle()?;
        harness.drive(handle.require_live(Duration::from_secs(60))).await?;
        harness
            .drive(async {
                while handle.catch_ups_total() == 0 {
                    tokio::task::yield_now().await;
                }
                Ok(())
            })
            .await?;
        Ok(harness)
    }

    fn handle(&self) -> Result<ConnectionHandle, SdkError> {
        self.runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .and_then(|account| account.connection.clone())
            .ok_or(SdkError::GatewaySessionNotEstablished)
    }

    async fn drive<T>(
        &mut self,
        future: impl std::future::Future<Output = Result<T, SdkError>>,
    ) -> Result<T, SdkError> {
        let mut future = Box::pin(future);
        loop {
            tokio::select! {
                result = &mut future => return result.map_err(|error| SdkError::GatewaySessionRejected(format!("account fixture exchange: {error:?}"))),
                Some(work) = self.runtime.connection_work.recv() => self.runtime.apply_connection_work(work).await?,
            }
        }
    }

    fn session(&self) -> Result<SessionClient, SdkError> {
        let handle = self.handle()?;
        let metadata = handle.metadata().ok_or(SdkError::GatewaySessionNotEstablished)?;
        Ok(SessionClient::new(
            handle,
            metadata,
            tokio::time::Instant::now() + Duration::from_secs(60),
        ))
    }

    /// Submit through the generation-fenced production account session client.
    /// # Errors
    /// Returns the exact session or transport failure.
    pub async fn submit(
        &mut self,
        envelope: ramflux_protocol::Envelope,
    ) -> Result<EphemeralSendOutcome, SdkError> {
        let mut client = self.session()?;
        self.drive(client.submit_ephemeral(envelope)).await
    }

    /// Export the authenticated fixture account's public directory.
    /// # Errors
    /// Returns directory construction or serialization errors.
    pub fn public_manifest(&self) -> Result<serde_json::Value, SdkError> {
        let account = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        let mut manifest = super::testing_authority::manifest(&account.client)?;
        manifest.devices[0].target_delivery_id.clone_from(&account.target_delivery_id);
        Ok(serde_json::to_value(manifest)?)
    }

    /// Install a root-verified peer and the fixture's explicit friend consent before measurement.
    /// # Errors
    /// Returns authority or storage errors.
    pub fn trust_peer(
        &mut self,
        manifest: serde_json::Value,
        expected_root: &str,
    ) -> Result<(), SdkError> {
        RamfluxClient::verify_device_manifest_json(manifest.clone(), expected_root)?;
        let manifest = serde_json::from_value(manifest)?;
        let account = self
            .runtime
            .state
            .accounts
            .get_mut(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        account.client.persist_identity_directory(&manifest)?;
        account.client.account_db()?.establish_friend_link(
            "fixture-peer",
            &account.principal_commitment,
            expected_root,
        )?;
        let device = manifest.devices.first().ok_or(SdkError::IdentityRootMissing)?;
        let remote = ramflux_crypto::RootQualifiedDeviceRef::from_signed_device_set(
            &ramflux_crypto::verifying_key_from_base64url(&manifest.root_public_key)?,
            manifest.signed_device_set.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &device.device_id,
        )?;
        let local = account.client.owned_device_identity()?;
        let local_hash = crate::dm::dm_device_id_hash(local.device_id());
        let remote_hash = crate::dm::dm_device_id_hash(remote.device_id());
        let pair = if account.gateway_config.principal_id == "agent" {
            ramflux_crypto::DmSession::initiator([17; 32], local_hash, remote_hash, [3; 32])?
        } else {
            ramflux_crypto::DmSession::recipient([17; 32], local_hash, remote_hash, [3; 32])?
        };
        account.client.persist_pair(&local, &remote, &[4; 32], &pair)?;
        Ok(())
    }

    /// Send a supported durable DM through the ordinary SDK encryption and session APIs.
    /// # Errors
    /// Returns encryption, projection or real session errors.
    pub async fn durable_message(
        &mut self,
        peer_root: &str,
        peer_device: &str,
        target: &str,
    ) -> Result<crate::GatewayInboxEntry, SdkError> {
        let mut session = self.session()?;
        let account = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        let message = crate::GatewayDirectMessage {
            conversation_id: "transport-control".into(),
            message_id: "durable-control".into(),
            envelope_id: "account-durable-control".into(),
            source_principal_id: account.gateway_config.principal_id.clone(),
            sender_id: account.gateway_config.device_id.clone(),
            recipient_device_id: Some(peer_device.into()),
            recipient_principal_commitment: Some(peer_root.into()),
            target_delivery_id: target.into(),
            encrypted_body: Vec::new(),
            created_at: crate::prelude::now_unix_timestamp(),
            ttl: 300,
        };
        account
            .client
            .send_plaintext_direct_message_via_gateway(
                &mut session,
                message,
                b"durable control before transient baseline",
            )
            .await
    }

    /// Service the real account writer while a test awaits an external semantic barrier.
    /// # Errors
    /// Returns the external barrier or account-writer failure.
    pub async fn service_while<T>(
        &mut self,
        future: impl std::future::Future<Output = Result<T, SdkError>>,
    ) -> Result<T, SdkError> {
        self.drive(future).await
    }

    /// Obtain the production generation-owned consumer.
    /// # Errors
    /// Returns the exact session or transport failure.
    pub async fn consumer(&mut self) -> Result<Option<EphemeralConsumer>, SdkError> {
        let mut client = self.session()?;
        self.drive(client.take_ephemeral_consumer()).await
    }

    /// Exercise this live gateway transport after a router restart, before measurement.
    /// # Errors
    /// Returns the actual session or router failure.
    pub async fn warm_transport(&mut self) -> Result<(), SdkError> {
        let mut client = self.session()?;
        self.drive(client.cursor()).await?;
        Ok(())
    }

    /// Pump the account writer while waiting for authenticated ciphertext handoff.
    /// # Errors
    /// Returns account writer errors.
    pub async fn next(
        &mut self,
        consumer: &mut EphemeralConsumer,
        resolve: impl FnMut(&ramflux_protocol::Envelope) -> Option<crate::EphemeralSource>,
    ) -> Result<Option<(Vec<u8>, u64)>, SdkError> {
        self.drive(async { Ok(consumer.next(resolve).await) }).await
    }

    /// Snapshot the actual owned account's durable journal/outbox/actor state.
    /// # Errors
    /// Returns storage failures.
    pub fn snapshot(&self) -> Result<String, SdkError> {
        let db = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?
            .client
            .account_db()?;
        Ok(format!(
            "{:?}|{:?}|{:?}|{:?}",
            db.journal_bounds()?,
            db.journal_after(0, 128)?,
            db.pending_outbox(256)?,
            db.list_actor_states::<serde_json::Value>("")?
        ))
    }

    /// Wait for the actual receive writer to settle a durable control and apply its ACK result.
    /// # Errors
    /// Returns account-writer or database failures.
    pub async fn settled(&mut self, target: &str, sequence: u64) -> Result<(), SdkError> {
        loop {
            let db = self
                .runtime
                .state
                .accounts
                .get(&self.runtime.id)
                .ok_or(SdkError::AccountDbNotUnlocked)?
                .client
                .account_db()?;
            if db.receive_startup(target)?.1 >= sequence
                && db.receive_status_counters(target)?.ack_intents_pending == 0
            {
                return Ok(());
            }
            let work = self
                .runtime
                .connection_work
                .recv()
                .await
                .ok_or(SdkError::GatewaySessionNotEstablished)?;
            self.runtime.apply_connection_work(work).await?;
        }
    }

    /// Inspect the connected account's receive observation for a named failure.
    /// # Errors
    /// Returns session observation serialization failures.
    pub fn diagnostics(&self) -> Result<serde_json::Value, SdkError> {
        let account = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(
            serde_json::json!({"connection":self.handle()?.snapshot(), "ledger":format!("{:?}", account.client.account_db()?.receive_status_counters(&account.target_delivery_id)?), "journal":format!("{:?}",account.client.account_db()?.journal_bounds()?), "startup":account.client.account_db()?.receive_startup(&account.target_delivery_id)?}),
        )
    }

    /// Stop all account-owned session work before ordinary database reopen.
    pub async fn stop(&mut self) {
        self.runtime.stop_connection().await;
        self.runtime.ledger = None;
        self.runtime.transfers.stop().await;
        self.event_router.abort();
        let _ = (&mut self.event_router).await;
    }
}

impl Drop for AccountSessionHarness {
    fn drop(&mut self) {
        if let Ok(handle) = self.handle() {
            handle.signal_stop();
        }
        self.event_router.abort();
    }
}
