// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit fixture API: real account writer and resident host, with only transport injected.

use super::{
    AccountIndex, AccountRuntime, Arc, BTreeMap, BTreeSet, Duration, LocalBusConfig,
    LocalBusDaemonState, RoutingMutex, SdkError, mpsc, uploads, watch,
};
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
    _preempt: watch::Sender<u64>,
    _shutdown: watch::Sender<bool>,
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

pub(super) struct FixtureCapabilities {
    pub incarnation: Option<String>,
    pub ephemeral: bool,
}

impl AccountSessionHarness {
    fn fixture_client(
        index: &AccountIndex,
        mut db: ramflux_storage::AccountDb,
        identity: ramflux_crypto::IdentityRoot,
        config: &GatewaySessionConfig,
        incarnation: Option<&str>,
    ) -> Result<RamfluxClient, SdkError> {
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
        manifest
            .devices
            .first_mut()
            .ok_or(SdkError::IdentityRootMissing)?
            .target_delivery_id
            .clone_from(&config.target_delivery_id);
        client.persist_identity_directory(&manifest)?;
        // The transport begins after authentication; initialize the account-side receive
        // epoch with the same operation used by production install_connection.
        client.first_activate_receive_ledger(&config.target_delivery_id, incarnation)?;
        Ok(client)
    }

    /// Attach an authenticated session transport to the account's actual writer and host.
    /// # Errors
    /// Returns account, configuration, or connection startup errors.
    pub async fn attach(fixture: AccountSessionFixture) -> Result<Self, SdkError> {
        let AccountSessionFixture {
            index,
            db,
            identity,
            config,
            session,
            stream,
            incarnation,
            ephemeral,
        } = fixture;
        let client = Self::fixture_client(&index, db, identity, &config, incarnation.as_deref())?;
        Box::pin(Self::attach_initialized(
            index,
            client,
            config,
            session,
            stream,
            FixtureCapabilities { incarnation, ephemeral },
        ))
        .await
    }

    pub(super) async fn attach_initialized(
        index: AccountIndex,
        client: RamfluxClient,
        config: GatewaySessionConfig,
        session: GatewaySessionState,
        stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
        capabilities: FixtureCapabilities,
    ) -> Result<Self, SdkError> {
        let FixtureCapabilities { incarnation, ephemeral } = capabilities;
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
        Box::pin(Self::start_account(index, account)).await
    }

    pub(super) async fn start_account(
        index: AccountIndex,
        account: super::super::state::LocalBusAccountState,
    ) -> Result<Self, SdkError> {
        let id = account.client.account_db()?.local_account_id.clone();
        let root = index.root().to_path_buf();
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
        let (preempt_owner, preempt) = watch::channel(0);
        let (shutdown_owner, shutdown) = watch::channel(false);
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
            transient: crate::bus::account_runtime::TransientHost::default(),
            pairing: crate::bus::account_runtime::pairing_calls::Calls::default(),
            #[cfg(test)]
            receive_gate_hook: None,
            #[cfg(test)]
            courier_events: None,
        };
        runtime.start_connection()?;
        let mut harness =
            Self { runtime, event_router, _preempt: preempt_owner, _shutdown: shutdown_owner };
        let handle = harness.handle()?;
        harness.drive(handle.require_live(Duration::from_secs(10))).await.map_err(|error| {
            SdkError::GatewaySessionRejected(format!("fixture live admission: {error:?}"))
        })?;
        harness
            .drive(async {
                tokio::time::timeout(Duration::from_secs(10), async {
                    while handle.catch_ups_total() == 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(|_| {
                    SdkError::GatewaySessionRejected("fixture initial catch-up deadline".into())
                })
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
                Some(work) = self.runtime.connection_work.recv() => Box::pin(self.runtime.apply_connection_work(work)).await?,
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

    /// Stage two independently owned calls; delivery uses the ordinary background courier.
    /// # Errors
    /// Refuses invalid native peer authority or account state.
    pub fn stage_calls(&mut self, manifest: serde_json::Value) -> Result<Vec<String>, SdkError> {
        let manifest: crate::SdkDeviceManifestResponse = serde_json::from_value(manifest)?;
        let account = self
            .runtime
            .state
            .accounts
            .get_mut(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        account.client.persist_fetched_identity_directory(&manifest)?;
        account.client.establish_friend_link(
            "calls-fixture",
            &account.principal_commitment,
            &manifest.principal_commitment,
        )?;
        let device = manifest.devices.first().ok_or(SdkError::IdentityRootMissing)?;
        let peer = ramflux_protocol::CallEndpoint {
            principal_id: manifest.principal_id.clone(),
            device_id: device.device_id.clone(),
            root_public_key: manifest.root_public_key.clone(),
        };
        let mut ids = Vec::new();
        for seed in [91u8, 92] {
            let id = ramflux_protocol::encode_base64url([seed; 16]);
            let thread = format!("call-thread-{seed}");
            account.client.account_db()?.persist_client_record("conversation",&thread,&serde_json::json!({"kind":"direct","group_id":null,"participants":[account.gateway_config.principal_id,manifest.principal_id]}))?;
            let mut call = crate::client::call::state::LiveCall::outgoing(
                id.clone(),
                thread,
                account.client.call_local_endpoint()?,
                vec![peer.clone()],
                crate::time::now_unix_timestamp(),
            )?;
            call.pin_peer(peer.clone(), device.branch_public_key.clone())?;
            account.client.persist_call_row(&call.row)?;
            account.client.voice_calls.insert(id.clone(), call);
            ids.push(id);
        }
        self.handle()?.wake_couriers();
        Ok(ids)
    }

    /// Request an owner action on the actual `LiveCall`, delivered by its production courier.
    /// # Errors
    /// Refuses absent calls or state-machine-invalid owner actions.
    pub fn call_action(&mut self, id: &str, action: &str) -> Result<(), SdkError> {
        let account = self
            .runtime
            .state
            .accounts
            .get_mut(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        let call = account.client.voice_calls.get_mut(id).ok_or(SdkError::NetworkingPending)?;
        let now = crate::time::now_unix_timestamp();
        match action {
            "answer" => call.answer(now)?,
            "reject" => call.end(true, now)?,
            "busy" => call.busy(now)?,
            "failed" => {
                call.fail(ramflux_protocol::VoiceCallFailureReason::RelayUnavailable, now)?;
            }
            "end" => call.end(false, now)?,
            _ => return Err(SdkError::NetworkingPending),
        }
        let row = call.row.clone();
        account.client.persist_call_row(&row)?;
        self.handle()?.wake_couriers();
        Ok(())
    }

    /// Observe an incoming call installed by the actual receive writer.
    /// # Errors
    /// Refuses a disconnected writer or the bounded receive deadline.
    pub async fn wait_call_present(&mut self, id: &str) -> Result<(), SdkError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if self
                .runtime
                .state
                .accounts
                .get(&self.runtime.id)
                .is_some_and(|account| account.client.voice_calls.contains_key(id))
            {
                return Ok(());
            }
            let work = tokio::time::timeout_at(deadline, self.runtime.connection_work.recv())
                .await
                .map_err(|_| SdkError::NetworkingPending)?
                .ok_or(SdkError::GatewaySessionNotEstablished)?;
            Box::pin(self.runtime.apply_connection_work(work)).await?;
        }
    }

    /// Snapshot media permission on the actual writer-owned calls.
    /// # Errors
    /// Refuses missing account or call state.
    pub fn call_media(&self, id: &str) -> Result<bool, SdkError> {
        let call = self
            .runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .and_then(|account| account.client.voice_calls.get(id))
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(!call.media_held && call.row.state != "ended")
    }

    /// Last production courier error; this observer never changes call permission.
    #[must_use]
    pub fn call_error(&self, id: &str) -> Option<&str> {
        self.runtime
            .state
            .accounts
            .get(&self.runtime.id)
            .and_then(|account| account.client.voice_calls.get(id))
            .and_then(|call| call.last_control_error.as_deref())
    }

    /// Pump the real writer until a bounded test observer sees the expected call permission.
    /// # Errors
    /// Refuses a disconnected writer or a ten-second observation deadline.
    pub async fn wait_call_media(&mut self, id: &str, expected: bool) -> Result<(), SdkError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if self.call_media(id)? == expected {
                return Ok(());
            }
            let work = tokio::time::timeout_at(deadline, self.runtime.connection_work.recv())
                .await
                .map_err(|_| SdkError::NetworkingPending)?
                .ok_or(SdkError::GatewaySessionNotEstablished)?;
            Box::pin(self.runtime.apply_connection_work(work)).await?;
        }
    }

    /// Await a completed production courier attempt, including a held/refused decision.
    /// # Errors
    /// Missing calls, writer failures and the fifteen-second observation deadline refuse.
    pub async fn wait_call_attempt(&mut self, id: &str) -> Result<(), SdkError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let call = self
                .runtime
                .state
                .accounts
                .get(&self.runtime.id)
                .and_then(|account| account.client.voice_calls.get(id))
                .ok_or(SdkError::AccountDbNotUnlocked)?;
            if call.pending.is_empty() || call.retry_attempts > 0 {
                return Ok(());
            }
            let work = tokio::time::timeout_at(deadline, self.runtime.connection_work.recv())
                .await
                .map_err(|_| SdkError::NetworkingPending)?
                .ok_or(SdkError::GatewaySessionNotEstablished)?;
            Box::pin(self.runtime.apply_connection_work(work)).await?;
        }
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
        manifest
            .devices
            .first_mut()
            .ok_or(SdkError::IdentityRootMissing)?
            .target_delivery_id
            .clone_from(&account.target_delivery_id);
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
            ttl: account.client.content_ttl()?,
        };
        Box::pin(account.client.send_plaintext_direct_message_via_gateway(
            &mut session,
            message,
            b"durable control before transient baseline",
        ))
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
            Box::pin(self.runtime.apply_connection_work(work)).await?;
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

#[path = "testing_pairing.rs"]
mod pairing;
pub use pairing::{NativePairingNetworkFixture, NativePairingSessionFixture};
