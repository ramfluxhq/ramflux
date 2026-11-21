// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native encrypted Message delivery and the ordinary bus dispatcher for consumer tests.
use super::testing_calls::NativeCallAccount;
use crate::bus::state::{LocalBusAccountState, LocalBusConnectionState, LocalBusDaemonState};
use crate::client::routed::{Route, SendMaterial};
use crate::{
    GatewayDirectMessage, GatewaySessionConfig, LocalBusConfig, LocalBusFrame, LocalBusFrameKind,
    RamfluxClient, SdkError,
};
use ramflux_protocol::message as g;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
};

/// Owns the actual unlocked account and dispatches the production local-bus read methods.
pub struct NativeMessageBus {
    state: LocalBusDaemonState,
    connection: LocalBusConnectionState,
}

impl NativeCallAccount {
    /// Send generated public content through real native sealing and durable receive.
    /// # Errors
    /// Propagates ordinary content validation, authority, crypto, and store failures.
    pub async fn deliver_message(
        &self,
        target: &mut Self,
        content: &g::Message,
    ) -> Result<(String, String), SdkError> {
        let manifest: crate::SdkDeviceManifestResponse =
            serde_json::from_value(target.manifest.clone())?;
        Box::pin(self.deliver_into(&mut target.client, &target.config, manifest, content)).await
    }

    /// Send generated public content to an already initialized independent client through the
    /// same real sealing and durable receive. The receiver keeps its own authority and prekeys.
    /// # Errors
    /// Propagates ordinary content validation, authority, crypto, and store failures.
    pub async fn deliver_message_to_client(
        &self,
        target: &mut RamfluxClient,
        config: &GatewaySessionConfig,
        content: &g::Message,
    ) -> Result<(String, String), SdkError> {
        let account = target.born_v3_account.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let identity = target.owned_device_identity()?;
        let branch = target.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let manifest = crate::SdkDeviceManifestResponse::from_native(
            ramflux_protocol::custody::CustodyManifest {
                publication: account.publication(),
                custodian_publication: account.custodian_publication(
                    target.account_index()?.root(),
                    crate::custody::network_now()?,
                )?,
                devices: vec![ramflux_protocol::custody::CustodyManifestDevice {
                    device_ref: ramflux_protocol::custody::DeviceRef {
                        account_anchor: identity.root_commitment().into(),
                        device_id: identity.device_id().into(),
                        device_epoch: branch.device_epoch,
                    },
                    target_delivery_id: config.target_delivery_id.clone(),
                    prekey_bundle: serde_json::to_value(
                        target.load_x3dh_private_state(&identity)?.bundle,
                    )?,
                    message_layer: account
                        .record()
                        .body
                        .devices
                        .iter()
                        .find(|row| row.device_id == identity.device_id())
                        .and_then(|row| row.message_layer.clone()),
                }],
            },
        )?;
        // The receiver verifies the sender through its own directory and friend consent.
        let sender: crate::SdkDeviceManifestResponse =
            serde_json::from_value(self.manifest.clone())?;
        target.persist_observed_identity_directory_now(&manifest)?;
        target.persist_observed_identity_directory_now(&sender)?;
        let own = target.own_account_anchor()?;
        let peer = self.client.own_account_anchor()?;
        target.establish_friend_link("history-sender-link", &own, &peer)?;
        self.client.establish_friend_link("history-receiver-link", &peer, &own)?;
        Box::pin(self.deliver_into(target, config, manifest, content)).await
    }

    /// The independent client authors one generated Message to this account through real native
    /// sealing; this account receives it durably and the client projects its own copy, exactly as
    /// the ordinary send path leaves it before any sibling exists.
    /// # Errors
    /// Propagates ordinary content validation, authority, crypto, and store failures.
    pub async fn receive_message_from_client(
        &mut self,
        source: &RamfluxClient,
        source_config: &GatewaySessionConfig,
        content: &g::Message,
    ) -> Result<(String, String), SdkError> {
        let manifest: crate::SdkDeviceManifestResponse =
            serde_json::from_value(self.manifest.clone())?;
        let reference = self.client.owned_device_identity()?;
        // A born-v3 session config carries no signing branch; the ordinary send path signs with
        // the account's own branch, so the fixture envelope does too.
        let mut source_config = source_config.clone();
        source_config.device_branch = Some(std::sync::Arc::new(
            source.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
        ));
        source_config.source_identity = Some(source.owned_device_identity()?);
        let source_config = &source_config;
        let mut message = GatewayDirectMessage {
            conversation_id: source.generated_direct_conversation_id(&reference)?,
            message_id: "native-own-authored-operation".into(),
            envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            source_principal_id: source_config.principal_id.clone(),
            sender_id: source_config.device_id.clone(),
            recipient_device_id: Some(self.config.device_id.clone()),
            recipient_principal_commitment: Some(self.client.own_account_anchor()?),
            target_delivery_id: self.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: source.content_ttl()?,
        };
        let prepared = source.prepare_authored_content(
            &mut message,
            None,
            &g::Content { value: Some(g::content::Value::Message(content.clone())) },
        )?;
        let sealed = source.seal_generated_routed_prepared(
            source_config,
            &message,
            &prepared.wire,
            Route::direct(),
            SendMaterial {
                manifest: Some((reference.root_commitment().into(), manifest)),
                bundle: Some(self.client.load_x3dh_private_state(&reference)?.bundle),
            },
        )?;
        let envelope =
            crate::dm::gateway_generated_envelope_from_sealed(source_config, &mut message, sealed)?;
        source.project_authored_message(&message, &prepared.exact, &[])?;
        let entry = crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 2,
            target_delivery_id: self.config.target_delivery_id.clone(),
            envelope,
        };
        let mut engine = crate::GatewaySessionEngine::with_test_transport(
            self.config.clone(),
            Box::new(NoNetwork),
        );
        let pool = ramflux_transport::RelayQuicPool::new(
            ramflux_transport::RelayQuicPoolConfig::functional_default().map_err(|error| {
                SdkError::LocalBus(format!("native message fixture relay configuration: {error}"))
            })?,
        );
        self.client.apply_routed_entry(&mut engine, &pool, &entry).await?;
        Ok((message.conversation_id, message.message_id))
    }

    async fn deliver_into(
        &self,
        target_client: &mut RamfluxClient,
        target_config: &GatewaySessionConfig,
        manifest: crate::SdkDeviceManifestResponse,
        content: &g::Message,
    ) -> Result<(String, String), SdkError> {
        self.client.persist_observed_identity_directory_now(&manifest)?;
        let reference = target_client.owned_device_identity()?;
        let mut message = GatewayDirectMessage {
            conversation_id: self.client.generated_direct_conversation_id(&reference)?,
            message_id: "native-consumer-operation".into(),
            envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            source_principal_id: self.config.principal_id.clone(),
            sender_id: self.config.device_id.clone(),
            recipient_device_id: Some(target_config.device_id.clone()),
            recipient_principal_commitment: Some(target_client.own_account_anchor()?),
            target_delivery_id: target_config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: self.client.content_ttl()?,
        };
        let prepared = self.client.prepare_authored_content(
            &mut message,
            None,
            &g::Content { value: Some(g::content::Value::Message(content.clone())) },
        )?;
        let sealed = self.client.seal_generated_routed_prepared(
            &self.config,
            &message,
            &prepared.wire,
            Route::direct(),
            SendMaterial {
                manifest: Some((reference.root_commitment().into(), manifest)),
                bundle: Some(target_client.load_x3dh_private_state(&reference)?.bundle),
            },
        )?;
        let envelope =
            crate::dm::gateway_generated_envelope_from_sealed(&self.config, &mut message, sealed)?;
        self.client.project_authored_message(&message, &prepared.exact, &[])?;
        let entry = crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: target_config.target_delivery_id.clone(),
            envelope,
        };
        let mut engine = crate::GatewaySessionEngine::with_test_transport(
            target_config.clone(),
            Box::new(NoNetwork),
        );
        let pool = ramflux_transport::RelayQuicPool::new(
            ramflux_transport::RelayQuicPoolConfig::functional_default().map_err(|error| {
                SdkError::LocalBus(format!("native message fixture relay configuration: {error}"))
            })?,
        );
        target_client.apply_routed_entry(&mut engine, &pool, &entry).await?;
        Ok((message.conversation_id, message.message_id))
    }

    /// Transfer account ownership to the production bus dispatcher.
    /// # Errors
    /// Returns an error if the account index or unlocked database is unavailable.
    pub fn into_message_bus(self) -> Result<NativeMessageBus, SdkError> {
        let index = self.client.account_index()?.clone();
        let root = index.root().to_path_buf();
        let id = self.client.account_db()?.local_account_id.clone();
        let principal = self.config.principal_id.clone();
        let account = LocalBusAccountState::disconnected(self.client, self.config, principal);
        let state = LocalBusDaemonState {
            account_index: Some(index),
            config: LocalBusConfig::new(root.join("consumer.sock"), &root),
            nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::from([(id.clone(), account)]),
            active_account_id: Some(id),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        };
        let (sender, _) = tokio::sync::mpsc::channel(2);
        Ok(NativeMessageBus { state, connection: LocalBusConnectionState::new(1, sender) })
    }
}

impl NativeMessageBus {
    /// Materialize the committed receive event through the production outbox projector.
    /// # Errors
    /// Refuses a missing account, an excessive fixture outbox, or absent matching receive.
    pub fn received_event(&self, account: &str, message: &str) -> Result<LocalBusFrame, SdkError> {
        let client =
            &self.state.accounts.get(account).ok_or(SdkError::AccountDbNotUnlocked)?.client;
        let db = client.account_db()?;
        let entries = db.pending_outbox(256)?;
        if entries.len() >= 256 {
            return Err(content_error());
        }
        let request = LocalBusFrame::request(
            "consumer",
            Some(account.into()),
            "message",
            "message.receive",
            serde_json::json!({}),
        );
        let mut selected = None;
        for entry in entries {
            let projections = crate::bus::journal::project(client, &entry)?;
            for event in
                db.journal_outbox(entry.sequence, &projections, crate::time::now_unix_timestamp())?
            {
                if event.topic == "message.received"
                    && event.body["message"]["message_id"] == message
                {
                    selected = Some(crate::bus::journal::frame(&request, account, event));
                }
            }
        }
        selected.ok_or_else(content_error)
    }

    /// Dispatch a real local-bus request against the received generation-1 store.
    /// # Errors
    /// Propagates ordinary bus validation and account-store refusals.
    pub async fn request(&mut self, request: LocalBusFrame) -> Result<LocalBusFrame, SdkError> {
        let body = if crate::bus::readers::is_reader_request(&request.method) {
            let account = request.account_id.as_deref().ok_or(SdkError::AccountDbNotUnlocked)?;
            crate::bus::readers::read_account(&self.state, account, &request)?
        } else {
            crate::bus::daemon::dispatch_local_bus_request(
                &request,
                &mut self.state,
                &mut self.connection,
            )
            .await?
            .response_body
        };
        let mut response = request;
        response.kind = LocalBusFrameKind::Response;
        response.ok = Some(true);
        response.body = body;
        Ok(response)
    }
}

struct NoNetwork;
impl ramflux_transport::GatewaySessionFrameSink for NoNetwork {
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>>
    {
        Box::pin(async { Err(network_error()) })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for NoNetwork {
    fn recv_frame(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>>
    {
        Box::pin(async { Err(network_error()) })
    }
}
fn network_error() -> ramflux_transport::TransportError {
    ramflux_transport::TransportError::Quic("unexpected network in native message fixture".into())
}

fn content_error() -> SdkError {
    SdkError::GeneratedRefused {
        code: crate::GeneratedRefusalCode::Content,
        reason: "native message fixture receive event is unavailable or exceeds its bound".into(),
    }
}
