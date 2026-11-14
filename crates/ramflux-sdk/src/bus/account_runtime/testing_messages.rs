// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native encrypted Message delivery and the ordinary bus dispatcher for consumer tests.
use super::testing_calls::NativeCallAccount;
use crate::bus::state::{LocalBusAccountState, LocalBusConnectionState, LocalBusDaemonState};
use crate::client::routed::{Route, SendMaterial};
use crate::{GatewayDirectMessage, LocalBusConfig, LocalBusFrame, LocalBusFrameKind, SdkError};
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
        self.client.persist_fetched_identity_directory(&manifest)?;
        let reference = target.client.owned_device_identity()?;
        let mut message = GatewayDirectMessage {
            conversation_id: self.client.generated_direct_conversation_id(&reference)?,
            message_id: "native-consumer-operation".into(),
            envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            source_principal_id: self.config.principal_id.clone(),
            sender_id: self.config.device_id.clone(),
            recipient_device_id: Some(target.config.device_id.clone()),
            recipient_principal_commitment: Some(target.client.own_account_anchor()?),
            target_delivery_id: target.config.target_delivery_id.clone(),
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
                bundle: Some(target.client.load_x3dh_private_state(&reference)?.bundle),
            },
        )?;
        let envelope =
            crate::dm::gateway_generated_envelope_from_sealed(&self.config, &mut message, sealed)?;
        self.client.project_authored_message(&message, &prepared.exact, &[])?;
        let entry = crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: target.config.target_delivery_id.clone(),
            envelope,
        };
        let mut engine = crate::GatewaySessionEngine::with_test_transport(
            target.config.clone(),
            Box::new(NoNetwork),
        );
        let pool = ramflux_transport::RelayQuicPool::new(
            ramflux_transport::RelayQuicPoolConfig::functional_default().map_err(|error| {
                SdkError::LocalBus(format!("native message fixture relay configuration: {error}"))
            })?,
        );
        target.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
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
