// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated Typing requests take no durable operation receipt or response capture path.
use crate::client::identity_authority::HeadUse;
use crate::{
    GatewayDirectMessage, GatewaySessionEngine, RamfluxClient, SdkError,
    bindings::{AdapterError, GeneratedErrorCode},
};
use prost::Message as _;
use ramflux_protocol::{
    ephemeral::{EphemeralDropReason, EphemeralSubmitOutcome},
    message as g,
};
use std::time::Instant;
fn refused(code: GeneratedErrorCode, reason: &str) -> SdkError {
    AdapterError::new(code, reason).into()
}

impl RamfluxClient {
    /// Set the frontend's focused conversation in this unlocked account generation.
    /// Returns the previous conversation so the host can issue its best-effort clear.
    /// # Errors
    /// Refuses group/unbound scopes and bounded transient-memory exhaustion.
    pub fn set_typing_focus(&self, conversation: Option<&str>) -> Result<Option<String>, SdkError> {
        if let Some(conversation) = conversation {
            self.typing_peer_root(conversation)?;
        }
        self.typing_sender.borrow_mut().focus(conversation)
    }
    /// Local account preference; disabling sharing emits no Typing.
    /// # Errors
    /// Returns account storage errors.
    pub fn set_share_typing(&self, enabled: bool) -> Result<(), SdkError> {
        self.account_db()?.write_transaction(|| {
            self.account_db()?
                .persist_actor_state("settings/share_typing", &enabled)
                .map_err(SdkError::from)
        })
    }
    /// Execute only `send.content.typing`, using bounded memory for correlation/replay.
    /// No request, response, journal, transport retry or operation receipt is persisted.
    /// # Errors
    /// Returns typed argument, focus/consent, rate, capability, crypto or transport errors.
    pub async fn send_generated_typing_request(
        &self,
        engine: &mut GatewaySessionEngine,
        request: &g::MessageRequest,
    ) -> Result<g::MessageUpdate, SdkError> {
        let mut request = crate::bindings::round_trip_request(request)?;
        if request.account_id != self.account_db()?.local_account_id {
            return Err(refused(GeneratedErrorCode::InvalidArgument, "typing account mismatch"));
        }
        request.request_id.clear(); // correlation never changes operation identity
        let fingerprint = *blake3::hash(&request.encode_to_vec()).as_bytes();
        let Some(g::message_request::Action::Send(send)) = request.action.as_ref() else {
            return Err(refused(GeneratedErrorCode::InvalidArgument, "use send.content.typing"));
        };
        let Some(g::content::Value::Typing(typing)) =
            send.content.as_ref().and_then(|content| content.value.as_ref())
        else {
            return Err(refused(
                GeneratedErrorCode::InvalidArgument,
                "expected send.content.typing",
            ));
        };
        if let Some(response) =
            self.typing_sender.borrow().lookup(&send.operation_id, &fingerprint)?
        {
            return Ok(response);
        }
        if !self.account_db()?.load_actor_state::<bool>("settings/share_typing")?.unwrap_or(true) {
            return Err(refused(
                GeneratedErrorCode::EphemeralUnavailable,
                "typing sharing is disabled",
            ));
        }
        let targets = self.typing_targets(&send.conversation_id)?;
        let response_bytes = self.typing_response_budget(&send.conversation_id)?;
        self.typing_sender.borrow_mut().reserve(&send.operation_id, fingerprint, response_bytes)?;
        let result =
            Box::pin(self.submit_generated_typing(engine, send, typing.active, targets)).await;
        self.typing_sender.borrow_mut().finish(&send.operation_id, &result);
        result
    }

    async fn submit_generated_typing(
        &self,
        engine: &mut GatewaySessionEngine,
        send: &g::SendMessage,
        active: bool,
        targets: Vec<ramflux_crypto::RootQualifiedDeviceRef>,
    ) -> Result<g::MessageUpdate, SdkError> {
        let mut response = None;
        for target in targets {
            let now = Instant::now();
            if !self.typing_sender.borrow_mut().admit(
                &send.conversation_id,
                target.storage_key(),
                active,
                now,
            )? {
                continue;
            }
            let message = self.typing_outbound_message(&send.conversation_id, &target, active)?;
            let (envelope, update) =
                self.prepare_typing_update_delivery(engine, &message, active)?;
            {
                let mut sender = self.typing_sender.borrow_mut();
                sender.sealed(&send.conversation_id, target.storage_key(), active, now);
                sender.mark_sealed(&send.operation_id);
            }
            let result = engine.submit_ephemeral(envelope).await;
            match result {
                Ok(result) if result.outcome() == EphemeralSubmitOutcome::Accepted => {
                    if response.is_none() {
                        response = Some(update);
                    }
                }
                Ok(result) if result.reason() == Some(EphemeralDropReason::Offline) => self
                    .typing_sender
                    .borrow_mut()
                    .offline(&send.conversation_id, target.storage_key(), now),
                Ok(_) => (),
                Err(error) => return Err(error),
            }
        }
        response.ok_or_else(|| {
            refused(GeneratedErrorCode::EphemeralUnavailable, "no eligible live typing target")
        })
    }
    fn typing_peer_root(&self, conversation: &str) -> Result<String, SdkError> {
        let row =
            self.account_db()?.client_record("conversation", conversation)?.ok_or_else(|| {
                refused(GeneratedErrorCode::TargetNotFound, "typing conversation absent")
            })?;
        if row["kind"] != "direct" || !row["group_id"].is_null() {
            return Err(refused(GeneratedErrorCode::InvalidArgument, "Typing is DM only"));
        }
        let own = self.own_account_anchor()?;
        let roots = row["participant_roots"].as_array().ok_or_else(|| {
            refused(GeneratedErrorCode::NotAuthorized, "direct root binding absent")
        })?;
        let peer = roots
            .iter()
            .filter_map(serde_json::Value::as_str)
            .find(|root| *root != own)
            .ok_or_else(|| refused(GeneratedErrorCode::NotAuthorized, "direct peer absent"))?;
        if roots.len() != 2
            || !roots.iter().any(|root| root.as_str() == Some(own.as_str()))
            || g::dm_scope::validate_direct(conversation, &own, peer).is_err()
        {
            return Err(refused(GeneratedErrorCode::NotAuthorized, "direct root binding mismatch"));
        }
        Ok(peer.into())
    }
    fn typing_targets(
        &self,
        conversation: &str,
    ) -> Result<Vec<ramflux_crypto::RootQualifiedDeviceRef>, SdkError> {
        let peer = self.typing_peer_root(conversation)?;
        if !self.friend_link_peer_is_accepted(&peer)? {
            return Err(refused(
                GeneratedErrorCode::NotAuthorized,
                "typing requires accepted contact",
            ));
        }
        let authority = self
            .current_custody_authority(&peer, crate::custody::network_now()?)?
            .ok_or_else(|| {
                refused(
                    GeneratedErrorCode::PeerUpgradeRequired,
                    "native peer authority unavailable",
                )
            })?;
        let local = self.owned_device_identity()?;
        let mut targets = Vec::new();
        for device in &authority.envelope().body.devices {
            let Ok(target) = ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(
                &authority,
                &device.device_id,
            ) else {
                continue;
            };
            if self.require_cached_root_authority(HeadUse::NewAuthorization, &target).is_ok()
                && self.sendable_pair(&local, &target)?.is_some()
            {
                targets.push(target);
            }
        }
        Ok(targets)
    }
    fn typing_outbound_message(
        &self,
        conversation: &str,
        target: &ramflux_crypto::RootQualifiedDeviceRef,
        active: bool,
    ) -> Result<GatewayDirectMessage, SdkError> {
        let record = self.trusted_device(HeadUse::NewAuthorization, target)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let nonce = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        Ok(GatewayDirectMessage {
            conversation_id: conversation.into(),
            message_id: nonce.clone(),
            envelope_id: nonce,
            source_principal_id: local.principal_id.clone(),
            sender_id: local.device_id.clone(),
            recipient_device_id: Some(target.device_id().into()),
            recipient_principal_commitment: Some(target.root_commitment().into()),
            target_delivery_id: record["target_delivery_id"]
                .as_str()
                .ok_or_else(|| {
                    refused(
                        GeneratedErrorCode::EphemeralUnavailable,
                        "typing target delivery absent",
                    )
                })?
                .into(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: if active { 5 } else { 1 },
        })
    }
    fn typing_response_budget(&self, conversation: &str) -> Result<usize, SdkError> {
        let local = self.owned_device_identity()?;
        Ok(g::MessageUpdate {
            account_id: self.account_db()?.local_account_id.clone(),
            journal_sequence: 0,
            identity: Some(g::EventIdentity {
                id: vec![0; 32],
                conversation_id: conversation.into(),
                author: Some(g::QualifiedDevice {
                    account_anchor: local.root_commitment().into(),
                    device_id: local.device_id().into(),
                    device_epoch: u64::MAX,
                }),
                ..Default::default()
            }),
            state: Some(g::message_update::State::Content(g::Content {
                value: Some(g::content::Value::Typing(g::Typing {
                    active: true,
                    expires_at: u64::MAX,
                })),
            })),
        }
        .encoded_len())
    }
}
