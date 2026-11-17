// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated Typing requests take no durable operation receipt or response capture path.
use crate::EphemeralSendOutcome;
use crate::client::identity_authority::HeadUse;
use crate::{
    GatewayDirectMessage, GatewaySessionAccess, RamfluxClient, SdkError,
    bindings::{AdapterError, GeneratedErrorCode},
};
use prost::Message as _;
use ramflux_protocol::{
    ephemeral::{EphemeralDropReason, EphemeralModeError},
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
        engine: &mut impl GatewaySessionAccess,
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
        engine: &mut impl GatewaySessionAccess,
        send: &g::SendMessage,
        active: bool,
        targets: Vec<ramflux_crypto::RootQualifiedDeviceRef>,
    ) -> Result<g::MessageUpdate, SdkError> {
        let mut response = None;
        // An admitted clear that the gateway drops must stay retryable. Releasing the
        // live target first makes the next stop look like there was never a target.
        let mut clear_not_delivered = false;
        let mut terminal_clear = false;
        for target in targets {
            let now = Instant::now();
            let storage_key = target.storage_key();
            if !self.typing_sender.borrow_mut().admit(
                &send.conversation_id,
                storage_key,
                active,
                now,
            )? {
                continue;
            }
            let message = self.typing_outbound_message(&send.conversation_id, &target, active)?;
            let (envelope, update) =
                self.prepare_typing_update_delivery(engine, &message, active)?;
            let storage_key = target.storage_key();
            if active {
                // An active frame spends cadence even when the gateway drops it.
                let mut sender = self.typing_sender.borrow_mut();
                sender.sealed(&send.conversation_id, storage_key, true, now);
                sender.mark_sealed(&send.operation_id);
            }
            let result = engine.submit_ephemeral(envelope).await;
            match result {
                Ok(EphemeralSendOutcome::Delivered) => {
                    if !active {
                        let mut sender = self.typing_sender.borrow_mut();
                        sender.sealed(&send.conversation_id, storage_key, false, now);
                        sender.mark_sealed(&send.operation_id);
                    }
                    if response.is_none() {
                        response = Some(update);
                    }
                }
                Ok(EphemeralSendOutcome::Dropped(EphemeralDropReason::Offline)) => {
                    self.typing_sender.borrow_mut().offline(
                        &send.conversation_id,
                        storage_key,
                        now,
                    );
                }
                Ok(
                    EphemeralSendOutcome::RateLimited
                    | EphemeralSendOutcome::Invalid(EphemeralModeError::Expired)
                    | EphemeralSendOutcome::Dropped(
                        EphemeralDropReason::Expired | EphemeralDropReason::QueueFull,
                    ),
                ) if !active => {
                    clear_not_delivered = true;
                }
                Ok(_) => {
                    if !active {
                        terminal_clear = true;
                    }
                }
                Err(error) => {
                    if !active {
                        self.typing_sender.borrow_mut().mark_sealed(&send.operation_id);
                    }
                    return Err(error);
                }
            }
        }
        if let Some(response) = response {
            return Ok(response);
        }
        if clear_not_delivered {
            return Err(refused(GeneratedErrorCode::RateLimited, "typing clear was not delivered"));
        }
        if terminal_clear {
            self.typing_sender.borrow_mut().mark_sealed(&send.operation_id);
        }
        Err(refused(GeneratedErrorCode::EphemeralUnavailable, "no eligible live typing target"))
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
            created_at: typing_created_at(active, crate::ephemeral::session::wall_ms()),
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

/// Whole-second `created_at` for a typing frame.
///
/// A clear's TTL is 1, so `(created_at + 1) * 1000` can fall inside the current
/// second. Stamp the next second when less than one second remains. That lead
/// stays inside the two-second future tolerance, and the receiver holds a future
/// clear until that second.
fn typing_created_at(active: bool, now_ms: u64) -> i64 {
    const CLEAR_LIFE_MS: u64 = 1_000;
    let now_secs = now_ms / CLEAR_LIFE_MS;
    let same_second_deadline = now_secs.saturating_add(1).saturating_mul(CLEAR_LIFE_MS);
    let created_secs = if active || same_second_deadline.saturating_sub(now_ms) >= CLEAR_LIFE_MS {
        now_secs
    } else {
        now_secs.saturating_add(1)
    };
    i64::try_from(created_secs).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::typing_created_at;
    use ramflux_protocol::ephemeral::{
        EPHEMERAL_FUTURE_TOLERANCE_MS, EphemeralModeError, deadline,
    };
    use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};

    fn envelope(created_at: i64, ttl: u32) -> Envelope {
        Envelope {
            schema: "schema".to_owned(),
            version: 2,
            domain: "domain".to_owned(),
            ext: Ext::default(),
            signed: SignedFields {
                signing_key_id: "key".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "signature".to_owned(),
            },
            envelope_id: "envelope".to_owned(),
            source_principal_id: "principal".to_owned(),
            source_device_id: "device".to_owned(),
            target_delivery_id: "target".to_owned(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Low,
            ttl,
            created_at,
            encrypted_payload: "payload".to_owned(),
            payload_hash: "hash".to_owned(),
            delivery_mode: Some("ephemeral".to_owned()),
            collapse_tag: Some(ramflux_protocol::encode_base64url([0x22; 32])),
            report_commitment: Some(ramflux_protocol::encode_base64url([0x33; 32])),
        }
    }

    #[test]
    fn typing_clear_deadline_survives_the_rest_of_its_second() {
        // The CI failure's active frame expired at this unix second.
        let second = 1_794_868_764_u64;
        for offset in [0_u64, 1, 500, 999] {
            let now_ms = second.saturating_mul(1_000).saturating_add(offset);
            let created = typing_created_at(false, now_ms);
            let created_ms = i128::from(created).saturating_mul(1_000);
            let now = i128::from(now_ms);
            let lead = created_ms.saturating_sub(now);
            assert!(
                lead < i128::from(EPHEMERAL_FUTURE_TOLERANCE_MS),
                "test: clear created_at lead {lead} ms stays inside the future tolerance"
            );
            deadline(&envelope(created, 1), now_ms)
                .expect("test: the gateway accepts the clear at the stamp");
            let later = now_ms.saturating_add(999);
            assert!(
                deadline(&envelope(created, 1), later).is_ok(),
                "test: a clear stamped at {now_ms} is still live 999 ms later"
            );
        }
        let raced_at = second.saturating_mul(1_000).saturating_add(999).saturating_add(999);
        assert!(
            matches!(
                deadline(&envelope(i64::try_from(second).expect("test: second fits"), 1), raced_at),
                Err(EphemeralModeError::Expired)
            ),
            "test: a clear stamped on the current second is expired 999 ms after that second's end"
        );
        let active_at = second.saturating_mul(1_000).saturating_add(999);
        assert_eq!(
            typing_created_at(true, active_at),
            i64::try_from(second).expect("test: second fits"),
            "test: an active frame keeps the current second"
        );
    }
}
