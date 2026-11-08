// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;

impl RamfluxClient {
    pub async fn send_a2i_control_event_via_gateway(
        &self,
        engine: &mut impl GatewaySessionAccess,
        event: &A2iControlEvent,
        target_delivery_id: Option<String>,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let mut event = event.clone();
        let source = self.bind_owned_a2i_event(&mut event)?;
        if engine.config().device_id != source.device_id()
            || event.source_principal_id.as_deref() != Some(engine.config().principal_id.as_str())
            || engine.config().device_branch.as_ref().is_none_or(|branch| {
                self.device_branch.as_ref().is_none_or(|owned| {
                    branch.signing_key.verifying_key() != owned.signing_key.verifying_key()
                })
            })
        {
            return Err(SdkError::InboundRejected("A2I source engine mismatch".into()));
        }
        self.resolve_target_principal_commitment(engine.config(), None, &event.target_device_id)
            .await?;
        let lookup = self.root_qualified_device_lookup(&event.target_device_id)?;
        let prekey = engine.fetch_prekey_bundle(&lookup).await?;
        let bundle = prekey
            .bundle
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("A2I target prekey missing".to_owned()))?;
        self.verify_root_bound_prekey(&self.device_identity(&event.target_device_id)?, bundle)?;
        let target_delivery_id =
            target_delivery_id.or(prekey.target_delivery_id).ok_or_else(|| {
                SdkError::LocalBus(format!(
                    "missing target delivery id for A2I target device {}",
                    event.target_device_id
                ))
            })?;
        let root = self.device_root(&event.target_device_id)?;
        event.target_device_id =
            super::identity_authority::device_namespace::wire_device_id(&event.target_device_id)?;
        let conversation_id =
            a2i_control_conversation_id(&event.source_device_id, &event.target_device_id);
        let message = GatewayDirectMessage {
            conversation_id,
            message_id: event.event_id.clone(),
            envelope_id: format!("a2i:{}", event.event_id),
            source_principal_id: engine.config().principal_id.clone(),
            sender_id: event.source_device_id.clone(),
            recipient_device_id: Some(event.target_device_id.clone()),
            recipient_principal_commitment: Some(root),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: event.created_at,
            ttl: self.content_ttl()?,
        };
        self.send_plaintext_direct_message_without_franking(
            engine,
            message,
            &serde_json::to_vec(&event)?,
            crate::client::routed::Route::control(),
        )
        .await
    }

    /// # Errors
    /// Returns an error when SDK-owned DM encryption, local projection persistence, envelope
    pub async fn receive_a2i_control_events(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        limit: usize,
    ) -> Result<Vec<A2iControlEvent>, SdkError> {
        self.account_db()?.refuse_legacy_receive()?;
        let after_inbox_seq = self.gateway_receive_cursor(engine.target_delivery_id())?;
        let mut entries = engine.resume_after(after_inbox_seq, limit).await?;
        entries.retain(|entry| entry.inbox_seq > after_inbox_seq);
        entries.sort_by_key(|entry| entry.inbox_seq);
        let mut events = Vec::new();
        for entry in entries {
            if crate::client::routed::decode(&entry.envelope).is_ok() {
                let pool = ramflux_transport::RelayQuicPool::new(
                    ramflux_transport::RelayQuicPoolConfig::functional_default()
                        .map_err(|error| SdkError::LocalBus(error.to_string()))?,
                );
                let delivery = self
                    .apply_routed_entry(engine, &pool, &entry, false)
                    .await
                    .map_err(SdkError::without_directory_context)?;
                if delivery
                    .routing
                    .as_ref()
                    .is_some_and(|route| route.kind == crate::client::routed::Kind::Control)
                {
                    let key = self
                        .authenticated_committed_key(HeadUse::NewAuthorization, &entry)?
                        .replace("routed/committed/", "routed/control/");
                    if let Some(event) =
                        self.account_db()?.load_actor_state::<A2iControlEvent>(&key)?
                    {
                        let event = self
                            .account_db()?
                            .load_actor_state::<A2iControlEvent>(
                                &crate::client::routed::control::a2i_key(
                                    &self.a2i_event_identity(&event)?,
                                    &event.event_id,
                                )?,
                            )?
                            .unwrap_or(event);
                        if !event.acknowledged {
                            events.push(event);
                        }
                    }
                }
                self.ack_gateway_entry(engine, &entry, now_unix_timestamp()).await?;
                self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
                continue;
            }
            if let Some(event) = self.receive_bound_legacy_a2i(engine, &entry).await? {
                events.push(event);
            }
        }
        Ok(events)
    }
    async fn receive_bound_legacy_a2i(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<A2iControlEvent>, SdkError> {
        if self.hold_unbound_legacy_a2i(&engine.config().device_id, entry)? {
            self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
            return Ok(None);
        }
        self.ensure_inbound_device(engine.config(), entry).await?;
        if let Some(receipt) = self.load_legacy_a2i_receipt(entry)? {
            self.finish_a2i_receive(engine, entry).await?;
            let event = self
                .account_db()?
                .load_actor_state::<A2iControlEvent>(&crate::client::routed::control::a2i_key(
                    &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
                    &receipt.event.event_id,
                )?)?
                .unwrap_or(receipt.event);
            return Ok((!event.acknowledged).then_some(event));
        }
        let opened = self.decrypt_bound_legacy_a2i(&engine.config().device_id, entry)?;
        self.account_db()?.write_transaction(|| self.persist_legacy_a2i_effect(entry, &opened))?;
        self.finish_a2i_receive(engine, entry).await?;
        Ok(Some(opened.event))
    }

    pub(crate) fn legacy_a2i_receipt_key(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        Ok(format!(
            "legacy/a2i/{}",
            self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?
        ))
    }

    pub(crate) fn legacy_a2i_is_unbound(
        &self,
        local_device: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        #[cfg(test)]
        if let Some(forced) = take_unbound_answer() {
            return Ok(forced);
        }
        let expected = a2i_control_conversation_id(&entry.envelope.source_device_id, local_device);
        Ok(self.legacy_routing_binding(local_device, entry)?.as_deref() != Some(expected.as_str()))
    }

    /// True when the entry has no exact A2I device-pair binding and was held unrouted.
    pub(crate) fn hold_unbound_legacy_a2i(
        &self,
        local_device: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        if !self.legacy_a2i_is_unbound(local_device, entry)? {
            return Ok(false);
        }
        self.account_db()?.hold_unrouted(
            &entry.envelope.envelope_id,
            entry.inbox_seq,
            &serde_json::to_vec(&entry)?,
            now_unix_timestamp(),
        )?;
        Ok(true)
    }

    /// Existing receipt, or `InboundRejected` when the envelope id is reused with a new payload.
    pub(crate) fn load_legacy_a2i_receipt(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<LegacyControlReceipt>, SdkError> {
        let Some(receipt) = self
            .account_db()?
            .load_actor_state::<LegacyControlReceipt>(&self.legacy_a2i_receipt_key(entry)?)?
        else {
            return Ok(None);
        };
        reject_legacy_a2i_payload_reuse(&receipt, entry)?;
        Ok(Some(receipt))
    }

    pub(crate) fn decrypt_bound_legacy_a2i(
        &self,
        local_device: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<LegacyA2iOpened, SdkError> {
        let conversation_id =
            a2i_control_conversation_id(&entry.envelope.source_device_id, local_device);
        let ciphertext_bytes = ramflux_protocol::decode_base64url(
            &entry.envelope.encrypted_payload,
        )
        .map_err(|error| SdkError::LocalBus(format!("invalid A2I encrypted payload: {error}")))?;
        let envelope: SdkDmEncryptedEnvelope = serde_json::from_slice(&ciphertext_bytes)?;
        let mut session =
            self.load_or_create_recv_dm_session(&conversation_id, envelope.x3dh.as_ref())?;
        let body = session.decrypt(&envelope.ciphertext, dm_associated_data(&conversation_id))?;
        let mut event: A2iControlEvent = serde_json::from_slice(&body)?;
        if event.source_device_id != entry.envelope.source_device_id
            || event.target_device_id != local_device
        {
            return Err(SdkError::InboundRejected("legacy A2I endpoint mismatch".to_owned()));
        }
        let source = self.bind_received_a2i_event(&mut event, entry)?;
        Ok(LegacyA2iOpened { conversation_id, session, event, source })
    }

    pub(crate) fn persist_legacy_a2i_effect(
        &self,
        entry: &GatewayInboxEntry,
        opened: &LegacyA2iOpened,
    ) -> Result<(), SdkError> {
        self.append_gateway_delivery(entry)?;
        self.account_db()?.persist_actor_state(
            &self.legacy_a2i_receipt_key(entry)?,
            &LegacyControlReceipt {
                event: opened.event.clone(),
                payload_hash: entry.envelope.payload_hash.clone(),
            },
        )?;
        self.persist_dm_session(
            &opened.conversation_id,
            &entry.envelope.envelope_id,
            "recv",
            &opened.session,
        )?;
        self.account_db()?.persist_actor_state(
            &crate::client::routed::control::a2i_key(&opened.source, &opened.event.event_id)?,
            &opened.event,
        )?;
        Ok(())
    }
    async fn finish_a2i_receive(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        self.ack_gateway_entry(engine, entry, now_unix_timestamp()).await?;
        self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct LegacyControlReceipt {
    pub event: A2iControlEvent,
    pub payload_hash: String,
}

pub(crate) struct LegacyA2iOpened {
    pub conversation_id: String,
    pub session: ramflux_crypto::DmSession,
    pub event: A2iControlEvent,
    pub source: ramflux_crypto::RootQualifiedDeviceRef,
}

/// Shared payload-hash check used by live receive and dormant W1.
pub(crate) fn reject_legacy_a2i_payload_reuse(
    receipt: &LegacyControlReceipt,
    entry: &GatewayInboxEntry,
) -> Result<(), SdkError> {
    if receipt.payload_hash != entry.envelope.payload_hash {
        return Err(SdkError::InboundRejected("legacy A2I envelope id reused".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static UNBOUND_QUEUE: std::cell::RefCell<Vec<bool>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn take_unbound_answer() -> Option<bool> {
    UNBOUND_QUEUE.with(|queue| {
        let mut queue = queue.borrow_mut();
        if queue.is_empty() { None } else { Some(queue.remove(0)) }
    })
}

#[cfg(test)]
pub(crate) fn queue_unbound_answers(answers: impl IntoIterator<Item = bool>) {
    UNBOUND_QUEUE.with(|queue| {
        let mut queue = queue.borrow_mut();
        queue.clear();
        queue.extend(answers);
    });
}
