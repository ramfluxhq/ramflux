// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub async fn send_a2i_control_event_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        event: &A2iControlEvent,
        target_delivery_id: Option<String>,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let mut event = event.clone();
        let source = self.bind_owned_a2i_event(&mut event)?;
        if engine.config.device_id != source.device_id()
            || event.source_principal_id.as_deref() != Some(engine.config.principal_id.as_str())
            || engine.config.device_branch.as_ref().is_none_or(|branch| {
                self.device_branch.as_ref().is_none_or(|owned| {
                    branch.signing_key.verifying_key() != owned.signing_key.verifying_key()
                })
            })
        {
            return Err(SdkError::InboundRejected("A2I source engine mismatch".into()));
        }
        self.resolve_target_principal_commitment(&engine.config, None, &event.target_device_id)
            .await?;
        let lookup = self.root_qualified_device_lookup(&event.target_device_id)?;
        let prekey = engine.fetch_prekey_bundle(&lookup).await?;
        let bundle = prekey
            .bundle
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("A2I target prekey missing".to_owned()))?;
        self.verify_root_bound_prekey(&event.target_device_id, bundle)?;
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
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: event.source_device_id.clone(),
            recipient_device_id: Some(event.target_device_id.clone()),
            recipient_principal_commitment: Some(root),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: event.created_at,
            ttl: 3_600,
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
        engine: &mut GatewaySessionEngine,
        limit: usize,
    ) -> Result<Vec<A2iControlEvent>, SdkError> {
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
                let delivery = self.apply_routed_entry(engine, &pool, &entry, false).await?;
                if delivery.routing.kind == crate::client::routed::Kind::Control {
                    let key = self
                        .authenticated_committed_key(&entry)?
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
        engine: &mut GatewaySessionEngine,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<A2iControlEvent>, SdkError> {
        let expected =
            a2i_control_conversation_id(&entry.envelope.source_device_id, &engine.config.device_id);
        if self.legacy_routing_binding(&engine.config.device_id, entry)?.as_deref()
            != Some(expected.as_str())
        {
            self.account_db()?.hold_unrouted(
                &entry.envelope.envelope_id,
                entry.inbox_seq,
                &serde_json::to_vec(&entry)?,
                now_unix_timestamp(),
            )?;
            self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
            return Ok(None);
        }
        self.ensure_inbound_device(&engine.config, entry).await?;
        let receipt_key = format!("legacy/a2i/{}", self.authenticated_committed_key(entry)?);
        if let Some(receipt) =
            self.account_db()?.load_actor_state::<LegacyControlReceipt>(&receipt_key)?
        {
            if receipt.payload_hash != entry.envelope.payload_hash {
                return Err(SdkError::InboundRejected("legacy A2I envelope id reused".to_owned()));
            }
            self.finish_a2i_receive(engine, entry).await?;
            let event = self
                .account_db()?
                .load_actor_state::<A2iControlEvent>(&crate::client::routed::control::a2i_key(
                    &self.authenticated_device_identity(entry)?,
                    &receipt.event.event_id,
                )?)?
                .unwrap_or(receipt.event);
            return Ok((!event.acknowledged).then_some(event));
        }

        let conversation_id =
            a2i_control_conversation_id(&entry.envelope.source_device_id, &engine.config.device_id);
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
            || event.target_device_id != engine.config.device_id
        {
            return Err(SdkError::InboundRejected("legacy A2I endpoint mismatch".to_owned()));
        }
        let source = self.bind_received_a2i_event(&mut event, entry)?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.append_gateway_delivery(entry)?;
            self.account_db()?.persist_actor_state(
                &receipt_key,
                &LegacyControlReceipt {
                    event: event.clone(),
                    payload_hash: entry.envelope.payload_hash.clone(),
                },
            )?;

            self.persist_dm_session(
                &conversation_id,
                &entry.envelope.envelope_id,
                "recv",
                &session,
            )?;
            self.account_db()?.persist_actor_state(
                &crate::client::routed::control::a2i_key(&source, &event.event_id)?,
                &event,
            )?;
            Ok(())
        })?;
        self.finish_a2i_receive(engine, entry).await?;
        Ok(Some(event))
    }
    async fn finish_a2i_receive(
        &mut self,
        engine: &mut GatewaySessionEngine,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        self.ack_gateway_entry(engine, entry, now_unix_timestamp()).await?;
        self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LegacyControlReceipt {
    event: A2iControlEvent,
    payload_hash: String,
}
