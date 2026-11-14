// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authored structural events use the generated carrier and existing native projection rules.
use super::{Kind, RamfluxClient, Route, SealPair, invalid};
use crate::prelude::*;
use ramflux_protocol::message as g;

pub(crate) struct ConversationEvent<'a> {
    pub message: GatewayDirectMessage,
    pub exact: &'a [u8],
    pub wire: &'a [u8],
    pub reconcile: Option<&'a dyn Fn() -> Result<(), SdkError>>,
    pub recipients: &'a [String],
}

impl RamfluxClient {
    pub(crate) async fn submit_conversation_event(
        &self,
        engine: &mut impl GatewaySessionAccess,
        event: ConversationEvent<'_>,
    ) -> Result<GatewayInboxEntry, SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        let ConversationEvent { mut message, exact, wire, reconcile, recipients } = event;
        let (identity, content) = Self::decode_generated_inner(exact)?;
        let (wire_identity, _) = Self::decode_generated_inner(wire)?;
        if !matches!(
            content.value,
            Some(
                g::content::Value::Message(_)
                    | g::content::Value::Edit(_)
                    | g::content::Value::Delete(_)
                    | g::content::Value::Reaction(_)
            )
        ) {
            return Err(invalid("unsupported conversation event kind"));
        }

        let local = self.owned_device_identity()?;
        if identity != wire_identity
            || identity.conversation_id != message.conversation_id
            || identity.author.as_ref().is_none_or(|author| {
                author.account_anchor != local.root_commitment()
                    || author.device_id != local.device_id()
            })
        {
            return Err(invalid("conversation event differs from authenticated author or wire"));
        }
        let route = identity.group_id.as_deref().map_or_else(Route::direct, Route::group_message);
        self.current_custody_authority(local.root_commitment(), crate::custody::network_now()?)?
            .ok_or(SdkError::NetworkingPending)?;
        if route.kind == Kind::Direct {
            let root = message
                .recipient_principal_commitment
                .as_deref()
                .ok_or_else(|| invalid("conversation peer root absent"))?;
            if !self.friend_link_peer_is_accepted(root)? {
                return Err(SdkError::LocalBusPermissionDenied);
            }
        } else if let Some(group) = identity.group_id.as_deref() {
            self.require_generated_group_epoch(
                group,
                &local,
                identity.group_epoch.ok_or_else(|| invalid("group epoch absent"))?,
                false,
            )?;
        }
        message.message_id = ramflux_protocol::encode_base64url(&identity.id);
        let (mut session, header, bundle) = self.send_pair_session(engine, &message).await?;
        let recipient = Self::qualified_recipient(&message)?;
        let envelope = self.account_db()?.write_transaction(|| {
            self.bind_outgoing_delivery(&local, &message, &route.kind)?;
            let sealed = self.seal_routed_with_route_in(
                &message,
                wire,
                route,
                SealPair {
                    local: &engine.config().device_id,
                    remote: &recipient,
                    session: &mut session,
                    header,
                    bundle,
                },
                Some((g::outer::CANDIDATE_ENVELOPE_SCHEMA, 2)),
            )?;
            crate::dm::gateway_generated_envelope_from_sealed(engine.config(), &mut message, sealed)
        })?;
        let accepted = engine.submit_envelope(envelope).await?;
        self.account_db()?.write_transaction(|| {
            self.project_authored_conversation_event(&accepted, &identity, &content, exact, wire)?;
            // Edit retirement erases old payload graphs. Capture/queue the accepted revision after it.
            if let Some(group) = identity.group_id.as_deref() {
                self.capture_own_authored_group(group, &message.sender_id, exact)?;
            } else {
                self.capture_own_authored_direct(&message, exact)?;
            }
            let peer = if identity.group_id.is_none() {
                Some(self.own_sent_peer(&message)?)
            } else {
                None
            };
            let ticket = self.queue_own_sent_copy(&message.message_id, || {
                self.stage_own_sent_message(crate::client::own_sent_message::OwnSentInput {
                    envelope: &message.envelope_id,
                    conversation: &message.conversation_id,
                    message: &message.message_id,
                    sender: &message.sender_id,
                    original_recipients: recipients,
                    group: identity.group_id.as_deref(),
                    peer: peer.as_deref(),
                    body: exact,
                    ciphertext: &message.encrypted_body,
                    at: message.created_at,
                })?;
                Ok(message.envelope_id.clone())
            });
            self.finish_own_sent_copy(&message.message_id, ticket.as_deref(), true);
            reconcile.map_or(Ok(()), |commit| commit())?;
            Ok::<_, SdkError>(())
        })?;
        Ok(accepted)
    }

    fn project_authored_conversation_event(
        &self,
        entry: &GatewayInboxEntry,
        identity: &g::EventIdentity,
        content: &g::Content,
        exact: &[u8],
        wire: &[u8],
    ) -> Result<(), SdkError> {
        let local = self.owned_device_identity()?;
        let conversation = &identity.conversation_id;
        match content.value.as_ref() {
            Some(g::content::Value::Edit(_)) => {
                self.apply_generated_edit_authorized(
                    crate::client::message_mutations::EditContext {
                        entry,
                        source: &local,
                        imported: None,
                        own_sent: false,
                    },
                    conversation,
                    exact,
                    None,
                )?;
            }
            Some(g::content::Value::Delete(delete)) => {
                self.apply_generated_delete_authorized(&local, identity, conversation, delete)?;
            }
            Some(g::content::Value::Reaction(reaction)) => {
                self.apply_generated_reaction_authorized(&local, identity, conversation, reaction)?;
            }
            Some(g::content::Value::Message(message)) => {
                let id = ramflux_protocol::encode_base64url(&identity.id);
                self.account_db()?.write_transaction(|| {
                    if self.direct_message_by_id(&id)?.is_none() {
                        self.send_direct_message(
                            conversation,
                            &id,
                            local.device_id(),
                            &ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
                                .map_err(|_| invalid("invalid submitted ciphertext"))?,
                        )?;
                        self.account_db()?.store_message_content(conversation, &id, wire)?;
                        self.record_authored_conversation_origin(identity)?;
                        self.account_db()?.persist_message_actor_state(
                            &id,
                            &format!("routed/generated-identity/{id}"),
                            identity,
                        )?;
                        if identity.group_id.is_some() {
                            use prost::Message as _;
                            self.account_db()?.persist_message_actor_state(
                                &id,
                                &format!("routed/group-projection/{id}"),
                                message,
                            )?;
                            self.account_db()?.persist_message_actor_state(
                                &id,
                                &format!("routed/group-content/{id}"),
                                &message.encode_to_vec(),
                            )?;
                        }
                    }
                    Ok::<_, SdkError>(())
                })?;
            }
            _ => return Err(invalid("unsupported authored conversation content")),
        }
        Ok(())
    }

    pub(crate) fn record_authored_conversation_origin(
        &self,
        identity: &g::EventIdentity,
    ) -> Result<(), SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        g::identity::verify(identity).map_err(|_| invalid("invalid authored identity"))?;
        let own = self.owned_device_identity()?;
        if identity.author.as_ref().is_none_or(|author| {
            author.account_anchor != own.root_commitment()
                || author.device_id != own.device_id()
                || self
                    .device_branch
                    .as_ref()
                    .is_none_or(|branch| author.device_epoch != branch.device_epoch)
        }) {
            return Err(invalid("authored origin differs from local identity"));
        }
        let id = ramflux_protocol::encode_base64url(&identity.id);
        let key = crate::client::delivery_receipts::origin_key(&identity.conversation_id, &id)?;
        self.account_db()?.persist_message_actor_state(
            &id,
            &key,
            &serde_json::json!({
                "sender_device_id": own.device_id(), "sender_root_commitment":own.root_commitment()
            }),
        )?;
        self.account_db()?.persist_message_actor_state(
            &id,
            &format!("routed/generated-identity/{id}"),
            identity,
        )?;
        Ok(())
    }

    pub(crate) fn wrap_conversation_group_reply(
        &self,
        identity: &g::EventIdentity,
        exact: &[u8],
    ) -> Result<Vec<u8>, SdkError> {
        let (source, content) = Self::decode_generated_inner(exact)?;
        if source != *identity {
            return Err(invalid("group reply identity mismatch"));
        }
        let group = identity.group_id.as_deref().ok_or_else(|| invalid("group absent"))?;
        let author = identity.author.clone().ok_or_else(|| invalid("author absent"))?;
        let Some(g::content::Value::Message(message)) = content.value else {
            return Err(invalid("reply Message absent"));
        };
        self.capture_own_authored_group(group, &author.device_id, exact)?;
        let wrapper = self.encrypt_generated_group_message(group, &author.device_id, &message)?;
        Self::encode_generated_inner(
            identity.clone(),
            &g::Content { value: Some(g::content::Value::Message(wrapper)) },
        )
    }
}
