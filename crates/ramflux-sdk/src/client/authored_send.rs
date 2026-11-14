// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One durable identity and private revision per local send operation, before recipient fan-out.
use super::identity_authority::HeadUse;
use crate::{GatewayDirectMessage, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct PreparedMessage {
    pub(crate) exact: Vec<u8>,
    pub(crate) wire: Vec<u8>,
    pub(crate) created_at: i64,
    // Public transport identifiers contain no plaintext/key material.
    #[zeroize(skip)]
    pub(crate) envelope_ids: std::collections::BTreeMap<String, String>,
    pub(crate) ttl: u32,
}

fn refused(reason: &str) -> SdkError {
    SdkError::InboundRejected(format!("authored message: {reason}"))
}

impl RamfluxClient {
    pub(crate) fn validate_user_authored_content(
        &self,
        content: &g::Content,
        conversation: &str,
    ) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        match content.value.as_ref() {
            Some(g::content::Value::Message(value))
                if value.erasure_nonce.is_empty() && value.sealed_group.is_none() =>
            {
                Self::attachment_message_content(&value.text, &value.media)?;
                Ok(())
            }
            Some(g::content::Value::Delete(delete)) => {
                self.validate_authored_delete(delete, conversation)
            }
            Some(g::content::Value::Surface(surface)) => {
                let Some(g::surface::Payload::Delivery(delivery)) = surface.payload.as_ref() else {
                    return Err(refused("user Surface requires a peer delivery"));
                };
                let control = super::surface::SurfaceControl::from_generated(delivery)?;
                if control.kind != super::surface::ControlKind::Peer
                    || control.context.is_some()
                    || !control.manifests.is_empty()
                {
                    return Err(refused("user Surface cannot carry own-device authority"));
                }
                let value =
                    delivery.carrier.as_ref().ok_or_else(|| refused("Surface carrier missing"))?;
                let carrier = super::surface::Carrier::from_generated(value)?;
                if carrier.conversation_id != conversation {
                    return Err(refused("Surface conversation mismatch"));
                }
                self.verify_surface_carrier(&carrier, &local.principal_id, &local.device_id)?;
                Ok(())
            }
            Some(g::content::Value::Task(task)) => {
                let Some(g::task::Payload::Carrier(value)) = task.payload.as_ref() else {
                    return Err(refused("user Task requires a carrier"));
                };
                let carrier = super::task::carrier::Carrier::from_generated(value)?;
                if carrier.conversation_id != conversation
                    || carrier.principal_id != local.principal_id
                    || carrier.device_id != local.device_id
                {
                    return Err(refused("Task source or conversation mismatch"));
                }
                carrier.verify(&self.task_signer_key(&local.principal_id, &local.device_id)?)?;
                Ok(())
            }
            _ => Err(refused(
                "user content requires Message, Delete, Surface delivery or Task carrier",
            )),
        }
    }

    /// Local operation tokens are not event identities. A retry reuses the retained exact
    /// revision; an erased operation never allocates another identity or regenerates entropy.
    #[cfg(test)]
    pub(crate) fn prepare_authored_message(
        &self,
        message: &mut GatewayDirectMessage,
        group: Option<&str>,
        content: &g::Message,
    ) -> Result<PreparedMessage, SdkError> {
        self.prepare_authored_content(
            message,
            group,
            &g::Content { value: Some(g::content::Value::Message(content.clone())) },
        )
    }

    fn validate_authored_source(
        &self,
        message: &GatewayDirectMessage,
        group: Option<&str>,
        content: &g::Content,
    ) -> Result<(ramflux_crypto::RootQualifiedDeviceRef, bool, u32), SdkError> {
        if message.message_id.is_empty() || message.message_id.len() > 256 {
            return Err(refused("operation token must be 1..256 bytes"));
        }
        if matches!(content.value.as_ref(), Some(g::content::Value::Message(value)) if !value.erasure_nonce.is_empty() || value.sealed_group.is_some())
        {
            return Err(refused("caller cannot choose private revision entropy or a sealed group"));
        }
        if let Some(g::content::Value::Message(value)) = content.value.as_ref() {
            Self::attachment_message_content(&value.text, &value.media)?;
        }
        let own = self.owned_device_identity()?;
        if message.sender_id != own.device_id() {
            return Err(refused("sender differs from the local device"));
        }
        if let Some(g::content::Value::Delete(delete)) = content.value.as_ref() {
            self.validate_authored_delete(delete, &message.conversation_id)?;
            for target in &delete.targets {
                let original = self.delete_target_identity(
                    &message.conversation_id,
                    &ramflux_protocol::encode_base64url(&target.id),
                )?;
                if original.group_id.as_deref() != group {
                    return Err(refused("Delete route differs from original group scope"));
                }
            }
        }
        self.require_backup_outbound_ready()?;
        self.current_custody_authority(own.root_commitment(), crate::custody::network_now()?)?
            .ok_or(SdkError::NetworkingPending)?;
        let own_only = message.recipient_principal_commitment.as_deref()
            == Some(own.root_commitment())
            && !matches!(content.value, Some(g::content::Value::Message(_)));
        if group.is_none() && !own_only {
            let peer = self.device_identity(&Self::qualified_recipient(message)?)?;
            let expected = self.generated_direct_conversation_id(&peer)?;
            if message.conversation_id != expected {
                return Err(refused("ordinary DM requires its canonical root-pair conversation"));
            }
        }
        let required_layer = Self::required_content_layer(content)?;
        if required_layer > g::registry::PROFILE_FLOOR {
            let plan = if let Some(group) = group {
                Self::candidate_target_plan(|| {
                    self.group_selection_request(
                        group,
                        &message.sender_id,
                        &message.message_id,
                        g::KindId::KindMessage,
                    )
                })?
            } else {
                Self::candidate_target_plan(|| {
                    self.dm_selection_request(message, g::KindId::KindMessage)
                })?
            };
            super::target_selection::require_layer(plan, required_layer)?;
        }
        Ok((own, own_only, required_layer))
    }

    fn authored_operation_keys(
        &self,
        message: &GatewayDirectMessage,
        group: Option<&str>,
        own: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(String, String), SdkError> {
        let operation = format!(
            "message-send/operation/{}",
            ramflux_crypto::blake3_256_base64url(
                "ramflux.sdk.message-send.operation.v1",
                &ramflux_protocol::canonical_json_bytes(&(
                    own.storage_key(),
                    self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_epoch,
                    &message.conversation_id,
                    group,
                    &message.message_id,
                ))?,
            )
        );
        let transport = ramflux_protocol::hash_base64url(
            "ramflux.message.send-target.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &message.recipient_principal_commitment,
                &message.recipient_device_id,
                &message.target_delivery_id,
            ))?,
        );
        Ok((operation, transport))
    }

    fn ensure_authored_direct_context(
        &self,
        message: &GatewayDirectMessage,
        own: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        let Some(peer_root) = message.recipient_principal_commitment.as_deref() else {
            return Err(refused("recipient root missing"));
        };
        if peer_root == own.root_commitment() {
            return Ok(());
        }
        let canonical = g::dm_scope::derive(own.root_commitment(), peer_root)
            .map_err(|_| refused("invalid authored root pair"))?;
        if canonical != message.conversation_id {
            return Err(refused("authored conversation scope differs"));
        }
        let db = self.account_db()?;
        if db.client_record("conversation", &canonical)?.is_some() {
            return Ok(());
        }
        let peer = self.device_identity(&Self::qualified_recipient(message)?)?;
        let record = self.trusted_device(HeadUse::NewAuthorization, &peer)?;
        let principal = record
            .get("principal_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| refused("recipient principal missing"))?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        // Bind local UI context from the verified recipient before own-history capture.
        // This grants no contact consent or peer authority.
        db.persist_client_record(
            "conversation",
            &canonical,
            &serde_json::json!({
                "id": canonical, "kind":"direct", "group_id":null,
                "participants":[local.principal_id, principal],
                "participant_roots":[own.root_commitment(), peer_root],
            }),
        )?;
        Ok(())
    }

    pub(crate) fn prepare_authored_content(
        &self,
        message: &mut GatewayDirectMessage,
        group: Option<&str>,
        content: &g::Content,
    ) -> Result<PreparedMessage, SdkError> {
        let (own, own_only, required_layer) =
            self.validate_authored_source(message, group, content)?;
        let (operation, transport) = self.authored_operation_keys(message, group, &own)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            if group.is_none() {
                self.ensure_authored_direct_context(message, &own)?;
            }
            if let Some(id) = db.load_actor_state::<String>(&operation)? {
                let mut prepared = db
                    .load_actor_state::<PreparedMessage>(&format!("message-send/prepared/{id}"))?
                    .ok_or_else(|| refused("operation content was retired"))?;
                let (identity, mut retained) = Self::decode_generated_inner(&prepared.exact)?;
                if let Some(g::content::Value::Message(value)) = retained.value.as_mut() {
                    value.erasure_nonce.clear();
                }
                if let Some(g::content::Value::Delete(delete)) = retained.value.as_mut() {
                    delete.tombstone_id.clear();
                }
                if let Some(group) = group {
                    let state = db
                        .shared_group_state(group)?
                        .ok_or_else(|| refused("group state missing"))?;
                    if identity.group_epoch != Some(state.view().epoch) {
                        return Err(refused("group epoch changed; use a fresh operation token"));
                    }
                }
                if &retained != content {
                    return Err(SdkError::ReplayMismatch);
                }
                message.message_id.clone_from(&id);
                message.created_at = prepared.created_at;
                self.reuse_authored_transport(message, &mut prepared, &transport, content)?;
                message.ttl = prepared.ttl;
                return Ok(prepared);
            }
            let mut identity = self.allocate_generated_identity(
                &message.conversation_id,
                super::generated_identity::now_ms(),
                own_only,
            )?;
            if let Some(group) = group {
                let state =
                    db.shared_group_state(group)?.ok_or_else(|| refused("group state missing"))?;
                if state.view().conversation_id != message.conversation_id {
                    return Err(refused("group conversation differs from its verified state"));
                }
                identity.group_id = Some(group.into());
                identity.group_epoch = Some(state.view().epoch);
            }
            let id = ramflux_protocol::encode_base64url(&identity.id);
            let mut allocated = content.clone();
            if let Some(g::content::Value::Delete(delete)) = allocated.value.as_mut() {
                delete.tombstone_id = g::identity::delete_tombstone(&identity.id)
                    .map_err(|_| refused("Delete identity invalid"))?
                    .to_vec();
            }
            let exact = Self::encode_generated_inner(identity.clone(), &allocated)?;
            message.message_id.clone_from(&id);
            let wire = if let Some(group) = group
                && matches!(content.value, Some(g::content::Value::Message(_)))
            {
                self.capture_own_authored_group(group, &message.sender_id, &exact)?;
                let (_, content) = Self::decode_generated_inner(&exact)?;
                let Some(g::content::Value::Message(content)) = content.value else {
                    return Err(refused("prepared group content is not a Message"));
                };
                let sealed =
                    self.encrypt_generated_group_message(group, &message.sender_id, &content)?;
                Self::encode_generated_inner_at_layer(
                    identity,
                    &g::Content { value: Some(g::content::Value::Message(sealed)) },
                    required_layer,
                )?
            } else {
                exact.clone()
            };
            let prepared = PreparedMessage {
                exact,
                wire,
                created_at: message.created_at,
                ttl: message.ttl,
                envelope_ids: [(transport.clone(), message.envelope_id.clone())].into(),
            };
            // The alias contains no payload fingerprint. The exact bytes are erased with
            // their message, while the alias prevents resurrection by operation-token reuse.
            let owner = Self::prepared_message_owner(content, &id);
            db.persist_message_actor_state(
                &owner,
                &format!("message-send/prepared/{id}"),
                &prepared,
            )?;
            db.persist_actor_state(&operation, &id)?;
            Ok(prepared)
        })
    }

    fn reuse_authored_transport(
        &self,
        message: &mut GatewayDirectMessage,
        prepared: &mut PreparedMessage,
        transport: &str,
        content: &g::Content,
    ) -> Result<(), SdkError> {
        if let Some(envelope) = prepared.envelope_ids.get(transport) {
            message.envelope_id.clone_from(envelope);
        } else {
            if prepared.envelope_ids.len() >= 4096 {
                return Err(SdkError::PayloadTooLarge);
            }
            if prepared.envelope_ids.values().any(|envelope| envelope == &message.envelope_id) {
                message.envelope_id = ramflux_protocol::hash_base64url(
                    "ramflux.message.send-target.envelope.v1",
                    &ramflux_protocol::canonical_json_bytes(&(&message.message_id, transport))?,
                );
            }
            prepared.envelope_ids.insert(transport.to_owned(), message.envelope_id.clone());
            let owner = Self::prepared_message_owner(content, &message.message_id);
            self.account_db()?.persist_message_actor_state(
                &owner,
                &format!("message-send/prepared/{}", message.message_id),
                prepared,
            )?;
        }
        Ok(())
    }

    fn prepared_message_owner(content: &g::Content, id: &str) -> String {
        match content.value.as_ref() {
            Some(g::content::Value::Receipt(receipt)) => receipt.targets.first().map_or_else(
                || id.to_owned(),
                |target| ramflux_protocol::encode_base64url(&target.id),
            ),
            _ => id.to_owned(),
        }
    }

    pub(crate) fn project_authored_message(
        &self,
        message: &GatewayDirectMessage,
        exact: &[u8],
        encrypted: &[u8],
    ) -> Result<(), SdkError> {
        let inner = g::Inner::decode(exact).map_err(|_| refused("exact Inner missing"))?;
        let identity = inner.identity.ok_or_else(|| refused("exact identity missing"))?;
        if message.message_id != ramflux_protocol::encode_base64url(&identity.id)
            || message.conversation_id != identity.conversation_id
        {
            return Err(refused("projection identity differs from prepared operation"));
        }
        let own = self.owned_device_identity()?;
        if message.sender_id != own.device_id()
            || identity.author.as_ref().is_none_or(|author| {
                author.account_anchor != own.root_commitment()
                    || author.device_id != own.device_id()
            })
        {
            return Err(refused("projection author differs from the owned device"));
        }
        if inner.kind == 4 {
            let delete = g::Delete::decode(inner.body.as_slice())
                .map_err(|_| refused("authored Delete body invalid"))?;
            return self.project_authored_delete(message, &identity, &delete, exact);
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            if db.message_is_deleted(&message.message_id)? {
                return Err(refused("message was erased"));
            }
            if let Some(previous) = db.direct_message_by_id(&message.message_id)? {
                if previous.conversation_id != message.conversation_id
                    || previous.sender_id != message.sender_id
                    || db.message_content(&message.message_id)?.as_deref() != Some(exact)
                {
                    return Err(SdkError::ReplayMismatch);
                }
            } else {
                db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
                    conversation_id: &message.conversation_id,
                    message_id: &message.message_id,
                    sender_id: &message.sender_id,
                    encrypted_body: encrypted,
                    metadata: &ramflux_storage::MessageMetadata::default(),
                    created_at: message.created_at,
                })?;
            }
            let own = self.owned_device_identity()?;
            if identity.group_id.is_none() {
                self.ensure_authored_direct_context(message, &own)?;
            }
            db.store_message_content(&message.conversation_id, &message.message_id, exact)?;
            for (prefix, value) in [
                ("routed/generated-order/", identity.hlc),
                ("routed/generated-display-hlc/", identity.hlc),
            ] {
                db.persist_message_actor_state(
                    &message.message_id,
                    &format!("{prefix}{}", message.message_id),
                    &value,
                )?;
            }
            db.persist_message_actor_state(
                &message.message_id,
                &format!("routed/generated-identity/{}", message.message_id),
                &identity,
            )?;
            db.mark_generated_message_owned(&message.message_id, &own)?;
            db.persist_message_actor_state(
                &message.message_id,
                &super::delivery_receipts::origin_key(
                    &message.conversation_id,
                    &message.message_id,
                )?,
                &serde_json::json!({
                    "direction": "outgoing", "sender_device_id": own.device_id(),
                    "sender_root_commitment": own.root_commitment(),
                    "sender_device_display": own.storage_key(), "envelope_id": message.envelope_id,
                }),
            )?;
            self.clear_self_sync_draft_after_send(&message.conversation_id)?;
            self.journal_generated_receive_updates(exact)
        })
    }
}
