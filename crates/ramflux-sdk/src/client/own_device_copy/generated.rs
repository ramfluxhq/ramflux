// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair-sealed `CONTROL_OWN_MESSAGE_COPY` envelopes, one per sibling (S10a P07b2 / audit M2).

use super::{OwnCopyDraft, invalid};
use crate::client::generated_content::GeneratedEventStream;
use crate::client::generated_control::control_from_payload;
use crate::client::identity_authority::NativeOperation;
use crate::client::routed::{Route, SendMaterial};
use crate::prelude::*;
use ramflux_protocol::message as g;
use ramflux_protocol::message::own_message_copy;

pub(crate) fn qualified(root: &str, device_id: &str, device_epoch: u64) -> g::QualifiedDevice {
    g::QualifiedDevice {
        account_anchor: root.to_owned(),
        device_id: device_id.to_owned(),
        device_epoch,
    }
}

impl RamfluxClient {
    pub(crate) fn seal_own_copy_generated(
        &self,
        config: &GatewaySessionConfig,
        mut draft: OwnCopyDraft,
        materials: Vec<SendMaterial>,
    ) -> Result<Vec<(String, ramflux_protocol::Envelope)>, SdkError> {
        if materials.len() != draft.messages.len() || draft.siblings.len() != draft.messages.len() {
            return Err(invalid("own-device material count mismatch"));
        }
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Sync)?;
        let body = zeroize::Zeroizing::new(draft.nested_body()?);
        let messages = std::mem::take(&mut draft.messages);
        let siblings = std::mem::take(&mut draft.siblings);
        let mut envelopes = Vec::with_capacity(messages.len());
        for (mut message, (material, sibling)) in
            messages.into_iter().zip(materials.into_iter().zip(siblings))
        {
            let recipient = Self::qualified_recipient(&message)?;
            self.require_native_operation(
                &self.device_identity(&recipient)?,
                NativeOperation::Sync,
            )?;
            message.conversation_id.clone_from(&draft.conversation);
            message.envelope_id = crate::new_surface_message_id()?;
            message.message_id.clone_from(&draft.packet.id);
            let inner = Self::encode_own_message_copy_inner(&draft, &sibling, &body)?;
            let sealed =
                self.seal_routed_prepared(config, &message, &inner, Route::control(), material)?;
            let envelope =
                crate::dm::gateway_envelope_from_sealed(config, &mut message, sealed, None)?;
            envelopes.push((sibling.device_id, envelope));
        }
        Ok(envelopes)
    }

    fn encode_own_message_copy_inner(
        draft: &OwnCopyDraft,
        sibling: &g::QualifiedDevice,
        body: &[u8],
    ) -> Result<Vec<u8>, SdkError> {
        let control =
            control_from_payload(g::control::Payload::OwnMessageCopy(g::OwnMessageCopy {
                source: Some(draft.source.clone()),
                target: Some(sibling.clone()),
                created_at: draft.created_at,
                expires_at: draft.expires_at,
                payload: Some(own_message_copy::Payload::Sent(g::OwnSentMessage {
                    envelope_id: draft.message_id.clone(),
                    message_id: draft.message_id.clone(),
                    sender_id: draft.source.device_id.clone(),
                    original_recipients: Vec::new(),
                    ciphertext_digest: None,
                    context: Some(g::OwnContext {
                        conversation_id: draft.conversation.clone(),
                        participants: Vec::new(),
                        group: None,
                        friend: None,
                    }),
                    authored_at: Some(draft.created_at),
                    exact_inner: body.to_vec(),
                })),
            }))?;
        let mut stream =
            GeneratedEventStream::new(draft.conversation.clone(), draft.source.clone());
        if let Some(group) = draft.group.as_deref() {
            stream = stream.with_group(group, 0);
        }
        Self::encode_generated_control(&mut stream, draft.message_id.as_bytes().to_vec(), control)
    }

    pub(crate) fn receive_generated_own_message_copy(
        &self,
        opened: &crate::client::routed::Opened,
        entry: &GatewayInboxEntry,
        copy: &g::OwnMessageCopy,
    ) -> Result<(), SdkError> {
        crate::client::generated_control::validate_control_operation(&g::Control {
            operation: 15,
            payload: Some(g::control::Payload::OwnMessageCopy(copy.clone())),
        })?;
        let local = self.owned_device_identity()?;
        let source = copy.source.as_ref().ok_or_else(|| invalid("own message copy source"))?;
        let target = copy.target.as_ref().ok_or_else(|| invalid("own message copy target"))?;
        if source.account_anchor != local.root_commitment()
            || target.account_anchor != local.root_commitment()
            || target.device_id != local.device_id()
        {
            return Err(invalid("own message copy requires same-root sibling authority"));
        }
        if source.device_id != entry.envelope.source_device_id {
            return Err(invalid("own message copy source device mismatch"));
        }
        let (id, nested, conversation, group) = match copy.payload.as_ref() {
            Some(own_message_copy::Payload::Sent(sent)) => (
                sent.message_id.as_str(),
                sent.exact_inner.as_slice(),
                sent.context.as_ref().map_or("", |ctx| ctx.conversation_id.as_str()),
                None,
            ),
            Some(own_message_copy::Payload::Item(item)) => (
                opened.routing.message_id.as_str(),
                item.exact_inner.as_slice(),
                opened.routing.conversation_id.as_str(),
                opened.routing.group_id.as_deref(),
            ),
            None => return Err(invalid("own message copy requires HistoryItem or OwnSentMessage")),
        };
        if conversation.is_empty() {
            return Err(invalid("own message copy conversation missing"));
        }
        let now = now_unix_timestamp();
        let source_identity =
            self.device_identity_for_root(source.account_anchor.as_str(), &source.device_id)?;
        self.require_native_operation(&local, NativeOperation::Sync)?;
        self.require_native_operation(&source_identity, NativeOperation::Sync)?;
        let principal =
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id.clone();
        let context = super::PrivateContext {
            message: id.to_owned(),
            principal,
            root: source.account_anchor.clone(),
            source: source.device_id.clone(),
            conversation: conversation.to_owned(),
            group: group.map(str::to_owned),
            created_at: copy.created_at,
            expires_at: copy.expires_at,
        };
        context.validate(
            &copy_id_for(&context.root, &context.source, &context.message)?,
            &context.principal,
            &context.root,
            &context.source,
            now,
        )?;
        let db = self.account_db()?;
        let replay_id = entry.envelope.envelope_id.as_str();
        let key = super::receipts::replay_key(db, &local, entry, replay_id)?;
        let wire_fingerprint = ramflux_protocol::hash_base64url(super::DOMAIN, nested);
        let fingerprint = super::receipts::packet_fingerprint(db, &wire_fingerprint)?;
        if super::receipts::committed(db, &key, &fingerprint, now)? {
            return Ok(());
        }
        super::receipts::remember(db, &key, &fingerprint, context.expires_at, false, now)?;
        let scope = self.apply_own_device_control(
            entry,
            &source_identity,
            &context,
            nested,
            local.device_id(),
        )?;
        self.persist_own_device_receipt(
            &format!("{}{replay_id}", super::RECEIPTS),
            &context,
            fingerprint,
            scope,
            &source_identity,
        )?;
        Ok(())
    }
}

impl OwnCopyDraft {
    fn nested_body(&self) -> Result<Vec<u8>, SdkError> {
        let key = &self.key;
        let (context, body) = self.packet.open(key)?;
        drop(context);
        Ok(body.to_vec())
    }
}

fn copy_id_for(root: &str, source: &str, message: &str) -> Result<String, SdkError> {
    super::copy_id(root, source, message)
}
