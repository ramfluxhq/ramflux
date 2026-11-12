// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair-sealed `CONTROL_OWN_MESSAGE_COPY` envelopes, one per sibling (S10a P07b2 / audit M2).

use super::{OwnCopyDraft, invalid};
use crate::client::generated_control::control_from_payload;
use crate::client::identity_authority::NativeOperation;
use crate::client::routed::{Route, SendMaterial};
use crate::prelude::*;
use prost::Message as _;
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
        draft: OwnCopyDraft,
        materials: Vec<SendMaterial>,
    ) -> Result<Vec<(String, ramflux_protocol::Envelope)>, SdkError> {
        self.account_db()?
            .write_transaction(|| self.seal_own_copy_generated_in(config, draft, materials))
    }

    fn seal_own_copy_generated_in(
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
        let identity = self.allocate_generated_identity(
            &draft.conversation,
            crate::client::generated_identity::now_ms(),
            true,
        )?;
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
            message.message_id = ramflux_protocol::encode_base64url(&identity.id);
            let inner =
                self.encode_own_message_copy_inner(&draft, &sibling, &body, identity.clone())?;
            let sealed = self.seal_generated_routed_prepared(
                config,
                &message,
                &inner,
                Route::control(),
                material,
            )?;
            let envelope =
                crate::dm::gateway_generated_envelope_from_sealed(config, &mut message, sealed)?;
            envelopes.push((sibling.device_id, envelope));
        }
        Ok(envelopes)
    }

    fn encode_own_message_copy_inner(
        &self,
        draft: &OwnCopyDraft,
        sibling: &g::QualifiedDevice,
        body: &[u8],
        identity: g::EventIdentity,
    ) -> Result<Vec<u8>, SdkError> {
        let payload = if let Some(sent) =
            crate::client::own_sent_message::generated_own_sent_from_prefix(body)?
        {
            own_message_copy::Payload::Sent(sent)
        } else {
            let inner =
                g::Inner::decode(body).map_err(|_| invalid("own copy requires exact Inner"))?;
            let target = if inner.kind == 3 {
                g::Edit::decode(inner.body.as_slice())
                    .map_err(|_| invalid("own copy Edit missing"))?
                    .target
                    .ok_or_else(|| invalid("own copy Edit target missing"))?
                    .id
            } else {
                inner.identity.ok_or_else(|| invalid("own copy original identity missing"))?.id
            };
            let item = self.export_generated_history_item(&target)?;
            if item.exact_inner != body {
                return Err(g::original_header::EvidenceError::ReportOpeningRetired.into());
            }
            own_message_copy::Payload::Item(item)
        };
        let control =
            control_from_payload(g::control::Payload::OwnMessageCopy(g::OwnMessageCopy {
                source: Some(draft.source.clone()),
                target: Some(sibling.clone()),
                created_at: draft.created_at,
                expires_at: draft.expires_at,
                payload: Some(payload),
            }))?;
        Self::encode_generated_inner(
            identity,
            &g::Content { value: Some(g::content::Value::Control(control)) },
        )
    }

    pub(crate) fn receive_generated_own_message_copy(
        &self,
        opened: &crate::client::routed::Opened,
        entry: &GatewayInboxEntry,
        copy: &g::OwnMessageCopy,
    ) -> Result<(), SdkError> {
        self.authorize_generated_own_message_copy(opened, entry, copy)?;
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
        let generated = generated_copy_parts(opened, copy)?;
        if generated.conversation.is_empty() {
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
            message: generated.id.to_owned(),
            principal,
            root: source.account_anchor.clone(),
            source: source.device_id.clone(),
            conversation: generated.conversation.to_owned(),
            group: generated.group.map(str::to_owned),
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
        // Transport replay uses the authenticated randomized ciphertext claim, never a
        // retained hash of a copied plaintext body after that body's erase lifetime.
        let wire_fingerprint = entry.envelope.payload_hash.clone();
        let fingerprint = super::receipts::packet_fingerprint(db, &wire_fingerprint)?;
        if super::receipts::committed(db, &key, &fingerprint, now)? {
            return Ok(());
        }
        super::receipts::remember(db, &key, &fingerprint, context.expires_at, false, now)?;
        let scope = if let Some(sent) = generated.sent {
            let applied =
                self.receive_generated_own_sent(entry, &source_identity, copy.created_at, sent)?;
            if !applied {
                return Err(invalid("own sent message context mismatch"));
            }
            self.retain_received_own_sent_attestation(opened, entry, sent)?;
            super::ReceiptScope::Private {
                private_scope: db.own_sent_receipt_scope(&context.source, local.device_id())?,
            }
        } else if let Some(own_message_copy::Payload::Item(item)) = copy.payload.as_ref()
            && (item.original_metadata_evidence.is_some()
                || !item.exact_original_identity.is_empty()
                || g::Inner::decode(item.exact_inner.as_slice()).is_ok_and(|inner| inner.kind == 3))
        {
            self.apply_generated_history_edit(entry, item)?;
            super::ReceiptScope::Private {
                private_scope: db.own_sent_receipt_scope(&context.source, local.device_id())?,
            }
        } else if let Some(own_message_copy::Payload::Item(item)) = copy.payload.as_ref() {
            let nested = g::Inner::decode(item.exact_inner.as_slice())
                .map_err(|_| invalid("own history Inner missing"))?;
            if nested
                .identity
                .as_ref()
                .is_none_or(|identity| identity.conversation_id != generated.conversation)
            {
                return Err(invalid("own history conversation differs from control"));
            }
            self.import_generated_history_message(&source_identity, item)?;
            super::ReceiptScope::Private {
                private_scope: db.own_sent_receipt_scope(&context.source, local.device_id())?,
            }
        } else {
            return Err(invalid("own message copy payload missing"));
        };
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

struct GeneratedCopyParts<'a> {
    id: &'a str,
    conversation: &'a str,
    group: Option<&'a str>,
    sent: Option<&'a g::OwnSentMessage>,
}

fn generated_copy_parts<'a>(
    opened: &'a crate::client::routed::Opened,
    copy: &'a g::OwnMessageCopy,
) -> Result<GeneratedCopyParts<'a>, SdkError> {
    match copy.payload.as_ref() {
        Some(own_message_copy::Payload::Sent(sent)) => Ok(GeneratedCopyParts {
            id: sent.envelope_id.as_str(),
            conversation: sent.context.as_ref().map_or("", |ctx| ctx.conversation_id.as_str()),
            group: sent
                .context
                .as_ref()
                .and_then(|ctx| ctx.group.as_ref())
                .map(|group| group.group_id.as_str()),
            sent: Some(sent),
        }),
        Some(own_message_copy::Payload::Item(_)) => Ok(GeneratedCopyParts {
            id: opened.routing.message_id.as_str(),
            conversation: opened.routing.conversation_id.as_str(),
            group: opened.routing.group_id.as_deref(),
            sent: None,
        }),
        None => Err(invalid("own message copy requires HistoryItem or OwnSentMessage")),
    }
}
