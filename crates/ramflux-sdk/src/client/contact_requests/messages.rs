// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated message requests remain private until explicit consent; no live ratchets are retained.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
pub(crate) type HeldReference<'a> =
    (&'a crate::dm::SdkDmAttachmentRef, Option<crate::client::object::DeferredObjectKeySlot>);
#[derive(Deserialize, Serialize)]
struct Attachment {
    reference: crate::dm::SdkDmAttachmentRef,
    key: Option<Zeroizing<[u8; 32]>>,
}
#[derive(Deserialize, Serialize)]
struct Held {
    route: crate::client::routed::Routing,
    entry: GatewayInboxEntry,
    body: Zeroizing<Vec<u8>>,
    metadata: Option<MessageMetadata>,
    attachments: Vec<Attachment>,
}
impl RamfluxClient {
    pub(crate) fn hold_contact_routed_message(
        &self,
        route: &crate::client::routed::Routing,
        entry: &GatewayInboxEntry,
        body: &[u8],
        metadata: Option<&MessageMetadata>,
        references: Vec<HeldReference<'_>>,
    ) -> Result<(), SdkError> {
        let sender = self.authenticated_device_identity(entry)?;
        let request = self
            .account_db()?
            .contact_request(sender.root_commitment(), "inbound")?
            .ok_or_else(|| super::invalid("pending contact request is absent"))?;
        let attachments = references
            .into_iter()
            .map(|(reference, prepared)| Attachment {
                reference: reference.clone(),
                key: prepared.map(|slot| Zeroizing::new(slot.object_key)),
            })
            .collect();
        let held = Held {
            route: route.clone(),
            entry: entry.clone(),
            body: Zeroizing::new(body.to_vec()),
            metadata: metadata.cloned(),
            attachments,
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&held)?);
        // Full queues consume authenticated pair counters normally, then drop this item. They
        // cannot create an endless ratchet retry or force the account actor to stop.
        self.account_db()?.hold_contact_message(ramflux_storage::ContactMessageRequestWrite {
            sender: &sender,
            message_id: &route.message_id,
            conversation_id: &route.conversation_id,
            message_json: &bytes,
            expires_at: request.expires_at,
            created_at: entry.envelope.created_at,
        })?;
        Ok(())
    }
    pub(super) fn contact_message_preview(
        first: Option<&[u8]>,
    ) -> Result<Option<String>, SdkError> {
        let Some(first) = first else {
            return Ok(None);
        };
        let held: Held = serde_json::from_slice(first)?;
        let text = String::from_utf8_lossy(&held.body).chars().take(256).collect::<String>();
        Ok(Some(ramflux_protocol::text_safety::quote_fallback_field(&text)))
    }
    pub(super) fn release_contact_messages(&self, root: &str) -> Result<(), SdkError> {
        for bytes in self.account_db()?.held_contact_messages(root)? {
            let bytes = Zeroizing::new(bytes);
            let held: Held = serde_json::from_slice(&bytes)?;
            let outcome = self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
                let sender = self.authenticated_device_identity(&held.entry)?;
                if sender.root_commitment() != root {
                    return Err(super::invalid("held message root mismatch"));
                }
                for attachment in &held.attachments {
                    let prepared = attachment.key.as_ref().map(|key| {
                        crate::client::object::DeferredObjectKeySlot {
                            object_key: **key,
                            session: None,
                            conversation_id: held.route.conversation_id.clone(),
                            commit_label: "contact-request-accepted".into(),
                            pair_slot: None,
                            legacy_slot: None,
                        }
                    });
                    self.persist_sender_attachment_reference(
                        &attachment.reference,
                        sender.device_id(),
                        crate::client::deferred_attachment::ReferenceContext {
                            owner: &held.entry.envelope.source_principal_id,
                            conversation: &held.route.conversation_id,
                            message: &held.route.message_id,
                        },
                        prepared,
                    )?;
                }
                self.project_accepted_contact_message(
                    &held.route,
                    &held.entry,
                    &held.body,
                    held.metadata.as_ref(),
                )?;
                Ok(())
            });
            if let Err(error) = outcome {
                match error {
                    SdkError::Storage(
                        StorageError::AuthorizationRejected | StorageError::GroupPermissionDenied,
                    ) => {
                        tracing::debug!(%error,"unauthorized held application payload dropped on consent");
                    }
                    SdkError::Storage(_) | SdkError::Io(_) => return Err(error),
                    _ => {
                        tracing::debug!(%error,"invalid or revoked held message dropped on consent");
                    }
                }
            }
        }
        self.account_db()?.discard_contact_messages(root)?;
        Ok(())
    }
}
