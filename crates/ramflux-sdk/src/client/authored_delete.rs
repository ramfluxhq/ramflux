// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Qualified Delete inputs are checked before allocating one retained authored event.
use crate::client::identity_authority::{HeadUse, NativeOperation};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;

pub(crate) struct DeleteDraft {
    pub(crate) original: g::EventIdentity,
    pub(crate) content: g::Content,
    pub(crate) operation: String,
}

fn refused(reason: &str) -> SdkError {
    SdkError::GeneratedRefused {
        code: crate::GeneratedRefusalCode::Content,
        reason: format!("authored Delete: {reason}"),
    }
}

impl RamfluxClient {
    pub(crate) fn delete_target_identity(
        &self,
        conversation: &str,
        message: &str,
    ) -> Result<g::EventIdentity, SdkError> {
        if conversation.is_empty() || conversation.len() > 256 || message.len() != 43 {
            return Err(refused("target requires a bounded conversation and canonical event id"));
        }
        let decoded = ramflux_protocol::decode_base64url(message)
            .map_err(|_| refused("target event id invalid"))?;
        if decoded.len() != 32 || ramflux_protocol::encode_base64url(decoded) != message {
            return Err(refused("target event id invalid"));
        }
        let identity = self
            .account_db()?
            .load_actor_state::<g::EventIdentity>(&format!("routed/generated-identity/{message}"))?
            .ok_or_else(|| refused("authenticated original metadata is unavailable"))?;
        if g::identity::verify(&identity).is_err()
            || identity.conversation_id != conversation
            || ramflux_protocol::encode_base64url(&identity.id) != message
        {
            return Err(refused("target differs from authenticated original metadata"));
        }
        Ok(identity)
    }

    pub(crate) fn authored_delete_draft(
        &self,
        conversation: &str,
        message: &str,
        operation: Option<&str>,
    ) -> Result<DeleteDraft, SdkError> {
        if operation.is_some_and(|token| token.is_empty() || token.len() > 256) {
            return Err(refused("operation token must be 1..256 bytes"));
        }
        let original = self.delete_target_identity(conversation, message)?;
        let author = original.author.as_ref().ok_or_else(|| refused("original author missing"))?;
        let delete = g::Delete {
            targets: vec![g::MessageRef {
                id: original.id.clone(),
                conversation_id: conversation.into(),
                author_anchor: author.account_anchor.clone(),
            }],
            scope: g::DeleteScope::Everyone.into(),
            tombstone_id: Vec::new(),
            native_group_authorization: Vec::new(),
        };
        self.validate_authored_delete(&delete, conversation)?;
        // This is a local retry token. The event identifier and its tombstone are
        // allocated from the qualified event stream after recipient admission.
        let operation = ramflux_protocol::hash_base64url(
            "ramflux.message.delete-operation.v1",
            &ramflux_protocol::canonical_json_bytes(&(message, conversation, operation))?,
        );
        Ok(DeleteDraft {
            original,
            content: g::Content { value: Some(g::content::Value::Delete(delete)) },
            operation,
        })
    }

    pub(crate) fn validate_authored_delete(
        &self,
        delete: &g::Delete,
        conversation: &str,
    ) -> Result<(), SdkError> {
        if delete.targets.is_empty()
            || delete.targets.len() > 256
            || delete.scope != g::DeleteScope::Everyone as i32
            || !delete.tombstone_id.is_empty()
            || !delete.native_group_authorization.is_empty()
        {
            return Err(refused(
                "peer Delete requires targets and EVERYONE; tombstones are derived",
            ));
        }
        let own = self.owned_device_identity()?;
        self.trusted_device(HeadUse::NewAuthorization, &own)?;
        for target in &delete.targets {
            let id = ramflux_protocol::encode_base64url(&target.id);
            let original = self.delete_target_identity(conversation, &id)?;
            let author =
                original.author.as_ref().ok_or_else(|| refused("original author missing"))?;
            if target.conversation_id != conversation
                || target.author_anchor != author.account_anchor
            {
                return Err(refused("target author or conversation differs from original"));
            }
            if let Some(group) = original.group_id.as_deref() {
                self.require_native_operation(&own, NativeOperation::Group)?;
                let state = self
                    .account_db()?
                    .shared_group_state(group)?
                    .ok_or_else(|| refused("verified group state missing"))?;
                if target.author_anchor != own.root_commitment()
                    && !matches!(
                        state.view().effective_role(own.root_commitment(), own.device_id()),
                        Some(
                            ramflux_protocol::SharedGroupRole::Owner
                                | ramflux_protocol::SharedGroupRole::Admin
                        )
                    )
                {
                    return Err(SdkError::GeneratedRefused {
                        code: crate::GeneratedRefusalCode::Authority,
                        reason: "only the authenticated author or a current group moderator may delete for everyone".into(),
                    });
                }
                self.require_generated_group_epoch(
                    group,
                    &own,
                    state.view().epoch,
                    target.author_anchor != own.root_commitment(),
                )?;
            } else if target.author_anchor != own.root_commitment() {
                return Err(SdkError::GeneratedRefused {
                    code: crate::GeneratedRefusalCode::Authority,
                    reason:
                        "only the authenticated author may delete a direct message for everyone"
                            .into(),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn project_authored_delete(
        &self,
        message: &crate::GatewayDirectMessage,
        identity: &g::EventIdentity,
        delete: &g::Delete,
        exact: &[u8],
    ) -> Result<(), SdkError> {
        let source = self.owned_device_identity()?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            let event_id = ramflux_protocol::encode_base64url(&identity.id);
            let staged = format!("delete-send/own-staged/{event_id}");
            if !db.actor_state_exists(&staged)? {
                let recipients = if let Some(group) = identity.group_id.as_deref() {
                    self.group_state(group)?.members.into_iter().collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                let peer = if identity.group_id.is_none() {
                    Some(self.own_sent_peer(message)?)
                } else {
                    None
                };
                self.stage_authored_mutation_copy(crate::client::own_sent_message::OwnSentInput {
                    envelope: &message.envelope_id,
                    conversation: &identity.conversation_id,
                    message: &event_id,
                    sender: &message.sender_id,
                    original_recipients: &recipients,
                    group: identity.group_id.as_deref(),
                    peer: peer.as_deref(),
                    body: exact,
                    ciphertext: &[],
                    at: message.created_at,
                })?;
                db.persist_message_actor_state(&event_id, &staged, &true)?;
            }
            self.apply_generated_delete_authorized(
                &source,
                identity,
                &identity.conversation_id,
                delete,
            )?;
            self.journal_generated_receive_updates(exact)
        })
    }
}
