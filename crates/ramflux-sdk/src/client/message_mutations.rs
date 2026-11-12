// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant Edit/Delete/Reaction authorization and layer admission (S10a P14).
//! This module neither sends a carrier nor admits a stored event.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message::registry::{COMPILED_LAYER, kind_binding};
use ramflux_protocol::message::{DeleteScope, KindId};

/// OV-EDIT-DIGEST transcript over the canonical target and exact content in force.
/// # Errors
/// Refuses malformed references, unsupported stored content and oversized fields.
pub fn previous_content_digest(
    target: &ramflux_protocol::message::MessageRef,
    stored_inner: &[u8],
) -> Result<[u8; 32], SdkError> {
    let exact = ramflux_protocol::message::exact_content::message_in_force(stored_inner)
        .map_err(|_| refused("stored message has no exact editable content"))?;
    digest_exact_content(target, exact)
}

pub(crate) fn digest_exact_content(
    target: &ramflux_protocol::message::MessageRef,
    exact: &[u8],
) -> Result<[u8; 32], SdkError> {
    if target.id.is_empty() || target.conversation_id.is_empty() || target.author_anchor.is_empty()
    {
        return Err(refused("edit target is not source-qualified"));
    }
    let mut transcript = Vec::new();
    for field in [
        ramflux_protocol::domain::EDIT_PREVIOUS_CONTENT.as_bytes(),
        target.id.as_slice(),
        target.conversation_id.as_bytes(),
        target.author_anchor.as_bytes(),
        exact,
    ] {
        let length =
            u32::try_from(field.len()).map_err(|_| refused("edit digest input too large"))?;
        transcript.extend_from_slice(&length.to_be_bytes());
        transcript.extend_from_slice(field);
    }
    Ok(*blake3::hash(&transcript).as_bytes())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EditRegister {
    revision: u64,
    event_id: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(crate) struct EditContext<'a> {
    pub entry: &'a crate::GatewayInboxEntry,
    pub source: &'a ramflux_crypto::RootQualifiedDeviceRef,
    pub imported: Option<&'a ramflux_protocol::message::HistoryItem>,
    pub own_sent: bool,
}

impl RamfluxClient {
    /// Apply a generated Delete after transport/source authentication.
    /// # Errors
    /// Refuses foreign LOCAL scope, forged authors and unsupported moderator proofs.
    pub fn apply_generated_delete_entry(
        &self,
        entry: &crate::GatewayInboxEntry,
        identity: &ramflux_protocol::message::EventIdentity,
        conversation: &str,
        delete: &ramflux_protocol::message::Delete,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            entry,
        )?;
        self.apply_generated_delete_authorized(&source, identity, conversation, delete)
    }

    /// The caller has verified the original source evidence; historical author authority
    /// survives revocation. LOCAL and moderator effects still require current permission.
    pub(crate) fn apply_generated_delete_authorized(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        identity: &ramflux_protocol::message::EventIdentity,
        conversation: &str,
        delete: &ramflux_protocol::message::Delete,
    ) -> Result<(), SdkError> {
        Self::verify_delete_authority(source, identity, conversation, delete)?;
        let scope =
            DeleteScope::try_from(delete.scope).map_err(|_| refused("delete scope invalid"))?;
        if delete.targets.is_empty()
            || delete.tombstone_id.is_empty()
            || scope == DeleteScope::Unspecified
        {
            return Err(SdkError::InboundRejected(
                "delete targets, scope and tombstone are required".into(),
            ));
        }
        if scope == DeleteScope::Local {
            self.require_native_operation(
                source,
                crate::client::identity_authority::NativeOperation::Sync,
            )?;
            self.require_native_operation(
                &self.owned_device_identity()?,
                crate::client::identity_authority::NativeOperation::Sync,
            )?;
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            for target in &delete.targets {
                let id = ramflux_protocol::encode_base64url(&target.id);
                if target.conversation_id != conversation {
                    return Err(SdkError::InboundRejected("delete conversation mismatch".into()));
                }
                if db.message_is_deleted(&id)? {
                    continue;
                }
                let row = self.direct_message_by_id(&id)?;
                let author = if let Some(row) = row.as_ref() {
                    let author = self.generated_target_author(conversation, &id, row.is_own)?;
                    if row.conversation_id != conversation || author != target.author_anchor {
                        return Err(SdkError::InboundRejected(
                            "delete target author mismatch".into(),
                        ));
                    }
                    author
                } else {
                    target.author_anchor.clone()
                };
                let mut moderator = None;
                let allowed = match scope {
                    DeleteScope::Local => source.root_commitment() == self.own_account_anchor()?,
                    DeleteScope::Everyone if source.root_commitment() == author => true,
                    DeleteScope::Everyone => {
                        if let (Some(group), Some(epoch)) =
                            (identity.group_id.as_ref(), identity.group_epoch)
                        {
                            self.require_generated_group_epoch(group, source, epoch, true)?;
                            moderator = Some(crate::client::generated_delete_fence::Moderator {
                                group: group.clone(),
                                epoch,
                                device: source.storage_key().into(),
                            });
                            true
                        } else {
                            false
                        }
                    }
                    DeleteScope::Unspecified => false,
                };
                if !allowed {
                    return Err(SdkError::InboundRejected(
                        "delete sender has no target authority".into(),
                    ));
                }
                let fence = crate::client::generated_delete_fence::Fence {
                    conversation: conversation.into(),
                    target: target.clone(),
                    source_root: source.root_commitment().into(),
                    source_device: source.storage_key().into(),
                    scope: delete.scope,
                    tombstone_id: delete.tombstone_id.clone(),
                    matched: row.is_some(),
                    moderator,
                    identity: db.load_actor_state(&format!("routed/generated-identity/{id}"))?,
                };
                self.install_generated_delete_fence(&fence)?;
                if row.is_some() {
                    db.delete_direct_message(
                        conversation,
                        &id,
                        if scope == DeleteScope::Local { "local" } else { "everyone" },
                        &ramflux_protocol::encode_base64url(&delete.tombstone_id),
                    )?;
                }
            }
            Ok(())
        })
    }

    fn verify_delete_authority(
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        identity: &ramflux_protocol::message::EventIdentity,
        conversation: &str,
        delete: &ramflux_protocol::message::Delete,
    ) -> Result<(), SdkError> {
        use ramflux_protocol::message as g;
        if g::identity::verify(identity).is_err()
            || identity.conversation_id != conversation
            || identity.author.as_ref().is_none_or(|author| {
                author.account_anchor != source.root_commitment()
                    || author.device_id != source.device_id()
            })
            || !delete.native_group_authorization.is_empty()
            || delete.tombstone_id.as_slice()
                != g::identity::delete_tombstone(&identity.id)
                    .map_err(|_| refused("Delete identity invalid"))?
        {
            return Err(refused("Delete identity or authority mismatch"));
        }
        Ok(())
    }

    fn generated_target_author(
        &self,
        conversation: &str,
        id: &str,
        own: bool,
    ) -> Result<String, SdkError> {
        if own {
            return self.own_account_anchor();
        }
        self.message_origin(conversation, id)?
            .and_then(|origin| origin["sender_root_commitment"].as_str().map(str::to_owned))
            .ok_or_else(|| refused("mutation target has no authenticated origin"))
    }

    /// Apply an authenticated edit using the exact received replacement bytes.
    /// # Errors
    /// Refuses forged authors/targets. Revisions converge by their event-id tie break;
    /// the previous-content digest detects forks and does not reject a greater edit.
    pub fn apply_generated_edit_entry(
        &self,
        entry: &crate::GatewayInboxEntry,
        conversation: &str,
        exact_inner: &[u8],
    ) -> Result<bool, SdkError> {
        self.apply_generated_edit_with_metadata(entry, conversation, exact_inner, None)
    }

    pub(crate) fn apply_generated_edit_with_metadata(
        &self,
        entry: &crate::GatewayInboxEntry,
        conversation: &str,
        exact_inner: &[u8],
        metadata: Option<&ramflux_storage::MessageMetadata>,
    ) -> Result<bool, SdkError> {
        let source = self.authenticated_device_identity(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            entry,
        )?;
        self.apply_generated_edit_authorized(
            EditContext { entry, source: &source, imported: None, own_sent: false },
            conversation,
            exact_inner,
            metadata,
        )
    }

    fn park_waiting_generated_edit(
        &self,
        context: EditContext<'_>,
        identity: &ramflux_protocol::message::EventIdentity,
        edit: &ramflux_protocol::message::Edit,
        bytes: &[u8],
    ) -> Result<(), SdkError> {
        if let Some(item) = context.imported {
            self.park_generated_history_edit(
                context.entry,
                item,
                identity,
                edit,
                context.source.root_commitment(),
            )
        } else {
            self.park_generated_edit(context.entry, identity, edit, bytes, context.own_sent)
        }
    }

    fn authorize_generated_edit_group(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        identity: &ramflux_protocol::message::EventIdentity,
    ) -> Result<(), SdkError> {
        if let Some(group) = identity.group_id.as_deref() {
            self.require_native_operation(
                source,
                crate::client::identity_authority::NativeOperation::Group,
            )?;
            self.require_generated_group_epoch(
                group,
                source,
                identity
                    .group_epoch
                    .ok_or_else(|| SdkError::InboundRejected("Edit group epoch missing".into()))?,
                false,
            )?;
        }
        Ok(())
    }

    pub(crate) fn apply_generated_edit_authorized(
        &self,
        authorization: EditContext<'_>,
        conversation: &str,
        exact_inner: &[u8],
        metadata: Option<&ramflux_storage::MessageMetadata>,
    ) -> Result<bool, SdkError> {
        use ramflux_protocol::message as g;
        let EditContext { source, imported, own_sent, .. } = authorization;
        let historical = imported.is_some() || own_sent;
        if own_sent && source.root_commitment() != self.own_account_anchor()? {
            return Err(refused("own-sent Edit requires same-root attestation"));
        }
        let (identity, content) = Self::decode_generated_inner(exact_inner)?;
        let Some(g::content::Value::Edit(edit)) = content.value else {
            return Err(refused("expected generated Edit"));
        };
        if edit.replacement.as_ref().is_some_and(|message| message.sealed_group.is_some()) {
            return Err(SdkError::InboundRejected("edit replacement must be plain content".into()));
        }
        let target = edit
            .target
            .as_ref()
            .ok_or_else(|| SdkError::InboundPending("message target missing".into()))?;
        if target.conversation_id != conversation
            || target.author_anchor != source.root_commitment()
        {
            return Err(SdkError::InboundRejected("edit requires the original author".into()));
        }
        self.authorize_generated_edit_group(source, &identity)?;
        let target_id = ramflux_protocol::encode_base64url(&target.id);
        let db = self.account_db()?;
        db.write_transaction(|| {
            if db.message_is_deleted(&target_id)? { return Ok(false); }
            let Some(row) = self.direct_message_by_id(&target_id)? else {
                self.park_waiting_generated_edit(authorization, &identity, &edit, exact_inner)?;
                return Ok(false);
            };
            let author = if row.is_own {
                self.own_account_anchor()?
            } else {
                self.message_origin(conversation, &target_id)?
                    .and_then(|origin| origin["sender_root_commitment"].as_str().map(str::to_owned))
                    .ok_or_else(|| refused("edit target has no authenticated origin"))?
            };
            if author != source.root_commitment() || row.conversation_id != conversation {
                return Err(SdkError::InboundRejected("edit target author or conversation mismatch".into()));
            }
            if db.load_actor_state::<g::EventIdentity>(&format!("routed/generated-identity/{target_id}"))?
                .is_some_and(|original| original.group_id != identity.group_id)
            {
                return Err(SdkError::InboundRejected("Edit target group differs from event group".into()));
            }
            let state_key = format!("routed/edit-revision/{target_id}");
            let applied = db.load_actor_state::<EditRegister>(&state_key)?;
            let incoming = (edit.revision, identity.id.as_slice());
            let old_pair = applied.as_ref().map(|state| (state.revision, state.event_id.as_slice()));
            let stored = db.message_content(&target_id)?;
            if stored.is_none() && imported.is_none() {
                self.park_waiting_generated_edit(authorization, &identity, &edit, exact_inner)?;
                return Ok(false);
            }
            edit.replacement.as_ref().ok_or_else(|| refused("Edit replacement missing"))?;
            let digest = if historical { [0; 32] } else {
                let stored = stored.as_deref().ok_or_else(|| refused("Edit target content missing"))?;
                if let Some(nested) = db.load_actor_state::<Vec<u8>>(&format!("routed/group-content/{target_id}"))? {
                    digest_exact_content(target, &nested)?
                } else { previous_content_digest(target, stored)? }
            };
            let old_revision = applied.as_ref().map_or(0, |state| state.revision);
            let fork = (old_revision == edit.revision && old_pair != Some(incoming))
                || (!historical && edit.revision == old_revision.saturating_add(1) && edit.previous_content_digest.as_slice() != digest);
            if fork && source.root_commitment() == self.own_account_anchor()? {
                let losing = if old_pair.is_some_and(|pair| pair < incoming) {
                    applied.as_ref().map_or_else(|| identity.id.clone(), |state| state.event_id.clone())
                } else { identity.id.clone() };
                let update = serde_json::json!({"target": target_id, "losing_event_id": losing, "expected": old_revision.saturating_add(1), "received": edit.revision});
                db.append_journal(&format!("edit-conflict/{target_id}/{}", ramflux_protocol::encode_base64url(&losing)), "message.edit.conflict", &update, crate::time::now_unix_timestamp(), None)?;
            }
            if old_pair.is_some_and(|pair| incoming <= pair) { return Ok(false); }
            if let Some(item) = imported {
                let stored_identity = db.load_actor_state::<g::EventIdentity>(&format!("routed/generated-identity/{target_id}"))?.ok_or(g::original_header::EvidenceError::OriginEvidenceMissing)?;
                let original_identity = g::original_header::decode_identity(&item.exact_original_identity)?;
                if stored_identity != original_identity { return Err(g::original_header::EvidenceError::EditTargetMismatch.into()); }
            }
            if edit.replacement.as_ref().is_some_and(|replacement| replacement.media.is_empty()) {
                db.retire_message_attachment_references(&target_id)?;
            }
            self.retire_generated_edit_payloads(conversation, &target_id)?;
            db.remove_actor_state(&format!("routed/group-content/{target_id}"))?;
            db.remove_actor_state(&format!("routed/group-projection/{target_id}"))?;
            let mut replacement_metadata = row.metadata;
            replacement_metadata.franking_report = metadata.and_then(|metadata| metadata.franking_report.clone());
            db.replace_generated_message_content(conversation, &target_id, exact_inner, &replacement_metadata)?;
            if let Some(item) = imported { self.store_generated_edited_evidence(&target_id, item)?; }
            db.persist_message_actor_state(&target_id, &state_key, &EditRegister { revision: edit.revision, event_id: identity.id })?;
            Ok(true)
        })
    }
}

/// Who is applying a mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationActor {
    /// Authenticated author of the target message.
    Author,
    /// Recipient of a DM or group member without moderator proof.
    Recipient,
    /// Current group moderator with signed group authorization.
    GroupModerator,
}

/// Conversation that holds the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationKind {
    Direct,
    Group,
    OwnCopy,
}

/// Stored target used for authorization. Candidate-only; not a live row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredTarget {
    pub author_root: String,
    pub revision: u64,
    pub tombstoned: bool,
    pub conversation: ConversationKind,
}

/// Receive maximum is the compiled layer. Own declaration expiry never lowers it.
#[must_use]
pub fn receive_compiled_layer(_own_declaration_expired: bool) -> u32 {
    COMPILED_LAYER
}

/// Encode Edit/Delete/Reaction as typed layer-2 content. Never substitute text.
/// # Errors
/// Rejects an unspecified kind.
pub(crate) fn mutation_encoding(
    kind: KindId,
    selected_layer: u32,
) -> Result<crate::client::target_selection::Encoding, SdkError> {
    crate::client::target_selection::encoding_for(kind, selected_layer)
}

/// Edit is own-root only. Tombstoned targets refuse a replacement.
/// # Errors
/// Refuses a non-author or a tombstoned target.
pub fn authorize_edit(actor_root: &str, target: &StoredTarget) -> Result<(), SdkError> {
    if target.tombstoned {
        return Err(refused("edit of a tombstoned target is refused"));
    }
    if actor_root != target.author_root {
        return Err(refused("edit requires the original author"));
    }
    Ok(())
}

/// Apply a new Edit revision. Conflicting or stale revisions are not last-write-wins.
/// # Errors
/// Refuses `incoming <= stored`.
pub fn apply_edit_revision(stored: u64, incoming: u64) -> Result<u64, SdkError> {
    if incoming <= stored {
        return Err(refused("stale edit revision"));
    }
    Ok(incoming)
}

/// Delete LOCAL is always a local-account choice. EVERYONE is author or group moderator.
/// # Errors
/// Refuses a recipient EVERYONE delete of a peer DM, unspecified scope, or missing proof.
pub fn authorize_delete(
    actor_root: &str,
    actor: MutationActor,
    target: &StoredTarget,
    scope: DeleteScope,
) -> Result<(), SdkError> {
    match scope {
        DeleteScope::Local => Ok(()),
        DeleteScope::Everyone => match target.conversation {
            ConversationKind::Direct | ConversationKind::OwnCopy => {
                if actor_root == target.author_root {
                    Ok(())
                } else {
                    Err(refused("recipient cannot delete a peer DM for everyone"))
                }
            }
            ConversationKind::Group => {
                if actor_root == target.author_root || actor == MutationActor::GroupModerator {
                    Ok(())
                } else {
                    Err(refused("group everyone-delete requires author or moderator"))
                }
            }
        },
        DeleteScope::Unspecified => Err(refused("delete scope is unspecified")),
    }
}

/// Reaction add/remove uses the target; a tombstone refuses recreation.
/// # Errors
/// Refuses a reaction on a tombstoned target.
pub fn authorize_reaction(target: &StoredTarget) -> Result<(), SdkError> {
    if target.tombstoned {
        return Err(refused("reaction after tombstone is refused"));
    }
    Ok(())
}

/// Closed Edit/Delete field tags at the S10a floor. A new erasure-relevant field
/// requires a floor raise; it cannot ride as optional above F.
pub const ERASURE_FIELDS: &[(&str, u32, u32)] = &[
    ("Message", 17, 3),
    ("Edit", 1, 2),
    ("Edit", 2, 2),
    ("Edit", 3, 2),
    ("Edit", 4, 2),
    ("Delete", 1, 2),
    ("Delete", 2, 2),
    ("Delete", 3, 2),
    ("Delete", 4, 2),
];

/// Admit an erasure-relevant field only at or below the new floor.
/// # Errors
/// Refuses a field above the current floor without raising the floor to match.
pub fn admit_erasure_field(first_layer: u32, new_floor: u32) -> Result<(), SdkError> {
    if new_floor < first_layer {
        return Err(refused("erasure-relevant field above the floor requires a profile reset"));
    }
    Ok(())
}

/// Mutations were introduced at layer 2; the private-revision profile now requires layer 3.
#[must_use]
pub fn mutation_first_layer(kind: KindId) -> Option<u32> {
    let number = u32::try_from(i32::from(kind)).ok()?;
    kind_binding(number).map(|binding| binding.first_layer)
}

fn refused(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}

impl RamfluxClient {
    /// Candidate Edit authorization. Does not send or persist.
    /// # Errors
    /// Refuses a non-author or a tombstoned target.
    pub fn authorize_generated_edit(
        actor_root: &str,
        target: &StoredTarget,
    ) -> Result<(), SdkError> {
        authorize_edit(actor_root, target)
    }

    /// Candidate Delete authorization. Does not send or persist.
    /// # Errors
    /// Refuses a recipient EVERYONE delete of a peer DM or unspecified scope.
    pub fn authorize_generated_delete(
        actor_root: &str,
        actor: MutationActor,
        target: &StoredTarget,
        scope: DeleteScope,
    ) -> Result<(), SdkError> {
        authorize_delete(actor_root, actor, target, scope)
    }

    /// Candidate Reaction authorization. Does not send or persist.
    /// # Errors
    /// Refuses a reaction on a tombstoned target.
    pub fn authorize_generated_reaction(target: &StoredTarget) -> Result<(), SdkError> {
        authorize_reaction(target)
    }

    /// Compiled receive layer. Own declaration expiry never lowers it.
    #[must_use]
    pub fn generated_receive_compiled_layer(own_declaration_expired: bool) -> u32 {
        receive_compiled_layer(own_declaration_expired)
    }

    /// Whether Edit/Delete/Reaction stay typed at `selected_layer`.
    /// # Errors
    /// Rejects an unspecified kind.
    pub fn generated_mutation_is_typed(
        kind: KindId,
        selected_layer: u32,
    ) -> Result<bool, SdkError> {
        Ok(matches!(
            mutation_encoding(kind, selected_layer)?,
            crate::client::target_selection::Encoding::Typed { .. }
        ))
    }

    /// Apply a new Edit revision.
    /// # Errors
    /// Refuses a stale or equal revision.
    pub fn apply_generated_edit_revision(stored: u64, incoming: u64) -> Result<u64, SdkError> {
        apply_edit_revision(stored, incoming)
    }

    /// Admit an erasure-relevant field against a proposed floor.
    /// # Errors
    /// Refuses a field above the current floor without raising the floor.
    pub fn admit_generated_erasure_field(first_layer: u32, new_floor: u32) -> Result<(), SdkError> {
        admit_erasure_field(first_layer, new_floor)
    }

    /// First schema layer of a mutation kind.
    #[must_use]
    pub fn generated_mutation_first_layer(kind: KindId) -> Option<u32> {
        mutation_first_layer(kind)
    }

    /// Closed Edit/Delete erasure field census at the S10a floor.
    #[must_use]
    pub fn generated_erasure_fields() -> &'static [(&'static str, u32, u32)] {
        ERASURE_FIELDS
    }
}

#[cfg(test)]
mod tests;

#[path = "message_mutations/reactions.rs"]
mod reactions;
