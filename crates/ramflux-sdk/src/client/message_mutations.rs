// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant Edit/Delete/Reaction authorization and layer admission (S10a P14).
//! This module neither sends a carrier nor admits a stored event.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message::registry::{COMPILED_LAYER, PROFILE_FLOOR, kind_binding};
use ramflux_protocol::message::{DeleteScope, KindId};

/// OV-EDIT-DIGEST transcript over the canonical target and exact content in force.
/// # Errors
/// Refuses malformed references, unsupported stored content and oversized fields.
pub fn previous_content_digest(
    target: &ramflux_protocol::message::MessageRef,
    stored_inner: &[u8],
) -> Result<[u8; 32], SdkError> {
    use prost::Message as _;
    let exact = ramflux_protocol::message::exact_content::message_in_force(stored_inner)
        .map_err(|_| refused("stored message has no exact editable content"))?;
    if target.id.is_empty() || target.conversation_id.is_empty() || target.author_anchor.is_empty() {
        return Err(refused("edit target is not source-qualified"));
    }
    let reference = target.encode_to_vec();
    let mut input = Vec::with_capacity(reference.len() + exact.len() + 8);
    for field in [reference.as_slice(), exact] {
        let length = u32::try_from(field.len()).map_err(|_| refused("edit digest input too large"))?;
        input.extend_from_slice(&length.to_be_bytes());
        input.extend_from_slice(field);
    }
    Ok(ramflux_crypto::blake3_256(ramflux_protocol::domain::EDIT_PREVIOUS_CONTENT, &input))
}

impl RamfluxClient {
    /// Apply a generated Delete after transport/source authentication.
    /// # Errors
    /// Refuses foreign LOCAL scope, forged authors and unsupported moderator proofs.
    pub fn apply_generated_delete_entry(
        &self,
        entry: &crate::GatewayInboxEntry,
        conversation: &str,
        delete: &ramflux_protocol::message::Delete,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(
            crate::client::identity_authority::HeadUse::NewAuthorization, entry,
        )?;
        let scope = DeleteScope::try_from(delete.scope).map_err(|_| refused("delete scope invalid"))?;
        if delete.targets.is_empty() || delete.tombstone_id.is_empty() || scope == DeleteScope::Unspecified {
            return Err(SdkError::InboundRejected("delete targets, scope and tombstone are required".into()));
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            for target in &delete.targets {
                let id = std::str::from_utf8(&target.id).map_err(|_| refused("delete target unbound"))?;
                if target.conversation_id != conversation { return Err(SdkError::InboundRejected("delete conversation mismatch".into())); }
                if db.message_is_deleted(id)? { continue; }
                let row = self.direct_message_by_id(id)?.ok_or_else(|| refused("delete target missing"))?;
                let author = self.generated_target_author(conversation, id, row.is_own)?;
                if row.conversation_id != conversation || author != target.author_anchor {
                    return Err(SdkError::InboundRejected("delete target author mismatch".into()));
                }
                let allowed = match scope {
                    DeleteScope::Local => source.root_commitment() == self.own_account_anchor()?,
                    DeleteScope::Everyone => source.root_commitment() == author,
                    DeleteScope::Unspecified => false,
                };
                if !allowed { return Err(SdkError::InboundRejected("delete sender has no target authority".into())); }
                let tombstone = format!("generated:{}", ramflux_protocol::encode_base64url(
                    ramflux_protocol::canonical_json_bytes(&(source.root_commitment(), id, &delete.tombstone_id))?,
                ));
                db.delete_direct_message(conversation, id,
                    if scope == DeleteScope::Local { "local" } else { "everyone" }, &tombstone)?;
            }
            Ok(())
        })
    }

    fn generated_target_author(&self, conversation: &str, id: &str, own: bool) -> Result<String, SdkError> {
        if own { return self.own_account_anchor(); }
        self.message_origin(conversation, id)?
            .and_then(|origin| origin["sender_root_commitment"].as_str().map(str::to_owned))
            .ok_or_else(|| refused("mutation target has no authenticated origin"))
    }

    /// Apply one idempotent generated reaction using a source-qualified operation id.
    /// # Errors
    /// Refuses missing/unbound targets, invalid tokens or an operation id reused with new intent.
    pub fn apply_generated_reaction_entry(
        &self,
        entry: &crate::GatewayInboxEntry,
        conversation: &str,
        reaction: &ramflux_protocol::message::Reaction,
    ) -> Result<bool, SdkError> {
        ramflux_protocol::message::validation::validate_reaction_token(&reaction.token)
            .map_err(|_| refused("invalid reaction token"))?;
        let source = self.authenticated_device_identity(
            crate::client::identity_authority::HeadUse::NewAuthorization, entry,
        )?;
        let target = reaction.target.as_ref().ok_or_else(|| refused("reaction target missing"))?;
        let id = std::str::from_utf8(&target.id).map_err(|_| refused("reaction target unbound"))?;
        if target.conversation_id != conversation || reaction.operation_id.is_empty() {
            return Err(SdkError::InboundRejected("reaction conversation or operation id missing".into()));
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            if db.message_is_deleted(id)? { return Ok(false); }
            let row = self.direct_message_by_id(id)?.ok_or_else(|| refused("reaction target missing"))?;
            if row.conversation_id != conversation || target.author_anchor != self.generated_target_author(conversation, id, row.is_own)? {
                return Err(SdkError::InboundRejected("reaction target author mismatch".into()));
            }
            let operation = format!("routed/reaction-operation/{}/{}", source.root_commitment(), ramflux_protocol::encode_base64url(&reaction.operation_id));
            if let Some(previous) = db.load_actor_state::<ramflux_protocol::message::Reaction>(&operation)? {
                if previous != *reaction { return Err(SdkError::ReplayMismatch); }
                return Ok(false);
            }
            let key = format!("routed/reaction/{}", ramflux_protocol::encode_base64url(
                ramflux_protocol::canonical_json_bytes(&(target, source.root_commitment(), &reaction.token))?,
            ));
            if reaction.remove { db.remove_actor_state(&key)?; }
            else { db.persist_message_actor_state(id, &key, reaction)?; }
            db.persist_message_actor_state(id, &operation, reaction)?;
            Ok(true)
        })
    }

    /// Apply an authenticated edit using the exact received replacement bytes.
    /// # Errors
    /// Refuses forged authors/targets; a gap or digest mismatch returns `EditConflict`.
    pub fn apply_generated_edit_entry(
        &self,
        entry: &crate::GatewayInboxEntry,
        conversation: &str,
        exact_inner: &[u8],
    ) -> Result<bool, SdkError> {
        use ramflux_protocol::message as g;
        let source = self.authenticated_device_identity(
            crate::client::identity_authority::HeadUse::NewAuthorization, entry,
        )?;
        let (_, content) = Self::decode_generated_inner(exact_inner)?;
        let Some(g::content::Value::Edit(edit)) = content.value else {
            return Err(refused("expected generated Edit"));
        };
        let target = edit.target.as_ref().ok_or_else(|| refused("edit target missing"))?;
        if target.conversation_id != conversation || target.author_anchor != source.root_commitment() {
            return Err(SdkError::InboundRejected("edit requires the original author".into()));
        }
        let target_id = std::str::from_utf8(&target.id).map_err(|_| refused("edit target is unbound"))?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            if db.message_is_deleted(target_id)? { return Ok(false); }
            let row = self.direct_message_by_id(target_id)?.ok_or_else(|| refused("edit target missing"))?;
            let author = if row.is_own {
                self.own_account_anchor()?
            } else {
                self.message_origin(conversation, target_id)?
                    .and_then(|origin| origin["sender_root_commitment"].as_str().map(str::to_owned))
                    .ok_or_else(|| refused("edit target has no authenticated origin"))?
            };
            if author != source.root_commitment() || row.conversation_id != conversation {
                return Err(SdkError::InboundRejected("edit target author or conversation mismatch".into()));
            }
            let state_key = format!("routed/edit-revision/{target_id}");
            let applied = db.load_actor_state::<u64>(&state_key)?.unwrap_or(0);
            if edit.revision <= applied { return Ok(false); }
            let expected = applied.checked_add(1).ok_or_else(|| refused("edit revision exhausted"))?;
            let stored = db.message_content(target_id)?.ok_or_else(|| refused("edit target content missing"))?;
            let digest = previous_content_digest(target, &stored)?;
            if edit.revision != expected || edit.previous_content_digest.as_slice() != digest {
                return Err(SdkError::EditConflict { target: target_id.to_owned(), expected, received: edit.revision });
            }
            db.replace_surface_message_content(conversation, target_id, exact_inner)?;
            db.persist_message_actor_state(target_id, &state_key, &edit.revision)?;
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
    if first_layer > PROFILE_FLOOR && new_floor < first_layer {
        return Err(refused("erasure-relevant field above the floor requires a profile reset"));
    }
    Ok(())
}

/// Kind first-layer for Edit/Delete/Reaction is the S10a floor (2), never 1.
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
