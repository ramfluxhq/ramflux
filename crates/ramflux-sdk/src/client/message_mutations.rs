// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant Edit/Delete/Reaction authorization and layer admission (S10a P14).
//! This module neither sends a carrier nor admits a stored event.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message::registry::{COMPILED_LAYER, PROFILE_FLOOR, kind_binding};
use ramflux_protocol::message::{DeleteScope, KindId};

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
