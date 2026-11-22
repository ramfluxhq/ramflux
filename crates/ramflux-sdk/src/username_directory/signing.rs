// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed local master ceremony. Recovery words and master material never enter a bus payload.
use super::{UsernameChange, UsernameDraft};
use crate::SdkError;
use ramflux_protocol::username_directory as w;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedUsernameChange {
    pub center: w::NativeDirectoryPin,
    pub operation: w::UsernameOperation,
    pub profile: w::SignedIdentityProfileV2,
}

/// Authorize exactly the requested typed change. The caller owns this transient ceremony;
/// only the resulting signed public records may be submitted or journalled.
/// # Errors
/// Refuses a different centre/change/root, stale draft, wrong phrase and malformed final records.
pub fn authorize_username_draft(
    words: Zeroizing<String>,
    mut draft: UsernameDraft,
    expected_center: &w::NativeDirectoryPin,
    expected_change: &UsernameChange,
    now: u64,
) -> Result<SignedUsernameChange, SdkError> {
    if draft.center != *expected_center
        || draft.change != expected_change.normalized()?
        || draft.operation.issued_at > now
        || now >= draft.operation.expires_at
    {
        return Err(w::DirectoryCode::Replay.into());
    }
    validate_intent(&draft)?;
    if words.len() > 4096 {
        return Err(w::DirectoryCode::AuthenticationRequired.into());
    }
    let phrase = ramflux_crypto::custody::RecoveryPhrase::parse(&words)
        .map_err(|_| w::DirectoryCode::AuthenticationRequired)?;
    let master = ramflux_crypto::custody::MasterKey::from_phrase(&phrase)
        .map_err(|_| w::DirectoryCode::AuthenticationRequired)?;
    if master.public_key() != draft.master_public_key {
        return Err(w::DirectoryCode::KeyChanged.into());
    }
    let profile = master
        .sign_username_profile(draft.profile)
        .map_err(|_| w::DirectoryCode::InvalidProfile)?;
    draft.operation.profile = w::ProfileRef {
        version: 2,
        epoch: profile.body.epoch,
        hash: Some(
            ramflux_crypto::username_directory::profile_hash_v2(&profile)
                .map_err(|_| w::DirectoryCode::InvalidProfile)?,
        ),
    };
    draft.operation.binding = draft
        .binding
        .map(|binding| master.sign_username_binding(binding))
        .transpose()
        .map_err(|_| w::DirectoryCode::InvalidUsername)?;
    let operation = master
        .sign_username_operation(draft.operation)
        .map_err(|_| w::DirectoryCode::InvalidUsername)?;
    Ok(SignedUsernameChange { center: draft.center, operation, profile })
}

fn validate_intent(draft: &UsernameDraft) -> Result<(), SdkError> {
    let op = &draft.operation;
    let profile = &draft.profile;
    let actual = match &draft.change {
        UsernameChange::Set { name } => {
            matches!(op.action, w::Action::Claim | w::Action::Rename)
                && draft.binding.as_ref().is_some_and(|binding| &binding.name == name)
                && op.discoverable
        }
        UsernameChange::Release => {
            op.action == w::Action::Release && draft.binding.is_none() && !op.discoverable
        }
        UsernameChange::Delete => {
            op.action == w::Action::Delete && draft.binding.is_none() && !op.discoverable
        }
        UsernameChange::Visibility { discoverable } => {
            op.action == w::Action::SetVisibility && op.discoverable == *discoverable
        }
        UsernameChange::Profile { display_name, bio } => {
            op.action == w::Action::ProfileUpdate
                && display_name.as_ref().is_none_or(|name| name == &profile.display_name)
                && bio.as_ref().is_none_or(|bio| bio == &profile.bio)
        }
    };
    if !actual
        || profile.avatar.is_some()
        || op.principal_commitment != profile.principal_commitment
        || draft.binding.as_ref().is_some_and(|binding| {
            binding.principal_commitment != op.principal_commitment
                || binding.epoch != op.next_epoch
        })
    {
        return Err(w::DirectoryCode::OwnershipMismatch.into());
    }
    draft.center.validate().map_err(|_| w::DirectoryCode::DirectoryUnavailable)?;
    Ok(())
}
