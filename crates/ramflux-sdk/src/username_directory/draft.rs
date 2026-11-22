// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Drafts contain public unsigned intent only. A typed local signer supplies master authorization.
use crate::SdkError;
use ramflux_protocol::{custody::{DeviceSet, Envelope}, username_directory as w};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub enum UsernameChange {
    Set { name: String },
    Release,
    Visibility { discoverable: bool },
    Delete,
    Profile { display_name: Option<String>, bio: Option<String> },
}

impl UsernameChange {
    /// # Errors
    /// Refuses invalid local names, display names or bios before requesting master authorization.
    pub fn normalized(&self) -> Result<Self, SdkError> {
        Ok(match self {
            Self::Set { name } => Self::Set { name: super::normalize_name(name)? },
            Self::Profile { display_name, bio } => Self::Profile {
                display_name: display_name.as_deref().map(ramflux_protocol::normalize_profile_display_name).transpose().map_err(|_| w::DirectoryCode::InvalidProfile)?,
                bio: bio.as_deref().map(w::normalize_bio).transpose().map_err(|_| w::DirectoryCode::InvalidProfile)?,
            },
            _ => self.clone(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameDraft {
    pub center: w::NativeDirectoryPin,
    pub master_public_key: String,
    pub change: UsernameChange,
    pub binding: Option<w::UsernameBindingBody>,
    pub operation: w::UsernameOperationBody,
    pub profile: w::IdentityProfileV2Body,
}

/// Caller supplies only state already verified through the native account and live home.
/// `None` means an exact no-op; it does not allocate an operation or charge mutation budgets.
/// # Errors
/// Refuses pending/deleted state, unsupported changes, overflow and malformed public fields.
pub fn prepare_username_draft(center: w::NativeDirectoryPin, native: &Envelope<DeviceSet>, home: &str,
    status: &w::NativeUsernameStatus, change: &UsernameChange, now: u64) -> Result<Option<UsernameDraft>, SdkError> {
    let change = change.normalized()?;
    center.validate().map_err(|_| w::DirectoryCode::DirectoryUnavailable)?;
    if status.state == w::NativeUsernameState::Pending { return Err(w::DirectoryCode::OperationPending.into()); }
    if status.current_operation.as_ref().is_some_and(|op| op.body.action == w::Action::Delete) { return Err(w::DirectoryCode::AccountDeleted.into()); }
    let root = &native.body.account_anchor;
    let current_name = status.binding.as_ref().map(|binding| binding.body.name.clone());
    let expected_epoch = status.receipt.as_ref().map_or(0, |r| r.body.epoch);
    let expected_profile = status.receipt.as_ref().map_or(w::ProfileRef { version: 0, epoch: 0, hash: None }, |r| r.body.profile.clone());
    let mut profile = status.profile.as_ref().map_or_else(|| w::IdentityProfileV2Body {
        schema: ramflux_protocol::domain::IDENTITY_PROFILE_V2.into(), principal_id: native.body.principal_id.clone(),
        principal_commitment: root.clone(), kind: w::ProfileKind::from_principal_kind(native.body.principal_kind),
        display_name: native.body.profile.display_name.clone(), bio: String::new(), avatar: None, epoch: 1,
    }, |p| p.body.clone());
    let mut discoverable = status.receipt.as_ref().is_some_and(|r| r.body.discoverable);
    let mut name = current_name.clone();
    let action = match &change {
        UsernameChange::Set { name: wanted } => {
            if current_name.as_ref() == Some(wanted) { return Ok(None); }
            name = Some(wanted.clone()); discoverable = true;
            if current_name.is_some() { w::Action::Rename } else { w::Action::Claim }
        }
        UsernameChange::Release => { if current_name.is_none() { return Ok(None); } name = None; discoverable = false; w::Action::Release }
        UsernameChange::Visibility { discoverable: wanted } => { if *wanted == discoverable { return Ok(None); } discoverable = *wanted; w::Action::SetVisibility }
        UsernameChange::Delete => { name = None; discoverable = false; w::Action::Delete }
        UsernameChange::Profile { display_name, bio } => {
            let before = profile.clone();
            if let Some(value) = display_name { profile.display_name.clone_from(value); }
            if let Some(value) = bio { profile.bio.clone_from(value); }
            if status.profile.is_some() && before == profile { return Ok(None); }
            profile.epoch = expected_profile.epoch.checked_add(1).ok_or(w::DirectoryCode::Capacity)?;
            w::Action::ProfileUpdate
        }
    };
    let next_epoch = expected_epoch.checked_add(1).ok_or(w::DirectoryCode::Capacity)?;
    let binding = name.map(|name| w::UsernameBindingBody { name, node: home.into(), principal_commitment: root.clone(), epoch: next_epoch });
    let operation = w::UsernameOperationBody { action, operation_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        principal_commitment: root.clone(), expected_epoch, next_epoch, expected_profile,
        profile: w::ProfileRef { version: 2, epoch: profile.epoch, hash: None }, old_name: current_name,
        binding: None, discoverable, issued_at: now, expires_at: now.checked_add(300).ok_or(w::DirectoryCode::Capacity)?,
    };
    Ok(Some(UsernameDraft { center, master_public_key: native.body.master_certificate.body.master_public_key.clone(), change, binding, operation, profile }))
}
