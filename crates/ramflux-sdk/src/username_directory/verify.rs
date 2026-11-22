// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verify complete live replies and persist signed restrictions before returning a preview.
use super::UsernameNetworkReply;
use crate::SdkError;
use ramflux_crypto::username_directory as crypto;
use ramflux_protocol::{custody::DeviceSet, username_directory as w};
use ramflux_storage::{AccountDb, UsernameFloor, UsernameNamePin};

#[derive(Clone, Debug, serde::Serialize)]
pub struct ResolvedUsername {
    pub name: String,
    pub node: String,
    pub principal_id: String,
    pub root_commitment: String,
    pub binding: w::UsernameBinding,
    pub profile: w::SignedIdentityProfileV2,
    pub receipt: w::DirectoryReceipt,
    pub home_epoch: u64,
    #[serde(skip)]
    pub(crate) floor: UsernameFloor,
}

fn verify_current(
    pin: &w::NativeDirectoryPin,
    native: &DeviceSet,
    operation: &w::UsernameOperation,
    binding: Option<&w::UsernameBinding>,
    profile: &w::SignedIdentityProfileV2,
    receipt: &w::DirectoryReceipt,
    now: u64,
) -> Result<UsernameFloor, SdkError> {
    let center = ramflux_crypto::verifying_key_from_base64url(&pin.public_key)?;
    let master = ramflux_crypto::verifying_key_from_base64url(
        &native.master_certificate.body.master_public_key,
    )?;
    crypto::verify_receipt(&center, &pin.id, receipt)
        .map_err(|_| w::DirectoryCode::SignatureInvalid)?;
    crypto::verify_operation(&master, operation).map_err(|_| w::DirectoryCode::SignatureInvalid)?;
    crypto::verify_profile(&master, profile).map_err(|_| w::DirectoryCode::SignatureInvalid)?;
    if let Some(binding) = binding {
        crypto::verify_binding(&master, binding).map_err(|_| w::DirectoryCode::SignatureInvalid)?;
    }
    if profile.body.avatar.is_some()
        || profile.body.principal_id != native.principal_id
        || profile.body.kind != w::ProfileKind::from_principal_kind(native.principal_kind)
        || profile.body.principal_commitment != native.account_anchor
        || receipt.body.principal_commitment != native.account_anchor
        || operation.body.principal_commitment != native.account_anchor
        || operation.body.binding.as_ref() != binding
        || operation.body.next_epoch != receipt.body.epoch
        || operation.body.operation_id != receipt.body.operation_id
        || crypto::operation_hash(operation).map_err(|_| w::DirectoryCode::InvalidProfile)?
            != receipt.body.operation_hash
        || operation.body.profile != receipt.body.profile
        || receipt.body.profile.version != 2
        || receipt.body.profile.epoch != profile.body.epoch
        || receipt.body.profile.hash.as_ref()
            != Some(
                &crypto::profile_hash_v2(profile).map_err(|_| w::DirectoryCode::InvalidProfile)?,
            )
        || receipt.body.binding_hash
            != binding
                .map(crypto::binding_hash)
                .transpose()
                .map_err(|_| w::DirectoryCode::InvalidProfile)?
        || receipt.body.state != w::ReceiptState::Committed
        || receipt.body.committed_at > now
        || now >= receipt.body.expires_at
        || receipt.body.expires_at > now.checked_add(60).ok_or(w::DirectoryCode::ClockUnsafe)?
        || operation.body.issued_at > receipt.body.committed_at
        || receipt.body.committed_at >= operation.body.expires_at
    {
        return Err(w::DirectoryCode::ProfileEquivocation.into());
    }
    Ok(UsernameFloor {
        master_public_key: native.master_certificate.body.master_public_key.clone(),
        operation: operation.clone(),
        binding: binding.cloned(),
        profile: profile.clone(),
        quarantined: false,
    })
}

pub(crate) fn observe_status(
    db: &AccountDb,
    result: UsernameNetworkReply,
    pin: &w::NativeDirectoryPin,
    root: &str,
    requested: Option<&str>,
    now: u64,
) -> Result<
    (w::NativeUsernameStatus, ramflux_protocol::custody::Envelope<DeviceSet>, String),
    SdkError,
> {
    if result.own_record.body.account_anchor != root {
        return Err(w::DirectoryCode::OwnershipMismatch.into());
    }
    let w::NativeUsernameReply::Status { status } = result.reply else {
        return Err(w::DirectoryCode::DirectoryUnavailable.into());
    };
    if requested.is_some_and(|id| status.operation_id.as_deref() != Some(id)) {
        return Err(w::DirectoryCode::Replay.into());
    }
    if let Some(operation_receipt) = &status.operation_receipt {
        let center = ramflux_crypto::verifying_key_from_base64url(&pin.public_key)?;
        crypto::verify_receipt(&center, &pin.id, operation_receipt)
            .map_err(|_| w::DirectoryCode::SignatureInvalid)?;
        let state = match operation_receipt.body.state {
            w::ReceiptState::Reserved => w::NativeUsernameState::Pending,
            w::ReceiptState::Committed => w::NativeUsernameState::Committed,
            w::ReceiptState::Aborted => w::NativeUsernameState::Aborted,
        };
        if operation_receipt.body.principal_commitment != root
            || status.operation_id.as_ref() != Some(&operation_receipt.body.operation_id)
            || operation_receipt.body.committed_at > now
            || now >= operation_receipt.body.expires_at
            || status.state != state
        {
            return Err(w::DirectoryCode::Replay.into());
        }
    } else if !matches!(
        status.state,
        w::NativeUsernameState::Pending | w::NativeUsernameState::Empty
    ) {
        return Err(w::DirectoryCode::DirectoryUnavailable.into());
    }
    match (&status.current_operation, &status.profile, &status.receipt) {
        (Some(operation), Some(profile), Some(receipt)) => {
            let floor = verify_current(
                pin,
                &result.own_record.body,
                operation,
                status.binding.as_ref(),
                profile,
                receipt,
                now,
            )?;
            db.observe_username(&floor)?;
        }
        (None, None, None) if status.binding.is_none() => {
            if status.state != w::NativeUsernameState::Pending && db.username_floor(root)?.is_some()
            {
                return Err(w::DirectoryCode::ProfileDowngrade.into());
            }
        }
        _ => return Err(w::DirectoryCode::DirectoryUnavailable.into()),
    }
    Ok((*status, result.own_record, result.own_home))
}

pub(crate) fn observe_resolution(
    db: &AccountDb,
    result: UsernameNetworkReply,
    pin: &w::NativeDirectoryPin,
    name: &str,
    nonce: &str,
    now: u64,
) -> Result<ResolvedUsername, SdkError> {
    let w::NativeUsernameReply::Resolved {
        operation,
        resolve,
        binding,
        profile,
        receipt,
        history,
        nonce: echoed,
    } = result.reply
    else {
        return Err(w::DirectoryCode::DirectoryUnavailable.into());
    };
    let center = ramflux_crypto::verifying_key_from_base64url(&pin.public_key)?;
    crypto::verify_resolve(&center, &pin.id, &resolve)
        .map_err(|_| w::DirectoryCode::SignatureInvalid)?;
    let first = history.predecessors.first().unwrap_or(&history.home);
    if !matches!(first.record, ramflux_protocol::home_migration::HomeRecord::Genesis { .. }) {
        return Err(w::DirectoryCode::MigrationRequired.into());
    }
    let home = ramflux_crypto::home_migration::verify_home_chain(&history, first, now)
        .map_err(|_| w::DirectoryCode::MigrationRequired)?;
    let native = &history.home.authority.record.body;
    if echoed != nonce
        || resolve.body.request_nonce != nonce
        || resolve.body.name != name
        || binding.body.name != name
        || resolve.body.issued_at > now
        || now >= resolve.body.expires_at
        || resolve.body.expires_at
            > resolve.body.issued_at.checked_add(60).ok_or(w::DirectoryCode::ClockUnsafe)?
        || resolve.body.node != home.home().0
        || resolve.body.node != binding.body.node
        || resolve.body.principal_commitment != native.account_anchor
        || home.evidence().record.account_anchor() != native.account_anchor
        || resolve.body.epoch != binding.body.epoch
        || resolve.body.epoch != receipt.body.epoch
        || resolve.body.binding_hash
            != crypto::binding_hash(&binding).map_err(|_| w::DirectoryCode::SignatureInvalid)?
        || resolve.body.profile != receipt.body.profile
        || !receipt.body.discoverable
    {
        return Err(w::DirectoryCode::ProfileEquivocation.into());
    }
    let floor = verify_current(pin, native, &operation, Some(&binding), &profile, &receipt, now)?;
    if let Some(old) = db.username_name_pin(name)?
        && (old.conflicted || old.binding.body.principal_commitment != native.account_anchor)
    {
        return Err(w::DirectoryCode::NameChanged.into());
    }
    db.observe_username(&floor)?;
    Ok(ResolvedUsername {
        name: name.into(),
        node: resolve.body.node,
        principal_id: native.principal_id.clone(),
        root_commitment: native.account_anchor.clone(),
        binding: *binding,
        profile: *profile,
        receipt: *receipt,
        home_epoch: home.epoch(),
        floor,
    })
}

impl ResolvedUsername {
    /// # Errors
    /// Refuses a changed explicit name pin or unavailable durable storage.
    pub fn pin_for_add(&self, db: &AccountDb) -> Result<(), SdkError> {
        db.pin_username_name(&UsernameNamePin {
            master_public_key: self.floor.master_public_key.clone(),
            binding: self.binding.clone(),
            conflicted: false,
        })?;
        Ok(())
    }
}
