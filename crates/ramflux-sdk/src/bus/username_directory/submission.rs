// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Validate and journal signed input in the account writer before any network operation.
use super::{Purpose, w};
use crate::prelude::{LocalBusAccountState, LocalBusFrame, SdkError};
use crate::username_directory::{SignedUsernameChange, UsernameChange};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Mutation {
    Prepare { change: UsernameChange },
    Submit { signed: Box<SignedUsernameChange> },
}
pub(super) fn prepare(
    request: &LocalBusFrame,
    account: &LocalBusAccountState,
    pin: &w::NativeDirectoryPin,
    gateway: &crate::gateway::GatewaySessionConfig,
    root: &str,
) -> Result<(w::NativeUsernameAction, Purpose), SdkError> {
    if request.body.get("avatar").is_some_and(|v| !v.is_null()) {
        return Err(w::DirectoryCode::InvalidAvatar.into());
    }
    let body: Mutation = serde_json::from_value(request.body.clone())?;
    match body {
        Mutation::Prepare { change } => {
            if request.method == "profile.update"
                && !matches!(change, UsernameChange::Profile { .. })
            {
                return Err(w::DirectoryCode::InvalidProfile.into());
            }
            Ok((w::NativeUsernameAction::Status { operation_id: None }, Purpose::Draft { change }))
        }
        Mutation::Submit { signed } => {
            validate(&signed, pin, gateway, root)?;
            if request.method == "profile.update"
                && signed.operation.body.action != w::Action::ProfileUpdate
            {
                return Err(w::DirectoryCode::InvalidProfile.into());
            }
            let db = account.client.account_db()?;
            let key = format!("username/intent/{root}");
            db.write_transaction(|| {
                if let Some(old) = db.load_actor_state::<SignedUsernameChange>(&key)?
                    && old != *signed
                {
                    if signed.operation.body.action != w::Action::Delete {
                        return Err(w::DirectoryCode::OperationPending.into());
                    }
                    db.retain_username_candidate(&old)?;
                }
                db.persist_actor_state(&key, signed.as_ref())?;
                Ok::<_, SdkError>(())
            })?;
            Ok((
                w::NativeUsernameAction::Mutate {
                    operation: Box::new(signed.operation),
                    profile: Box::new(signed.profile),
                },
                Purpose::Submit,
            ))
        }
    }
}
fn validate(
    signed: &SignedUsernameChange,
    pin: &w::NativeDirectoryPin,
    gateway: &crate::gateway::GatewaySessionConfig,
    root: &str,
) -> Result<(), SdkError> {
    if signed.center != *pin || signed.operation.body.principal_commitment != root {
        return Err(w::DirectoryCode::OwnershipMismatch.into());
    }
    let custody = gateway.custody.as_ref().ok_or(SdkError::NetworkingPending)?;
    let native = crate::custody::load_account(
        &custody.account_root,
        &custody.account_id,
        crate::custody::network_now()?,
    )?;
    let master = ramflux_crypto::verifying_key_from_base64url(
        &native.record().body.master_certificate.body.master_public_key,
    )?;
    ramflux_crypto::username_directory::verify_operation(&master, &signed.operation)
        .map_err(|_| w::DirectoryCode::SignatureInvalid)?;
    ramflux_crypto::username_directory::verify_profile(&master, &signed.profile)
        .map_err(|_| w::DirectoryCode::SignatureInvalid)?;
    if signed.profile.body.principal_commitment != root
        || signed.profile.body.avatar.is_some()
        || signed.operation.body.profile.hash.as_ref()
            != Some(
                &ramflux_crypto::username_directory::profile_hash_v2(&signed.profile)
                    .map_err(|_| w::DirectoryCode::InvalidProfile)?,
            )
        || signed.operation.body.profile.epoch != signed.profile.body.epoch
    {
        return Err(w::DirectoryCode::InvalidProfile.into());
    }
    Ok(())
}
