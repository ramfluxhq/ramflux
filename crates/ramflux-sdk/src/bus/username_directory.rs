// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account actor adapters. Master words stay in the CLI; the actor receives signed intent only.
use crate::prelude::{
    LocalBusDaemonState, LocalBusDispatchResult, LocalBusFrame, SdkError, local_bus_account,
    local_bus_ok, request_account_id,
};
use crate::username_directory::{self as directory, SignedUsernameChange, UsernameChange};
use ramflux_protocol::username_directory as w;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Mutation {
    Prepare { change: UsernameChange },
    Submit { signed: Box<SignedUsernameChange> },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    operation_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolve {
    name: String,
}

pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let pin = directory::configured_center()?;
    let (gateway, root) = {
        let account = local_bus_account(state, account_id)?;
        (account.sealing_config()?, account.principal_commitment.clone())
    };
    match request.method.as_str() {
        "username.resolve" => {
            let body: Resolve = serde_json::from_value(request.body.clone())?;
            let name = directory::normalize_name(&body.name)?;
            let nonce = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
            let result = directory::exchange_username(
                &gateway,
                pin.clone(),
                w::NativeUsernameAction::Resolve { name: name.clone(), nonce: nonce.clone() },
            )
            .await?;
            let account = local_bus_account(state, account_id)?;
            let resolved = directory::observe_resolution(
                account.client.account_db()?,
                result,
                &pin,
                &name,
                &nonce,
                crate::custody::network_now()?,
            )?;
            Ok(local_bus_ok(serde_json::to_value(resolved)?))
        }
        "username.status" => {
            let body: Status = serde_json::from_value(request.body.clone())?;
            let result = directory::exchange_username(
                &gateway,
                pin.clone(),
                w::NativeUsernameAction::Status { operation_id: body.operation_id.clone() },
            )
            .await?;
            let db = local_bus_account(state, account_id)?.client.account_db()?;
            let (status, _, _) = directory::observe_status(
                db,
                result,
                &pin,
                &root,
                body.operation_id.as_deref(),
                crate::custody::network_now()?,
            )?;
            directory::settle_local_intent(db, &root, &status, crate::custody::network_now()?)?;
            Ok(local_bus_ok(serde_json::to_value(status)?))
        }
        "username.mutate" | "profile.update" => {
            if request.body.get("avatar").is_some_and(|value| !value.is_null()) {
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
                    let result = directory::exchange_username(
                        &gateway,
                        pin.clone(),
                        w::NativeUsernameAction::Status { operation_id: None },
                    )
                    .await?;
                    let db = local_bus_account(state, account_id)?.client.account_db()?;
                    let (status, native, home) = directory::observe_status(
                        db,
                        result,
                        &pin,
                        &root,
                        None,
                        crate::custody::network_now()?,
                    )?;
                    directory::settle_local_intent(
                        db,
                        &root,
                        &status,
                        crate::custody::network_now()?,
                    )?;
                    let draft = directory::prepare_username_draft(
                        pin,
                        &native,
                        &home,
                        &status,
                        &change,
                        crate::custody::network_now()?,
                    )?;
                    Ok(local_bus_ok(serde_json::json!({"draft": draft, "status": status})))
                }
                Mutation::Submit { signed } => {
                    if signed.center != pin || signed.operation.body.principal_commitment != root {
                        return Err(w::DirectoryCode::OwnershipMismatch.into());
                    }
                    if request.method == "profile.update"
                        && signed.operation.body.action != w::Action::ProfileUpdate
                    {
                        return Err(w::DirectoryCode::InvalidProfile.into());
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
                    ramflux_crypto::username_directory::verify_operation(
                        &master,
                        &signed.operation,
                    )
                    .map_err(|_| w::DirectoryCode::SignatureInvalid)?;
                    ramflux_crypto::username_directory::verify_profile(&master, &signed.profile)
                        .map_err(|_| w::DirectoryCode::SignatureInvalid)?;
                    let key = format!("username/intent/{root}");
                    let db = local_bus_account(state, account_id)?.client.account_db()?;
                    if let Some(old) = db.load_actor_state::<SignedUsernameChange>(&key)?
                        && (old.operation != signed.operation
                            || old.profile != signed.profile
                            || old.center != signed.center)
                    {
                        return Err(w::DirectoryCode::OperationPending.into());
                    }
                    db.persist_actor_state(&key, signed.as_ref())?;
                    let result = directory::exchange_username(
                        &gateway,
                        pin.clone(),
                        w::NativeUsernameAction::Mutate {
                            operation: Box::new(signed.operation),
                            profile: Box::new(signed.profile),
                        },
                    )
                    .await?;
                    let db = local_bus_account(state, account_id)?.client.account_db()?;
                    let (status, _, _) = directory::observe_status(
                        db,
                        result,
                        &pin,
                        &root,
                        None,
                        crate::custody::network_now()?,
                    )?;
                    Ok(local_bus_ok(serde_json::to_value(status)?))
                }
            }
        }
        _ => Err(w::DirectoryCode::UnsupportedVersion.into()),
    }
}
