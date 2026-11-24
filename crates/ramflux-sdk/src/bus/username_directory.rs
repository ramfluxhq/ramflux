// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordered writer preparation and application; only owned public input crosses network waits.
mod recovery;
mod retry;
mod submission;
use crate::prelude::{
    LocalBusDaemonState, LocalBusDispatchResult, LocalBusFrame, SdkError, local_bus_account,
    local_bus_ok, request_account_id,
};
use crate::username_directory::{self as directory, UsernameChange};
use ramflux_protocol::username_directory as w;
pub(super) use retry::{delivery_retry, delivery_status};
use serde::Deserialize;

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

pub(super) struct Prepared {
    pub(super) gateway: crate::sealing::SealingConfig,
    pub(super) pin: w::NativeDirectoryPin,
    pub(super) root: String,
    pub(super) action: w::NativeUsernameAction,
    repairs: Vec<directory::SignedUsernameChange>,
    pub(in crate::bus) transport: directory::UsernameConnection,
    purpose: Purpose,
}
enum Purpose {
    Resolve { name: String, nonce: String, add: bool },
    Status { requested: Option<String> },
    Draft { change: UsernameChange },
    Submit,
}

pub(super) fn handles(method: &str) -> bool {
    matches!(
        method,
        "username.resolve"
            | "username.contact.add"
            | "username.status"
            | "username.mutate"
            | "profile.update"
    )
}

pub(super) fn prepare(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<Prepared, SdkError> {
    if !w::enabled() {
        return Err(w::DirectoryCode::DirectoryUnavailable.into());
    }
    let id = request_account_id(request)?;
    let account = local_bus_account(state, id)?;
    let pin =
        state.config.username_directory.clone().ok_or(w::DirectoryCode::DirectoryUnavailable)?;
    directory::validate_center(&pin)?;
    let gateway = account.sealing_config()?;
    let root = account.principal_commitment.clone();
    let (action, purpose) = match request.method.as_str() {
        "username.resolve" | "username.contact.add" => {
            let body: Resolve = serde_json::from_value(request.body.clone())?;
            let name = directory::normalize_name(&body.name)?;
            let nonce = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
            (
                w::NativeUsernameAction::Resolve { name: name.clone(), nonce: nonce.clone() },
                Purpose::Resolve { name, nonce, add: request.method == "username.contact.add" },
            )
        }
        "username.status" => {
            let body: Status = serde_json::from_value(request.body.clone())?;
            (
                w::NativeUsernameAction::Status { operation_id: body.operation_id.clone() },
                Purpose::Status { requested: body.operation_id },
            )
        }
        "username.mutate" | "profile.update" => {
            submission::prepare(request, account, &pin, &gateway, &root)?
        }
        _ => return Err(w::DirectoryCode::UnsupportedVersion.into()),
    };
    let repairs = if matches!(purpose, Purpose::Status { .. } | Purpose::Draft { .. }) {
        recovery::candidates(account.client.account_db()?, &root, &pin)?
    } else {
        Vec::new()
    };
    Ok(Prepared {
        gateway,
        pin,
        root,
        action,
        repairs,
        transport: directory::UsernameConnection::default(),
        purpose,
    })
}

impl Prepared {
    pub(super) async fn exchange(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<directory::UsernameNetworkReply, SdkError> {
        self.exchange_with_recovery(deadline).await
    }
}

pub(super) async fn apply(
    state: &mut LocalBusDaemonState,
    id: &str,
    prepared: Prepared,
    result: directory::UsernameNetworkReply,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account(state, id)?;
    if account.principal_commitment != prepared.root {
        return Err(w::DirectoryCode::OwnershipMismatch.into());
    }
    let db = account.client.account_db()?;
    let now = crate::custody::network_now()?;
    match prepared.purpose {
        Purpose::Resolve { name, nonce, add } => {
            let resolved =
                directory::observe_resolution(db, result, &prepared.pin, &name, &nonce, now)?;
            if add {
                super::dispatch::contact_resolution::add_username(state, id, &resolved).await
            } else {
                Ok(local_bus_ok(serde_json::to_value(resolved)?))
            }
        }
        purpose => {
            let requested = match &purpose {
                Purpose::Status { requested } => requested.as_deref(),
                _ => None,
            };
            let (status, native, home) = directory::observe_status(
                db,
                result,
                &prepared.pin,
                &prepared.root,
                requested,
                now,
            )?;
            directory::settle_local_intent(db, &prepared.root, &status, now)?;
            if let Purpose::Draft { change } = purpose {
                let draft = directory::prepare_username_draft(
                    prepared.pin,
                    &native,
                    &home,
                    &status,
                    &change,
                    now,
                )?;
                Ok(local_bus_ok(serde_json::json!({"draft":draft, "status":status})))
            } else {
                Ok(local_bus_ok(serde_json::to_value(status)?))
            }
        }
    }
}

pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let prepared = prepare(request, state)?;
    let deadline = tokio::time::Instant::now() + super::runtime_limits::COMMAND_DEADLINE
        - std::time::Duration::from_secs(1);
    let result = prepared.exchange(deadline).await?;
    apply(state, request_account_id(request)?, prepared, result).await
}
