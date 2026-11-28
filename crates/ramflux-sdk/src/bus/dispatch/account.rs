// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
use zeroize::Zeroize;

fn account_request<T: serde::de::DeserializeOwned>(
    body: &serde_json::Value,
) -> Result<T, SdkError> {
    serde_json::from_value(body.clone())
        .map_err(|_| SdkError::LocalBus("invalid account request".to_owned()))
}

pub(crate) async fn dispatch_account_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        // Creation is owned by the exclusive secret ceremony on the connection.
        "account.create" => Err(SdkError::CustodySetupInvalid),
        "account.list" => Ok(local_bus_ok(account_list(state)?)),
        "account.switch" => {
            let account_id = request_account_id(request)?.to_owned();
            if !state.accounts.contains_key(&account_id) {
                return Err(SdkError::AccountNotOpen(account_id));
            }
            state.active_account_id = Some(account_id.clone());
            Ok(local_bus_ok(serde_json::json!({ "active_account_id": account_id })))
        }
        "account.status" => account_status(state, request),
        "account.config.get" | "account.config.set" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account_mut(state, account_id)?;
            if request.method == "account.config.set" {
                let config = crate::offline_retention::decode_config(request.body.clone())?;
                account.client.set_offline_retention_secs(config.offline_retention_secs)?;
            }
            Ok(local_bus_ok(serde_json::to_value(account.client.account_config()?)?))
        }
        "account.lock" | "account.sign_out" => {
            let account_id = request_account_id(request)?.to_owned();
            let reason = if request.method == "account.sign_out" { "sign_out" } else { "lock" };
            crate::client::surface::card_session::drop_account(&account_id, reason);
            local_bus_account_lock(state, &account_id).await?;
            let mut body = serde_json::json!({
                "local_account_id": account_id,
                "locked": true,
            });
            if request.method == "account.sign_out"
                && let Some(map) = body.as_object_mut()
            {
                map.insert("signed_out".to_owned(), serde_json::Value::Bool(true));
            }
            Ok(local_bus_ok(body))
        }
        "account.unlock" => {
            let account_id = request_account_id(request)?.to_owned();
            if crate::custody::account_exists(&state.config.data_root, &account_id)? {
                if let Some(reason) =
                    crate::custody::failed_setup(&state.config.data_root, &account_id)?
                {
                    return Err(crate::custody::failed_setup_error(&account_id, reason));
                }
                let result =
                    super::super::native_account::unlock_request(state, &account_id, request)?;
                return Ok(local_bus_ok(serde_json::to_value(result)?));
            }

            // Only native custody accounts exist; any other id is unknown.
            Err(super::super::account_local::missing())
        }
        "account.passphrase.rotate" => {
            let account_id = request_account_id(request)?.to_owned();
            let mut body: LocalBusAccountPassphraseRotateRequest = account_request(&request.body)?;
            local_bus_account_passphrase_rotate(state, &account_id, &mut body)?;
            Ok(local_bus_ok(serde_json::json!({
                "local_account_id": account_id,
                "rotated": true,
            })))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn account_list(state: &LocalBusDaemonState) -> Result<serde_json::Value, SdkError> {
    // On-disk and locked rows stay. An open session still publishes its live name and kind.
    let mut body = super::super::account_local::daemon_list(state)?;
    if let Some(details) = body.get_mut("account_details").and_then(|value| value.as_array_mut()) {
        for detail in details {
            let Some(id) = detail.get("id").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let id = id.to_owned();
            let Some(account) = state.accounts.get(&id) else {
                continue;
            };
            let open = open_account_detail(&id, account);
            let Some(map) = detail.as_object_mut() else {
                continue;
            };
            if let Some(name) = open.get("display_name").and_then(serde_json::Value::as_str)
                && !name.is_empty()
            {
                map.insert("display_name".to_owned(), serde_json::Value::String(name.to_owned()));
            }
            if let Some(kind) = open.get("kind") {
                map.insert("kind".to_owned(), kind.clone());
            }
        }
    }
    if let Some(details) = body.get("account_details").and_then(serde_json::Value::as_array) {
        let accounts = super::super::account_local::picker(details);
        if let Some(map) = body.as_object_mut() {
            map.insert("accounts".to_owned(), serde_json::Value::Array(accounts));
        }
    }
    Ok(body)
}

fn open_account_detail(id: &str, account: &LocalBusAccountState) -> serde_json::Value {
    if let Some(native) = account.client.born_v3_account.as_ref() {
        let body = &native.record().body;
        return serde_json::json!({
            "id": id,
            "display_name": body.profile.display_name,
            "kind": principal_kind_name(body.principal_kind),
        });
    }
    let principal = account
        .client
        .account_db()
        .ok()
        .and_then(|db| db.client_record("self", "account").ok().flatten())
        .and_then(|row| {
            row.get("principal_id").and_then(serde_json::Value::as_str).map(str::to_owned)
        });
    let display_name = principal.as_deref().and_then(|principal| {
        account
            .client
            .read_profile_facts(principal)
            .map(|facts| facts.profile.display_name.clone())
            .filter(|name| !name.is_empty())
    });
    serde_json::json!({
        "id": id,
        "display_name": display_name,
        "kind": serde_json::Value::Null,
    })
}

fn principal_kind_name(kind: ramflux_protocol::PrincipalKind) -> &'static str {
    match kind {
        ramflux_protocol::PrincipalKind::Human => "human",
        ramflux_protocol::PrincipalKind::HeadlessAi => "headless_ai",
        ramflux_protocol::PrincipalKind::Bot => "bot",
        ramflux_protocol::PrincipalKind::Workflow => "workflow",
    }
}

fn account_status(
    state: &LocalBusDaemonState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account(state, account_id)?;
    if account.client.born_v3_account.is_none() {
        return Err(super::super::account_local::missing());
    }
    Ok(local_bus_ok(super::super::native_account::status(account, account_id)?))
}

async fn local_bus_account_lock(
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<(), SdkError> {
    if let Some(account) = state.accounts.get(account_id) {
        let db = account.client.account_db()?;
        let tick = db.journal_bounds()?.head_seq;
        db.append_journal(
            &format!("account:locked:{tick}"),
            "account.state",
            &serde_json::json!({"local_account_id":account_id,"state":"locked"}),
            now_unix_timestamp(),
            None,
        )?;
    }
    let pairing_pending =
        crate::custody::pairing::work_signal(&state.config.data_root, account_id).is_some();
    crate::custody::pairing::remove_actor_and_drain(&state.config.data_root, account_id).await?;
    let removed = state.accounts.remove(account_id);
    if removed.is_none() && !pairing_pending {
        return Err(SdkError::AccountNotOpen(account_id.to_owned()));
    }
    if state.active_account_id.as_deref() == Some(account_id) {
        state.active_account_id = None;
    }
    state.attended_accounts.remove(account_id);
    state.subscribers.retain(|_, subscriber| subscriber.account_id != account_id);
    Ok(())
}

fn local_bus_account_passphrase_rotate(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    body: &mut LocalBusAccountPassphraseRotateRequest,
) -> Result<(), SdkError> {
    if let Some(old_passphrase) = body.old_passphrase.as_mut() {
        local_bus_account(state, account_id)?
            .client
            .verify_active_account_secret(account_id, old_passphrase.as_bytes())?;
        old_passphrase.zeroize();
    }
    {
        let account = local_bus_account_mut(state, account_id)?;
        account.client.rekey_active_account(account_id, body.new_passphrase.as_bytes())?;
    }
    body.new_passphrase.zeroize();
    Ok(())
}
