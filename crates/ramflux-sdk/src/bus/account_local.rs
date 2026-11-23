// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! On-disk account picker and local removal. Sign-out reuses the lock route.

use crate::prelude::*;
use std::path::Path;

type Listed = (serde_json::Value, bool);

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveLocal {
    confirmation: String,
}

/// Index rows that are not custody accounts, then every custody account.
///
/// # Errors
/// Returns index, custody, or filesystem errors. A removed index row is omitted.
pub(super) fn known_rows(
    index: &AccountIndex,
    root: &Path,
) -> Result<(Option<String>, Vec<Listed>), SdkError> {
    let mut known = Vec::new();
    for id in index.known_account_ids()? {
        if removed(index, &id) || crate::custody::account_exists(root, &id)? {
            continue;
        }
        known.push(manifest_row(root, &id));
    }
    append_custody(root, &mut known)?;
    Ok((index.active_account()?, known))
}

/// Adds open sessions that have no on-disk row yet.
pub(super) fn include_open(known: &mut Vec<Listed>, open: &[String]) {
    for id in open {
        if !known.iter().any(|(row, _)| row_id(row) == id) {
            known.push((serde_json::json!({"id": id}), false));
        }
    }
}

/// Account id of a picker or detail row. Empty when the row has no id.
#[must_use]
pub(super) fn row_id(row: &serde_json::Value) -> &str {
    row.get("id").and_then(serde_json::Value::as_str).unwrap_or_default()
}

/// Sets `display_name` and `locked` from the row's state. `unlocked` is the only open state.
pub(super) fn attach_from_state(row: &mut serde_json::Value) {
    let locked = row.get("state").and_then(serde_json::Value::as_str) != Some("unlocked");
    attach_picker_fields(row, locked);
}

/// `{id, display_name, locked}` for every detail row. No secret fields.
#[must_use]
pub(super) fn picker(rows: &[serde_json::Value]) -> Vec<serde_json::Value> {
    rows.iter()
        .filter(|row| !row_id(row).is_empty())
        .map(|row| {
            serde_json::json!({
                "id": row_id(row),
                "display_name": row
                    .get("display_name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
                "locked": row.get("locked").and_then(serde_json::Value::as_bool).unwrap_or(true),
            })
        })
        .collect()
}

/// Daemon `account.list`: every on-disk account, plus any open session, with lock state.
///
/// # Errors
/// Returns index or custody read errors.
pub(super) fn daemon_list(
    state: &super::state::LocalBusDaemonState,
) -> Result<serde_json::Value, SdkError> {
    let open = state.accounts.keys().cloned().collect::<Vec<_>>();
    let mut known = match &state.account_index {
        Some(index) => known_rows(index, &state.config.data_root)?.1,
        None => custody_rows(&state.config.data_root)?,
    };
    include_open(&mut known, &open);
    let mut rows = Vec::with_capacity(known.len());
    for (mut row, _) in known {
        let id = row_id(&row).to_owned();
        attach_picker_fields(&mut row, !open.iter().any(|open_id| open_id == &id));
        rows.push(row);
    }
    let active = state.active_account_id.clone().filter(|id| open.iter().any(|item| item == id));
    Ok(serde_json::json!({
        "active_account_id": active,
        "accounts": picker(&rows),
        "account_details": rows,
    }))
}

/// The typed confirmation must equal the frame account id, with no trimming.
///
/// # Errors
/// `ConfirmationRequired` when the field is missing, mistyped, or not exactly the account id.
pub(super) fn confirm(request: &LocalBusFrame) -> Result<(), SdkError> {
    let id = request_account_id(request)?;
    let Ok(body) = serde_json::from_value::<RemoveLocal>(request.body.clone()) else {
        return Err(refused("ConfirmationRequired", "confirmation_required"));
    };
    if body.confirmation != id {
        return Err(refused("ConfirmationRequired", "confirmation_required"));
    }
    Ok(())
}

/// Drops the confirmation text so a later log cannot print it.
pub(super) fn wipe_confirmation(body: &mut serde_json::Value) {
    if let Some(value) = body.get_mut("confirmation") {
        *value = serde_json::Value::Null;
    }
}

/// An account is present when custody still has it or the index row is not `removed`.
///
/// # Errors
/// Returns index and filesystem errors other than a missing row.
pub(super) fn present(index: &AccountIndex, root: &Path, id: &str) -> Result<bool, SdkError> {
    if crate::custody::account_exists(root, id)? {
        return Ok(true);
    }
    match index.account(id) {
        Ok(record) => Ok(record.account_state != "removed"),
        Err(ramflux_storage::StorageError::AccountNotFound(_)) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Local wipe: vault items, the account database, the custody tree, then the active pointer.
///
/// When the removed account was active, the pointer moves to another on-disk account.
/// When none remains, the pointer is cleared and a later list still succeeds.
/// A busy writer fails before the custody tree is removed. `AccountNotFound` from the index
/// is success for a custody-only account. There is no network call.
///
/// # Errors
/// Returns vault, writer, or filesystem errors.
pub(super) fn erase(
    index: &AccountIndex,
    root: &Path,
    vault: &dyn crate::custody::PrimaryVault,
    id: &str,
) -> Result<(), SdkError> {
    delete_secrets(root, vault, id)?;
    forget_database(index, id)?;
    crate::custody::remove_custody_tree(root, id)?;
    index.release_active_account(id)?;
    Ok(())
}

/// Refusal for a second remove after the account is already gone.
#[must_use]
pub(super) fn missing() -> SdkError {
    refused("AccountNotFound", "account_not_found")
}

fn removed(index: &AccountIndex, id: &str) -> bool {
    index.account(id).is_ok_and(|record| record.account_state == "removed")
}

fn custody_rows(root: &Path) -> Result<Vec<Listed>, SdkError> {
    let mut known = Vec::new();
    append_custody(root, &mut known)?;
    Ok(known)
}

fn append_custody(root: &Path, known: &mut Vec<Listed>) -> Result<(), SdkError> {
    for mut account in crate::custody::list_accounts(root, super::custody_setup::now()?)? {
        let Some(id) = account.get("local_account_id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let id = id.to_owned();
        if id.is_empty() {
            continue;
        }
        if let Some(map) = account.as_object_mut() {
            map.insert("id".to_owned(), serde_json::Value::String(id));
        }
        known.push((account, false));
    }
    Ok(())
}

fn manifest_row(root: &Path, id: &str) -> (serde_json::Value, bool) {
    let path = super::daemon::local_bus_account_manifest_path(root, id);
    let (manifest, unreadable) = if super::daemon::account_manifest_available(&path) {
        if let Ok(manifest) = super::daemon::read_local_bus_account_manifest(&path) {
            (Some(manifest), false)
        } else {
            tracing::warn!(
                account_id = %id,
                reason_code = "manifest_unreadable",
                "account list omitted unreadable manifest metadata"
            );
            (None, true)
        }
    } else {
        (None, false)
    };
    let row = serde_json::json!({
        "id": id,
        "label": manifest.as_ref().and_then(|item| item.label.clone()),
        "kind": manifest.as_ref().and_then(|item| item.kind.clone()),
        "principal_id": manifest.as_ref().map(|item| item.principal_id.clone()),
    });
    (row, unreadable)
}

fn attach_picker_fields(row: &mut serde_json::Value, locked: bool) {
    let display = row
        .get("display_name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .or_else(|| row.get("label").and_then(serde_json::Value::as_str).map(str::to_owned))
        .unwrap_or_default();
    if let Some(map) = row.as_object_mut() {
        map.insert("display_name".to_owned(), serde_json::Value::String(display));
        map.insert("locked".to_owned(), serde_json::Value::Bool(locked));
    }
}

fn delete_secrets(
    root: &Path,
    vault: &dyn crate::custody::PrimaryVault,
    id: &str,
) -> Result<(), SdkError> {
    crate::client::device_unlock::delete_device_secret(vault, id)?;
    let Ok(account) = crate::custody::load_data_account(root, id, super::custody_setup::now()?)
    else {
        return Ok(());
    };
    delete_ref(vault, account.branch_vault_ref())?;
    delete_ref(vault, account.primary_vault_ref())?;
    if let Some(reference) = account.provisioning_vault_ref() {
        delete_ref(vault, reference)?;
    }
    Ok(())
}

fn delete_ref(vault: &dyn crate::custody::PrimaryVault, reference: &str) -> Result<(), SdkError> {
    if reference.is_empty() {
        return Ok(());
    }
    vault.delete(reference)
}

fn forget_database(index: &AccountIndex, id: &str) -> Result<(), SdkError> {
    match index.erase_account_database(id) {
        Ok(()) | Err(ramflux_storage::StorageError::AccountNotFound(_)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn refused(code: &str, reason: &str) -> SdkError {
    SdkError::LocalBusRefused {
        code: code.to_owned(),
        message: reason.replace('_', " "),
        body: Box::new(serde_json::json!({"reason_code": reason})),
    }
}
