// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Supervisor-side idempotency for lifecycle and public node metadata operations.

use crate::prelude::*;

pub(super) struct Receipt {
    scope: String,
    operation: String,
    pub cached: Option<serde_json::Value>,
}

pub(super) fn handles(method: &str) -> bool {
    matches!(
        method,
        "account.create"
            | "account.unlock"
            | "account.lock"
            | "account.switch"
            | "account.backup.import"
            | "account.backup.export"
            | "account.passphrase.rotate"
            | "node.add"
            | "node.confirm"
            | "node.set_enabled"
            | "node.remove"
            | "node.set_default"
    )
}

pub(super) async fn reserve(
    index: AccountIndex,
    root: PathBuf,
    request: &LocalBusFrame,
) -> Result<Option<Receipt>, SdkError> {
    let Some(operation) = request
        .operation_id
        .as_deref()
        .or_else(|| request.body.get("idempotency_key").and_then(serde_json::Value::as_str))
    else {
        return Ok(None);
    };
    if operation.is_empty() || operation.len() > 256 {
        return Err(SdkError::LocalBus("operation_id must contain 1 to 256 bytes".to_owned()));
    }
    let scope = if request.method.starts_with("node.") {
        String::new()
    } else if request.method == "account.create" {
        request
            .body
            .get("local_account_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SdkError::LocalBus("account.create requires local_account_id".to_owned())
            })?
            .to_owned()
    } else {
        request_account_id(request)?.to_owned()
    };
    let operation = operation.to_owned();
    let intent = ramflux_protocol::canonical_json_bytes(&(
        "ramflux.supervisor.operation.v1",
        &request.method,
        &request.body,
    ))?;
    tokio::task::spawn_blocking(move || {
        // A keyed intent fingerprint cannot become a fast offline passphrase verifier in the
        // unencrypted index. Account/domain responses are never stored here.
        let vault = FileVaultSecretSource::new(root).vault_secret("supervisor.lifecycle")?;
        let fingerprint = ramflux_protocol::encode_base64url(ramflux_crypto::blake3_keyed_derive(
            &vault, &intent,
        ));
        let cached = index.reserve_supervisor_operation(&scope, &operation, &fingerprint)?;
        Ok(Some(Receipt { scope, operation, cached }))
    })
    .await
    .map_err(|error| SdkError::LocalBus(format!("supervisor receipt worker failed: {error}")))?
}

pub(super) async fn complete(
    index: AccountIndex,
    receipt: Receipt,
    body: serde_json::Value,
) -> Result<(), SdkError> {
    tokio::task::spawn_blocking(move || {
        index.complete_supervisor_operation(&receipt.scope, &receipt.operation, &body)
    })
    .await
    .map_err(|error| SdkError::LocalBus(format!("supervisor receipt worker failed: {error}")))??;
    Ok(())
}

pub(super) async fn import_account_id(request: &LocalBusFrame) -> Result<String, SdkError> {
    let body: LocalBusAccountBackupImportRequest = serde_json::from_value(request.body.clone())?;
    tokio::task::spawn_blocking(move || local_bus_backup_account_id(body))
        .await
        .map_err(|error| SdkError::LocalBus(format!("backup inspection failed: {error}")))?
}
