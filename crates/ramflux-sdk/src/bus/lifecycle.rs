// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Supervisor-side idempotency for lifecycle and public node metadata operations.

use crate::prelude::*;

tokio::task_local! {
    pub(super) static ROOT_LEASE: Option<std::sync::Arc<super::data_root_lock::DataRootLock>>;
}

// Blocking work can outlive its cancelled async waiter and must keep daemon ownership.
pub(super) fn spawn_blocking<F, R>(work: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let lease = ROOT_LEASE.try_with(Clone::clone).ok().flatten();
    tokio::task::spawn_blocking(move || {
        let _lease = lease;
        work()
    })
}

pub(super) struct Receipt {
    pub(super) scope: String,
    pub(super) operation: String,
    pub(super) fingerprint: String,
    pub cached: Option<serde_json::Value>,
}

pub(super) fn handles(method: &str) -> bool {
    matches!(
        method,
        "account.create"
            | "account.itest_legacy.create"
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

pub(super) async fn fingerprint(
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
    } else if matches!(request.method.as_str(), "account.create" | "account.itest_legacy.create") {
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
    spawn_blocking(move || {
        // A keyed intent fingerprint cannot become a fast offline passphrase verifier in the
        // unencrypted index. Account/domain responses are never stored here.
        let vault = FileVaultSecretSource::new(root).vault_secret("supervisor.lifecycle")?;
        let fingerprint = ramflux_protocol::encode_base64url(ramflux_crypto::blake3_keyed_derive(
            &vault, &intent,
        ));
        Ok(Some(Receipt { scope, operation, fingerprint, cached: None }))
    })
    .await
    .map_err(|error| SdkError::LocalBus(format!("supervisor receipt worker failed: {error}")))?
}

pub(super) fn takeover_eligible(method: &str) -> bool {
    matches!(method, "account.unlock" | "account.lock" | "account.switch")
}

pub(super) async fn reserve(
    index: AccountIndex,
    root: PathBuf,
    request: &LocalBusFrame,
) -> Result<Option<Receipt>, SdkError> {
    reserve_fingerprint(index, fingerprint(root, request).await?, None).await
}

pub(super) async fn reserve_fingerprint(
    index: AccountIndex,
    receipt: Option<Receipt>,
    method: Option<&str>,
) -> Result<Option<Receipt>, SdkError> {
    let Some(mut receipt) = receipt else { return Ok(None) };
    let takeover = method.is_some_and(takeover_eligible);
    let typed = method.is_some();
    spawn_blocking(move || {
        if typed {
            match index.lookup_supervisor_operation(
                &receipt.scope,
                &receipt.operation,
                &receipt.fingerprint,
            )? {
                ramflux_storage::OperationLookup::Pending if takeover => {
                    index.take_over_supervisor_operation(
                        &receipt.scope,
                        &receipt.operation,
                        &receipt.fingerprint,
                    )?;
                    return Ok(Some(receipt));
                }
                ramflux_storage::OperationLookup::Pending => {
                    return Err(SdkError::OperationReconciliationRequired(receipt.operation));
                }
                _ => {}
            }
        }
        receipt.cached = index.reserve_supervisor_operation(
            &receipt.scope,
            &receipt.operation,
            &receipt.fingerprint,
        )?;
        Ok(Some(receipt))
    })
    .await
    .map_err(|error| SdkError::LocalBus(format!("supervisor receipt worker failed: {error}")))?
}

pub(super) async fn complete(
    index: AccountIndex,
    receipt: Receipt,
    body: serde_json::Value,
) -> Result<(), SdkError> {
    spawn_blocking(move || {
        index.complete_supervisor_operation(&receipt.scope, &receipt.operation, &body)
    })
    .await
    .map_err(|error| SdkError::LocalBus(format!("supervisor receipt worker failed: {error}")))??;
    Ok(())
}

pub(super) async fn import_account_id(request: &LocalBusFrame) -> Result<String, SdkError> {
    let body: LocalBusAccountBackupImportRequest = serde_json::from_value(request.body.clone())
        .map_err(|_| SdkError::LocalBus("invalid account request".to_owned()))?;
    spawn_blocking(move || local_bus_backup_account_id(body))
        .await
        .map_err(|error| SdkError::LocalBus(format!("backup inspection failed: {error}")))?
}

/// Holds a lifecycle operation at a selected boundary and signals durable completion.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestGate {
    pub before_creation: bool,
    pub fingerprint_barrier: Option<std::sync::Arc<tokio::sync::Barrier>>,
    pub before_receipt: bool,
    pub joined: tokio::sync::Notify,
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
    pub completed: tokio::sync::Notify,
    pub draining: tokio::sync::Notify,
    pub executions: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
pub(super) async fn hold_claimed(config: &LocalBusConfig, command: &super::actor::AccountCommand) {
    if command.request.method == "account.unlock"
        && let Some(gate) = &config.lifecycle_gate
        && !gate.before_creation
        && !gate.before_receipt
    {
        gate.executions.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        gate.entered.notify_one();
        gate.release.notified().await;
    }
}

#[cfg(test)]
pub(super) async fn hold_before_creation(config: &LocalBusConfig) {
    if let Some(gate) = &config.lifecycle_gate
        && gate.before_creation
    {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_lifecycle_worker_retains_data_root_lease_until_quiescent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let lease = super::super::data_root_lock::DataRootLock::acquire(&root.0)?;
        let (entered, running) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let (finished, done) = tokio::sync::oneshot::channel();
        let worker = ROOT_LEASE.sync_scope(Some(lease.clone()), || {
            spawn_blocking(move || {
                let _ = entered.send(());
                let _ = held.recv();
            })
        });
        tokio::time::timeout(Duration::from_secs(5), running).await??;
        // Aborting an already-running blocking worker cannot cancel its write.
        worker.abort();
        drop(lease);
        assert!(matches!(
            super::super::data_root_lock::DataRootLock::acquire(&root.0),
            Err(SdkError::DataRootInUse)
        ));
        tokio::spawn(async move {
            let _ = worker.await;
            let _ = finished.send(());
        });
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(5), done).await??;
        assert!(super::super::data_root_lock::DataRootLock::acquire(&root.0).is_ok());
        Ok(())
    }
}
