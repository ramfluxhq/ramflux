// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lost lifecycle holders are recoverable only for idempotent local operations.

use super::*;
use crate::bus::lifecycle::{self, TestGate};
use serde_json::json;
type Case = Result<(), Box<dyn std::error::Error>>;

fn unlock() -> LocalBusFrame {
    let mut request =
        request("takeover", "alice", "account.unlock", json!({"passphrase":"actor-test-secret"}));
    request.operation_id = Some("old-key".into());
    request
}
async fn seed(supervisor: &Supervisor, root: &Path, request: &LocalBusFrame) -> Case {
    // The pre-upgrade writer uses the exact existing schema and keyed fingerprint.
    assert!(
        lifecycle::reserve(supervisor.index.clone(), root.to_path_buf(), request)
            .await?
            .ok_or("missing key")?
            .cached
            .is_none()
    );
    Ok(())
}
async fn lost_holder() -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("lost-holder");
            drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
            let supervisor = Supervisor::new(LocalBusConfig::new(root.join("bus.sock"), &root))?;
            let initial = unlock();
            seed(&supervisor, &root, &initial).await?;
            let (outbound, _) = mpsc::channel(8);
            let connection = LocalBusConnectionState::new(1, outbound);
            assert_eq!(
                supervisor.request(initial, &connection).await?.body["local_account_id"],
                "alice"
            );
            assert!(supervisor.account_is_open("alice"));
            for method in ["account.unlock", "account.lock", "account.switch"] {
                assert!(lifecycle::takeover_eligible(method));
            }
            let mut node = request("node", "alice", "node.add", json!({}));
            node.operation_id = Some("node-pending".into());
            seed(&supervisor, &root, &node).await?;
            let (mut client, server) = UnixStream::pair()?;
            let owner = supervisor.clone();
            let handler = tokio::task::spawn_local(async move {
                crate::bus::connection::handle(server, owner, 2).await
            });
            write_local_bus_frame(&mut client, &node).await?;
            let response =
                tokio::time::timeout(Duration::from_secs(5), read_local_bus_frame(&mut client))
                    .await??;
            let error = response.error.ok_or("pending node operation was accepted")?;
            assert_eq!(error.code, "OperationReconciliationRequired");
            assert!(error.message.contains("operation requires reconciliation"));
            assert!(!lifecycle::takeover_eligible("account.create"));
            drop(client);
            handler.await??;
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}
#[tokio::test(flavor = "current_thread")]
async fn lost_holder_takeover_only_for_idempotent_methods() -> Case {
    lost_holder().await
}
#[tokio::test(flavor = "current_thread")]
async fn pre_upgrade_pending_rows_are_takeover_eligible_for_idempotent_methods_only() -> Case {
    lost_holder().await
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_takeover_runs_once() -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("concurrent-takeover");
            drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
            let gate = Arc::new(TestGate {
                fingerprint_barrier: Some(Arc::new(tokio::sync::Barrier::new(3))),
                ..TestGate::default()
            });
            let mut config = LocalBusConfig::new(root.join("bus.sock"), &root);
            config.lifecycle_gate = Some(gate.clone());
            let supervisor = Supervisor::new(config)?;
            let request = unlock();
            seed(&supervisor, &root, &request).await?;
            let mut tasks = Vec::new();
            for id in 1..=2 {
                let owner = supervisor.clone();
                let request = request.clone();
                tasks.push(tokio::task::spawn_local(async move {
                    let (outbound, _) = mpsc::channel(8);
                    owner.request(request, &LocalBusConnectionState::new(id, outbound)).await
                }));
            }
            tokio::time::timeout(
                Duration::from_secs(5),
                gate.fingerprint_barrier.as_ref().ok_or("missing barrier")?.wait(),
            )
            .await?;
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await?;
            tokio::time::timeout(Duration::from_secs(5), gate.joined.notified()).await?;
            gate.release.notify_one();
            let first = tasks.remove(0).await??;
            let second = tasks.remove(0).await??;
            assert_eq!(first.body, second.body);
            assert_eq!(gate.executions.load(Ordering::SeqCst), 1);
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn failed_unlock_same_key_retry_reexecutes() -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("failed-takeover");
            drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
            let gate = Arc::new(TestGate::default());
            let mut config = LocalBusConfig::new(root.join("bus.sock"), &root);
            config.lifecycle_gate = Some(gate.clone());
            let supervisor = Supervisor::new(config)?;
            let mut request = unlock();
            request.body["passphrase"] = json!("wrong");
            for count in 1..=2 {
                let owner = supervisor.clone();
                let request = request.clone();
                let task = tokio::task::spawn_local(async move {
                    let (outbound, _) = mpsc::channel(8);
                    owner.request(request, &LocalBusConnectionState::new(count, outbound)).await
                });
                tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await?;
                assert_eq!(gate.executions.load(Ordering::SeqCst), usize::try_from(count)?);
                gate.release.notify_one();
                let error = task.await?.err().ok_or("wrong passphrase succeeded")?;
                assert!(!error.to_string().contains("requires reconciliation"));
            }
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn restore_does_not_import_pending_receipts_as_live() -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("restore-pending-receipt");
            drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
            let config = LocalBusConfig::new(root.join("bus.sock"), &root);
            let supervisor = Supervisor::new(config.clone())?;
            seed(&supervisor, &root, &unlock()).await?;
            drop(supervisor);
            let supervisor = Supervisor::new(config)?;
            let mut events = super::restore::subscribe_restore(&supervisor);
            let mut tasks = tokio::task::JoinSet::new();
            supervisor.hydrate(&mut tasks)?;
            assert_eq!(super::restore::restore_event(&mut events).await?.body["state"], "unlocked");
            while let Some(task) = tasks.join_next().await {
                task?;
            }
            let receipt = lifecycle::fingerprint(root.to_path_buf(), &unlock())
                .await?
                .ok_or("missing key")?;
            assert!(matches!(
                supervisor.index.lookup_supervisor_operation(
                    &receipt.scope,
                    &receipt.operation,
                    &receipt.fingerprint
                )?,
                ramflux_storage::OperationLookup::Pending
            ));
            let (outbound, _) = mpsc::channel(8);
            assert_eq!(
                supervisor
                    .request(unlock(), &LocalBusConnectionState::new(1, outbound))
                    .await?
                    .body["local_account_id"],
                "alice"
            );
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn actor_mutation_pending_receipt_still_requires_reconciliation() -> Case {
    let root = root("actor-pending-receipt");
    let db = account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    let mut request = request("block", "alice", "contact.block", json!({"contact_id":"bob"}));
    request.operation_id = Some("block-key".into());
    let intent = crate::bus::mutation_intent::MutationIntent::new(&request)?;
    assert!(intent.reserve(db.client.account_db()?)?.is_none());
    let error =
        intent.lookup(db.client.account_db()?).err().ok_or("actor pending row was accepted")?;
    assert!(error.to_string().contains("operation requires reconciliation"));
    assert!(intent.reserve(db.client.account_db()?).is_err());
    drop(db);
    Ok(())
}
