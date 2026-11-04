// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Concurrent lifecycle retries share the original execution through durable completion.

use super::*;
use crate::bus::lifecycle::TestGate;
use serde_json::json;
type Case = Result<(), Box<dyn std::error::Error>>;

async fn bounded(signal: &tokio::sync::Notify) -> Case {
    tokio::time::timeout(Duration::from_secs(5), signal.notified()).await?;
    Ok(())
}

async fn concurrent(before_receipt: bool, changed: bool) -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("registry-retry");
            drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
            let gate = Arc::new(TestGate { before_receipt, ..TestGate::default() });
            let mut config = LocalBusConfig::new(root.join("bus.sock"), &root);
            config.lifecycle_gate = Some(gate.clone());
            let supervisor = Supervisor::new(config)?;
            let mut unlock = request(
                "original",
                "alice",
                "account.unlock",
                json!({"passphrase":"actor-test-secret"}),
            );
            unlock.operation_id = Some("joined-key".into());
            let owner = supervisor.clone();
            let original = unlock.clone();
            let first = tokio::task::spawn_local(async move {
                let (outbound, _) = mpsc::channel(8);
                owner.request(original, &LocalBusConnectionState::new(1, outbound)).await
            });
            bounded(&gate.entered).await?;
            if before_receipt {
                assert!(supervisor.account_is_open("alice"));
                let pending =
                    crate::bus::lifecycle::reserve(supervisor.index.clone(), root.clone(), &unlock)
                        .await;
                assert!(
                    pending
                        .err()
                        .ok_or("receipt already completed")?
                        .to_string()
                        .contains("requires reconciliation")
                );
            }
            unlock.request_id = "retry".into();
            if changed {
                unlock.body["passphrase"] = json!("different");
            }
            let owner = supervisor.clone();
            let mut retry = tokio::task::spawn_local(async move {
                let (outbound, _) = mpsc::channel(8);
                owner.request(unlock, &LocalBusConnectionState::new(2, outbound)).await
            });
            if changed {
                let error = tokio::time::timeout(Duration::from_secs(5), &mut retry)
                    .await??
                    .err()
                    .ok_or("changed retry accepted")?;
                assert_eq!(crate::bus::io::local_bus_error_code(&error), "ValidationFailed");
            } else {
                tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::select! {
                        () = gate.joined.notified() => Ok::<(), Box<dyn std::error::Error>>(()),
                        result = &mut retry => {
                            result??;
                            Err("retry completed before the original".into())
                        }
                    }
                })
                .await??;
                assert!(!retry.is_finished());
            }
            gate.release.notify_one();
            let original = tokio::time::timeout(Duration::from_secs(5), first).await???;
            if !changed {
                let replay = tokio::time::timeout(Duration::from_secs(5), retry).await???;
                assert_eq!(original.body, replay.body);
            }
            if !before_receipt {
                assert_eq!(gate.executions.load(Ordering::SeqCst), 1);
            }
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}
#[tokio::test(flavor = "current_thread")]
async fn retry_while_in_flight_waits_for_the_original() -> Case {
    concurrent(false, false).await
}
#[tokio::test(flavor = "current_thread")]
async fn retry_before_receipt_completion_joins_the_registry() -> Case {
    concurrent(true, false).await
}
#[tokio::test(flavor = "current_thread")]
async fn in_flight_retry_with_changed_body_is_refused_as_conflict() -> Case {
    concurrent(false, true).await
}

#[tokio::test(flavor = "current_thread")]
async fn failed_unlock_clears_in_flight_and_fresh_key_unlocks() -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("registry-failure");
            drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
            let supervisor = Supervisor::new(LocalBusConfig::new(root.join("bus.sock"), &root))?;
            let (outbound, _) = mpsc::channel(8);
            let connection = LocalBusConnectionState::new(1, outbound);
            let mut unlock =
                request("bad", "alice", "account.unlock", json!({"passphrase":"wrong"}));
            unlock.operation_id = Some("failed-key".into());
            assert!(supervisor.request(unlock.clone(), &connection).await.is_err());
            // A released entry re-executes the pending unlock, rather than joining the old error.
            let error = supervisor
                .request(unlock.clone(), &connection)
                .await
                .err()
                .ok_or("wrong passphrase accepted")?;
            assert!(!error.to_string().contains("requires reconciliation"));
            unlock.body["passphrase"] = json!("actor-test-secret");
            unlock.operation_id = Some("fresh-key".into());
            assert_eq!(
                supervisor.request(unlock, &connection).await?.body["local_account_id"],
                "alice"
            );
            assert!(supervisor.account_is_open("alice"));
            assert_eq!(supervisor.index.account("alice")?.account_state, "active");
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}
