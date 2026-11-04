// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client wait cancellation never owns keyed lifecycle execution or its receipt.

use super::*;
use crate::bus::lifecycle::TestGate;
use serde_json::json;

type Case = Result<(), Box<dyn std::error::Error>>;

async fn bounded(signal: &tokio::sync::Notify) -> Case {
    tokio::time::timeout(Duration::from_secs(5), signal.notified()).await?;
    Ok(())
}

async fn run(advance_deadlines: bool) -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("detached-lifecycle");
            drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
            let gate = Arc::new(TestGate::default());
            let mut config = LocalBusConfig::new(root.join("bus.sock"), &root);
            config.lifecycle_gate = Some(gate.clone());
            let supervisor = Supervisor::new(config)?;
            let (outbound, mut replies) = mpsc::channel(8);
            let connection = LocalBusConnectionState::new(1, outbound);
            let mut unlock = request(
                "detached-unlock",
                "alice",
                "account.unlock",
                json!({"passphrase":"actor-test-secret"}),
            );
            unlock.operation_id = Some("durable-unlock".into());
            unlock.deadline_ms = Some(
                u64::try_from(
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis(),
                )? + 2_000,
            );
            let owner = supervisor.clone();
            let original = unlock.clone();
            let waiter = tokio::task::spawn_local(async move {
                crate::bus::requests::respond(original, owner, connection).await
            });
            bounded(&gate.entered).await?;
            assert_eq!(gate.executions.load(Ordering::SeqCst), 1);
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(if advance_deadlines { 26 } else { 3 })).await;
            let (_, sent) = waiter.await?;
            sent?;
            tokio::time::resume();
            let response = replies.recv().await.ok_or("missing deadline response")?;
            assert_eq!(response.ok, Some(false));
            assert!(serde_json::to_string(&response)?.contains("request deadline exceeded"));
            gate.release.notify_one();
            bounded(&gate.completed).await?;
            assert_eq!(gate.executions.load(Ordering::SeqCst), 1);
            assert!(supervisor.account_is_open("alice"));
            assert!(
                supervisor.account_actor("alice").ok_or("missing actor")?.reader_pool().is_ok()
            );
            assert_eq!(supervisor.index.account("alice")?.account_state, "active");
            // Read the durable cached body before retrying, so the test does not depend on P3.
            let saved =
                crate::bus::lifecycle::reserve(supervisor.index.clone(), root.clone(), &unlock)
                    .await?
                    .ok_or("missing receipt")?
                    .cached
                    .ok_or("receipt still pending")?;
            let (outbound, _replies) = mpsc::channel(8);
            let retry = LocalBusConnectionState::new(2, outbound);
            unlock.deadline_ms = None;
            let replay = supervisor.request(unlock, &retry).await?;
            assert_eq!(replay.body, saved);
            assert_eq!(replay.body["local_account_id"], "alice");
            assert_eq!(gate.executions.load(Ordering::SeqCst), 1);
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn same_key_retry_after_client_timeout_returns_success() -> Case {
    run(false).await
}

#[tokio::test(flavor = "current_thread")]
async fn closed_connection_does_not_cancel_unlock() -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("disconnected-lifecycle");
            drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
            let gate = Arc::new(TestGate::default());
            let mut config = LocalBusConfig::new(root.join("bus.sock"), &root);
            config.lifecycle_gate = Some(gate.clone());
            let supervisor = Supervisor::new(config)?;
            let (mut client, server) = UnixStream::pair()?;
            let owner = supervisor.clone();
            let connection = tokio::task::spawn_local(async move {
                crate::bus::connection::handle(server, owner, 1).await
            });
            let mut unlock = request(
                "disconnect",
                "alice",
                "account.unlock",
                json!({"passphrase":"actor-test-secret"}),
            );
            unlock.operation_id = Some("disconnected-unlock".into());
            write_local_bus_frame(&mut client, &unlock).await?;
            bounded(&gate.entered).await?;
            drop(client);
            // Join the real connection handler: its response JoinSet has been cancelled.
            tokio::time::timeout(Duration::from_secs(5), connection).await???;
            gate.release.notify_one();
            bounded(&gate.completed).await?;
            assert_eq!(gate.executions.load(Ordering::SeqCst), 1);
            assert_eq!(supervisor.index.account("alice")?.account_state, "active");
            assert!(
                supervisor.account_actor("alice").ok_or("missing actor")?.reader_pool().is_ok()
            );
            let saved =
                crate::bus::lifecycle::reserve(supervisor.index.clone(), root.clone(), &unlock)
                    .await?
                    .ok_or("missing receipt")?
                    .cached
                    .ok_or("pending receipt")?;
            let (outbound, _replies) = mpsc::channel(8);
            let replay =
                supervisor.request(unlock, &LocalBusConnectionState::new(2, outbound)).await?;
            assert_eq!(replay.body, saved);
            assert_eq!(gate.executions.load(Ordering::SeqCst), 1);
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn claimed_lifecycle_outlives_actor_response_deadline() -> Case {
    run(true).await
}
