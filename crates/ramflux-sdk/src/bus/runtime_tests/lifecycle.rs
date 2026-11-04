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

async fn stop_daemon(socket: PathBuf) -> Result<(), SdkError> {
    let mut client = UnixStream::connect(socket).await?;
    write_local_bus_frame(&mut client, &request("stop", "alice", "daemon.stop", json!({}))).await?;
    let response = read_local_bus_frame(&mut client).await?;
    assert_eq!(response.ok, Some(true));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_stop_aborts_a_stuck_lifecycle_task_within_five_seconds() -> Case {
    for explicit in [false, true] {
        for stuck in [false, true] {
            LocalSet::new()
                .run_until(async {
                    let root = root("lifecycle-stop");
                    drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
                    let gate = Arc::new(TestGate { before_creation: true, ..TestGate::default() });
                    let mut config = LocalBusConfig::new(root.join("bus.sock"), &root);
                    config.lifecycle_gate = Some(gate.clone());
                    let listener = UnixListener::bind(&config.socket_path)?;
                    let uid = std::fs::metadata(&config.socket_path)?.uid();
                    let supervisor = Supervisor::new(config)?;
                    let (shutdown, receiver) = watch::channel(false);
                    let owner = supervisor.clone();
                    let daemon = tokio::task::spawn_local(async move {
                        crate::bus::connection::accept(listener, uid, owner, receiver).await
                    });
                    let mut unlock = request(
                        "stop-unlock",
                        "alice",
                        "account.unlock",
                        json!({"passphrase":"actor-test-secret"}),
                    );
                    unlock.operation_id = Some("stop-unlock-key".into());
                    let owner = supervisor.clone();
                    let mut waiter = tokio::task::spawn_local(async move {
                        let (outbound, _replies) = mpsc::channel(8);
                        owner.request(unlock, &LocalBusConnectionState::new(9, outbound)).await
                    });
                    bounded(&gate.entered).await?;
                    assert!(supervisor.account_actor("alice").is_none());
                    assert_eq!(supervisor.lifecycle_task_count(), 1);
                    let stop_response = if explicit {
                        Some(tokio::task::spawn_local(stop_daemon(root.join("bus.sock"))))
                    } else {
                        shutdown.send(true)?;
                        None
                    };
                    bounded(&gate.draining).await?;
                    // Both paths close admission before lifecycle work can make a late actor.
                    let (outbound, _replies) = mpsc::channel(8);
                    let refused = supervisor
                        .request(
                            request("late", "alice", "account.unlock", json!({})),
                            &LocalBusConnectionState::new(10, outbound),
                        )
                        .await;
                    assert!(refused.is_err());
                    let aborted_response = if stuck {
                        tokio::time::pause();
                        let started = tokio::time::Instant::now();
                        tokio::time::advance(Duration::from_secs(5)).await;
                        let response =
                            tokio::time::timeout(Duration::from_secs(1), &mut waiter).await??;
                        // Tokio timers round up to the next millisecond.
                        assert!(started.elapsed() <= Duration::from_millis(5_001));
                        tokio::time::resume();
                        Some(response)
                    } else {
                        gate.release.notify_one();
                        None
                    };
                    tokio::time::timeout(Duration::from_secs(5), daemon).await???;
                    if let Some(stop_response) = stop_response {
                        stop_response.await??;
                    }
                    let response = match aborted_response {
                        Some(response) => response,
                        None => tokio::time::timeout(Duration::from_secs(1), waiter).await??,
                    };
                    if stuck {
                        assert!(response.is_err());
                        assert!(supervisor.account_actor("alice").is_none());
                    } else {
                        response?;
                        assert!(
                            supervisor
                                .account_actor("alice")
                                .ok_or("missing drained actor")?
                                .has_stopped(),
                            "late actor escaped final stop snapshot (explicit={explicit})"
                        );
                    }
                    assert_eq!(supervisor.lifecycle_task_count(), 0);
                    gate.release.notify_one();
                    tokio::task::yield_now().await;
                    assert!(
                        supervisor.account_actor("alice").is_none_or(|actor| actor.has_stopped())
                    );
                    drop(supervisor);
                    std::fs::remove_dir_all(root)?;
                    Ok::<(), Box<dyn std::error::Error>>(())
                })
                .await?;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn completed_lifecycle_tasks_are_reaped_while_daemon_is_idle() -> Case {
    LocalSet::new()
        .run_until(async {
            let root = root("lifecycle-reap");
            drop(account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?);
            let config = LocalBusConfig::new(root.join("bus.sock"), &root);
            let listener = UnixListener::bind(&config.socket_path)?;
            let uid = std::fs::metadata(&config.socket_path)?.uid();
            let supervisor = Supervisor::new(config)?;
            let (shutdown, receiver) = watch::channel(false);
            let owner = supervisor.clone();
            let daemon = tokio::task::spawn_local(async move {
                crate::bus::connection::accept(listener, uid, owner, receiver).await
            });
            let mut unlock = request(
                "reap",
                "alice",
                "account.unlock",
                json!({"passphrase":"actor-test-secret"}),
            );
            unlock.operation_id = Some("reap-key".into());
            let (outbound, _replies) = mpsc::channel(8);
            supervisor.request(unlock, &LocalBusConnectionState::new(1, outbound)).await?;
            tokio::time::timeout(Duration::from_secs(5), async {
                while supervisor.lifecycle_task_count() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            shutdown.send(true)?;
            tokio::time::timeout(Duration::from_secs(5), daemon).await???;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}
