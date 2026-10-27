// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Startup restore races and authenticated repeated unlocks.

use super::*;

fn persisted_account(root: &Path) -> Result<(), SdkError> {
    drop(account(root, "alice", None, Arc::new(AtomicBool::new(false)))?);
    Ok(())
}

fn subscribe_restore(supervisor: &Supervisor) -> mpsc::Receiver<LocalBusFrame> {
    let (outbound, receiver) = mpsc::channel(8);
    let mut connection = LocalBusConnectionState::new(99, outbound);
    connection.topics.insert("account.restore.finished".to_owned());
    supervisor.subscribe(&connection, "alice".to_owned());
    receiver
}

async fn restore_event(
    receiver: &mut mpsc::Receiver<LocalBusFrame>,
) -> Result<LocalBusFrame, SdkError> {
    tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .map_err(|_| failure("restore must finish"))?
        .ok_or_else(|| failure("restore event channel must stay open"))
}

#[tokio::test(flavor = "current_thread")]
async fn immediate_unlock_and_startup_restore_succeed_in_both_orders() -> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            for restore_first in [false, true] {
                let root = root("restore-race");
                persisted_account(&root)?;
                let config = LocalBusConfig::new(root.join("bus.sock"), &root);
                let supervisor = Supervisor::new(config)?;
                let mut events = subscribe_restore(&supervisor);
                let mut background = tokio::task::JoinSet::new();
                supervisor.hydrate(&mut background)?;
                let (outbound, _receiver) = mpsc::channel(8);
                let connection = LocalBusConnectionState::new(1, outbound);
                if restore_first {
                    // Explicitly exercise the already-open path as well as overlapping restore.
                    assert_eq!(restore_event(&mut events).await?.body["state"], "unlocked");
                }
                let unlock = request(
                    "immediate-unlock",
                    "alice",
                    "account.unlock",
                    serde_json::json!({"passphrase":"actor-test-secret"}),
                );
                let response = supervisor.request(unlock.clone(), &connection).await?;
                assert_eq!(response.body["local_account_id"], "alice");
                if !restore_first {
                    assert_eq!(restore_event(&mut events).await?.body["state"], "unlocked");
                }
                assert_eq!(supervisor.request(unlock, &connection).await?.body, response.body);
                let bad = request(
                    "bad-secret",
                    "alice",
                    "account.unlock",
                    serde_json::json!({"passphrase":"wrong-secret"}),
                );
                assert!(supervisor.request(bad, &connection).await.is_err());
                // Rejection must leave the live actor usable.
                assert!(supervisor.account_actor("alice").is_some_and(|actor| actor.is_open()));
                while let Some(task) = background.join_next().await {
                    task.map_err(|_| failure("restore task panicked"))?;
                }
                supervisor.shutdown().await?;
                drop(supervisor);
                std::fs::remove_dir_all(root)?;
            }
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn startup_restore_failure_emits_structured_error_and_allows_retry() -> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("restore-failed");
            persisted_account(&root)?;
            let path = local_bus_account_manifest_path(&root, "alice");
            let mut manifest = read_local_bus_account_manifest(&path)?;
            manifest.account_secret = "invalid-startup-secret".to_owned();
            write_local_bus_account_manifest(&root, &manifest)?;
            let supervisor = Supervisor::new(LocalBusConfig::new(root.join("bus.sock"), &root))?;
            let (outbound, _events) = mpsc::channel(8);
            let connection = LocalBusConnectionState::new(2, outbound);
            let (mut client, server) = client(Rc::clone(&supervisor), 1).await?;
            client
                .request_frame(request(
                    "subscribe",
                    "alice",
                    "subscription.open",
                    serde_json::json!({"topics":["account.restore.finished"]}),
                ))
                .await?;
            let mut background = tokio::task::JoinSet::new();
            supervisor.hydrate(&mut background)?;
            let event = tokio::time::timeout(Duration::from_secs(5), client.next_event())
                .await
                .map_err(|_| failure("restore event timed out"))??;
            assert_eq!(event.method, "account.restore.finished");
            assert_eq!(event.account_id.as_deref(), Some("alice"));
            assert_eq!(event.body["state"], "failed");
            assert_eq!(event.body["error"]["code"], "ValidationFailed");
            assert!(
                event.body["error"]["message"].as_str().is_some_and(|message| !message.is_empty())
            );
            assert!(!serde_json::to_string(&event)?.contains("invalid-startup-secret"));
            assert!(matches!(
                supervisor
                    .request(
                        request("status", "alice", "account.status", serde_json::json!({})),
                        &connection
                    )
                    .await,
                Err(SdkError::AccountRestoreFailed { .. })
            ));
            let list = supervisor
                .request(
                    request("list", "alice", "account.list", serde_json::json!({})),
                    &connection,
                )
                .await?;
            assert_eq!(list.body["account_details"][0]["state"], "restore_failed");
            let unlocked = client
                .request_frame(request(
                    "retry",
                    "alice",
                    "account.unlock",
                    serde_json::json!({"passphrase":"actor-test-secret"}),
                ))
                .await?;
            assert_eq!(unlocked["local_account_id"], "alice");
            let list = supervisor
                .request(
                    request("list-again", "alice", "account.list", serde_json::json!({})),
                    &connection,
                )
                .await?;
            assert_eq!(list.body["account_details"][0]["state"], "unlocked");
            assert!(
                client
                    .request_frame(request(
                        "stale-secret",
                        "alice",
                        "account.unlock",
                        serde_json::json!({"passphrase":"invalid-startup-secret"}),
                    ))
                    .await
                    .is_err()
            );
            while let Some(task) = background.join_next().await {
                task.map_err(|_| failure("restore task panicked"))?;
            }
            drop(client);
            server.await.map_err(|_| failure("connection task panicked"))??;
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test]
async fn daemon_start_and_immediate_socket_unlock_are_race_free() -> Result<(), SdkError> {
    let root = root("restore-socket");
    persisted_account(&root)?;
    let socket = root.join("bus.sock");
    let (shutdown, receiver) = watch::channel(false);
    let server = serve_local_bus_until(LocalBusConfig::new(&socket, &root), receiver);
    let client_flow = async {
        let client = loop {
            if let Ok(client) = LocalBusClient::connect(&socket).await {
                break client;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        };
        let response = client
            .request_frame(request(
                "unlock",
                "alice",
                "account.unlock",
                serde_json::json!({"passphrase":"actor-test-secret"}),
            ))
            .await?;
        assert_eq!(response["local_account_id"], "alice");
        assert!(
            client
                .request_frame(request(
                    "bad",
                    "alice",
                    "account.unlock",
                    serde_json::json!({"passphrase":"wrong-secret"})
                ))
                .await
                .is_err()
        );
        shutdown.send_replace(true);
        Ok::<_, SdkError>(())
    };
    let (daemon_result, unlocked) =
        tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(server, client_flow) })
            .await
            .map_err(|_| failure("daemon start/unlock must not hang"))?;
    daemon_result?;
    unlocked?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn a_real_daemon_emits_account_not_open_after_lock_and_for_missing_accounts()
-> Result<(), SdkError> {
    let root = root("closed-account-code");
    persisted_account(&root)?;
    let socket = root.join("bus.sock");
    let (shutdown, receiver) = watch::channel(false);
    let server = serve_local_bus_until(LocalBusConfig::new(&socket, &root), receiver);
    let flow = async {
        let client = loop {
            if let Ok(client) = LocalBusClient::connect(&socket).await {
                break client;
            }
            tokio::task::yield_now().await;
        };
        client
            .request_frame(request(
                "unlock",
                "alice",
                "account.unlock",
                serde_json::json!({"passphrase":"actor-test-secret"}),
            ))
            .await?;
        client
            .request_frame(request("lock", "alice", "account.lock", serde_json::json!({})))
            .await?;
        for account in ["alice", "missing"] {
            for method in ["account.status", "device.list", "message.receive", "account.switch"] {
                let response = client
                    .request_frame_response(request(method, account, method, serde_json::json!({})))
                    .await?;
                assert_eq!(
                    response.error.as_ref().map(|error| error.code.as_str()),
                    Some("AccountNotOpen"),
                    "{account}/{method}: {response:?}"
                );
            }
        }
        shutdown.send_replace(true);
        Ok::<(), SdkError>(())
    };
    let (server, flow) =
        tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(server, flow) })
            .await
            .map_err(|_| failure("closed-account code test timed out"))?;
    server?;
    flow?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
