// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;

fn seeded(root: &Path, count: u64) -> AccountInitializer {
    let root = root.to_path_buf();
    Box::new(move |index| {
        let account = account_with_counter(
            &root,
            "bob",
            None,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicUsize::new(0)),
            Some(index),
        )?;
        for n in 1..=count {
            account.client.account_db()?.append_journal(
                &format!("seed:{n}"),
                "message.received",
                &serde_json::json!({"message_id":format!("m{n}"),"conversation_id":"c"}),
                now_unix_timestamp(),
                None,
            )?;
        }
        Ok(account)
    })
}
#[tokio::test(flavor = "current_thread")]
async fn replay_is_ordered_resumes_without_duplicates_and_rejects_cursor_below_floor()
-> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("stream-replay");
            let supervisor =
                supervisor(&root, BTreeMap::from([("bob".to_owned(), seeded(&root, 4))]))?;
            let (mut one, server) = client(Rc::clone(&supervisor), 1).await?;
            let response = one
                .request(
                    Some("bob".to_owned()),
                    "stream",
                    "bus.subscribe",
                    serde_json::json!({"topics":["message.received"],"since_seq":1}),
                )
                .await?;
            assert_eq!(response["floor_seq"], 1);
            for expected in 2..=4 {
                let event = tokio::time::timeout(Duration::from_secs(2), one.next_event())
                    .await
                    .map_err(|_| failure("replay timeout"))??;
                assert_eq!(event.seq, Some(expected));
                assert_eq!(event.body["message_id"], format!("m{expected}"));
                assert!(event.at.is_some());
            }
            one.request(
                Some("bob".to_owned()),
                "stream",
                "bus.subscribe",
                serde_json::json!({"topics":["message.received"],"since_seq":0}),
            )
            .await?;
            for expected in 1..=4 {
                let event = tokio::time::timeout(Duration::from_secs(2), one.next_event())
                    .await
                    .map_err(|_| failure("fresh replay timeout"))??;
                assert_eq!(event.seq, Some(expected));
                assert_eq!(event.body["message_id"], format!("m{expected}"));
            }
            drop(one);
            server.abort();
            let _ = server.await;
            let (mut two, server) = client(Rc::clone(&supervisor), 2).await?;
            two.request(
                Some("bob".to_owned()),
                "stream",
                "bus.subscribe",
                serde_json::json!({"topics":["message.received"],"since_seq":3}),
            )
            .await?;
            let event = two.next_event().await?;
            assert_eq!(event.seq, Some(4));
            assert!(
                tokio::time::timeout(Duration::from_millis(150), two.next_event()).await.is_err()
            );
            supervisor.shutdown().await?;
            drop(two);
            server.abort();
            let _ = server.await;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}
#[tokio::test(flavor = "current_thread")]
async fn slow_subscription_reports_lagged_and_retains_replayable_events() -> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("stream-lagged");
            let supervisor =
                supervisor(&root, BTreeMap::from([("bob".to_owned(), seeded(&root, 200))]))?;
            let (tx, mut rx) = mpsc::channel(4);
            let connection = LocalBusConnectionState::new(1, tx);
            supervisor
                .subscribe_stream(
                    request(
                        "subscribe",
                        "bob",
                        "bus.subscribe",
                        serde_json::json!({"topics":["message.received"],"since_seq":1}),
                    ),
                    &connection,
                )
                .await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                rx.recv().await.ok_or_else(|| failure("ack"))?.kind,
                LocalBusFrameKind::Response
            );
            let mut last = 1;
            loop {
                let event = rx.recv().await.ok_or_else(|| failure("lagged missing"))?;
                if event.method == "stream.lagged" {
                    assert_eq!(event.body["last_delivered_seq"], last);
                    break;
                }
                assert_eq!(event.seq, Some(last + 1));
                last += 1;
            }
            assert!(last < 200);
            let pool =
                supervisor.account_actor("bob").ok_or_else(|| failure("actor"))?.reader_pool()?;
            let page = pool
                .request(request(
                    "read",
                    "bob",
                    "stream.read",
                    serde_json::json!({"since_seq":last}),
                ))
                .await?;
            assert_eq!(page["events"][0]["seq"], last + 1);
            supervisor.disconnect(1);
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}
#[tokio::test(flavor = "current_thread")]
async fn two_subscribers_share_one_driver_and_lock_stops_it() -> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("stream-driver");
            let supervisor =
                supervisor(&root, BTreeMap::from([("bob".to_owned(), seeded(&root, 1))]))?;
            let (mut one, server1) = client(Rc::clone(&supervisor), 1).await?;
            let (mut two, server2) = client(Rc::clone(&supervisor), 2).await?;
            for c in [&mut one, &mut two] {
                c.request(
                    Some("bob".to_owned()),
                    "stream",
                    "bus.subscribe",
                    serde_json::json!({"topics":["sync.status"]}),
                )
                .await?;
            }
            let a = tokio::time::timeout(Duration::from_secs(2), one.next_event())
                .await
                .map_err(|_| failure("driver not running"))??;
            let b = two.next_event().await?;
            assert_eq!(a.seq, b.seq);
            assert_eq!(a.method, "sync.status");
            let actor = supervisor.account_actor("bob").ok_or_else(|| failure("actor"))?;
            one.request(Some("bob".to_owned()), "account", "account.lock", serde_json::json!({}))
                .await?;
            assert!(actor.has_stopped());
            assert!(!actor.is_open());
            let closed = tokio::time::timeout(Duration::from_secs(2), one.next_event())
                .await
                .map_err(|_| failure("locked stream did not close"))??;
            assert_eq!(closed.method, "stream.lagged");
            supervisor.shutdown().await?;
            drop(one);
            drop(two);
            server1.abort();
            server2.abort();
            let _ = server1.await;
            let _ = server2.await;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_restarts_driver_with_persisted_journal_sequence() -> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("stream-unlock");
            let supervisor =
                supervisor(&root, BTreeMap::from([("bob".to_owned(), seeded(&root, 1))]))?;
            let (mut bus, server) = client(Rc::clone(&supervisor), 1).await?;
            let before = supervisor
                .account_actor("bob")
                .ok_or_else(|| failure("actor"))?
                .reader_pool()?
                .request(request("head", "bob", "stream.read", serde_json::json!({})))
                .await?;
            bus.request(Some("bob".to_owned()), "account", "account.lock", serde_json::json!({}))
                .await?;
            bus.request(
                Some("bob".to_owned()),
                "account",
                "account.unlock",
                serde_json::json!({"passphrase":"actor-test-secret"}),
            )
            .await?;
            assert!(supervisor.account_actor("bob").is_some_and(|actor| actor.is_open()));
            bus.request(
                Some("bob".to_owned()),
                "stream",
                "bus.subscribe",
                serde_json::json!({"topics":["sync.status"]}),
            )
            .await?;
            let event = tokio::time::timeout(Duration::from_secs(25), bus.next_event())
                .await
                .map_err(|_| failure("driver did not resume"))??;
            assert!(
                event.seq.ok_or_else(|| failure("seq"))?
                    > before["bounds"]["head_seq"].as_u64().ok_or_else(|| failure("head"))?
            );
            supervisor.shutdown().await?;
            drop(bus);
            server.abort();
            let _ = server.await;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn idle_driver_samples_keep_one_transition_per_topic_across_restart_and_name_the_bound_node()
-> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("idle-driver-transitions");
            for restart in 0..2 {
                let (send, receive) = oneshot::channel();
                let account_root = root.clone();
                let initialize: AccountInitializer = Box::new(move |index| {
                    let account = account_with_counter(
                        &account_root,
                        "bob",
                        None,
                        Arc::new(AtomicBool::new(false)),
                        Arc::new(AtomicUsize::new(0)),
                        Some(index),
                    )?;
                    let path = local_bus_account_manifest_path(&account_root, "bob");
                    let mut manifest = read_local_bus_account_manifest(&path)?;
                    manifest.node_id = Some("node-one".into());
                    write_local_bus_account_manifest(&account_root, &manifest)?;
                    send.send(account.client.account_db()?.open_reader()?)
                        .map_err(|_| failure("observer dropped"))?;
                    Ok(account)
                });
                let supervisor = supervisor(&root, BTreeMap::from([("bob".into(), initialize)]))?;
                let db = receive.await.map_err(|_| failure("reader missing"))?;
                let (bus, server) = client(Rc::clone(&supervisor), 1).await?;
                bus.request_frame(request(
                    "start-router",
                    "bob",
                    "account.list",
                    serde_json::json!({}),
                ))
                .await?;
                let tick = db.load_actor_state::<u64>("sync/tick")?.unwrap_or_default();
                tokio::time::timeout(Duration::from_secs(10), async {
                    while db.load_actor_state::<u64>("sync/tick")?.unwrap_or_default() < tick + 3 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Ok::<_, SdkError>(())
                })
                .await
                .map_err(|_| failure("sync ticks did not progress"))??;
                let events = db.journal_after(0, 128)?;
                assert_eq!(
                    events.iter().filter(|e| e.topic == "sync.status").count(),
                    1,
                    "idle samples after restart {restart}"
                );
                let health = events.iter().filter(|e| e.topic == "node.health").collect::<Vec<_>>();
                assert_eq!(health.len(), 1);
                assert_eq!(health[0].body["node_id"], "node-one");
                let current: serde_json::Value = db
                    .load_actor_state("sync/status")?
                    .ok_or_else(|| failure("current sync sample"))?;
                assert_eq!(current["state"], "idle");
                assert_eq!(health[0].body["state"], "connected");
                assert!(current["last_run"].as_i64().is_some_and(|at| at >= health[0].at));
                supervisor.shutdown().await?;
                drop(bus);
                server.abort();
                let _ = server.await;
                drop(db);
                drop(supervisor);
            }
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn a_cursor_that_missed_a_pruned_message_returns_replay_bounds_through_the_sdk()
-> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("pruned-stream-refusal");
            let account_root = root.clone();
            let initialize: AccountInitializer = Box::new(move |index| {
                let account = account_with_counter(
                    &account_root,
                    "bob",
                    None,
                    Arc::new(AtomicBool::new(false)),
                    Arc::new(AtomicUsize::new(0)),
                    Some(index),
                )?;
                for n in 1..=4 {
                    account.client.account_db()?.append_journal(
                        &format!("seed:{n}"),
                        "message.received",
                        &serde_json::json!({"message_id":n}),
                        now_unix_timestamp(),
                        None,
                    )?;
                }
                account.client.account_db()?.retain_journal(now_unix_timestamp(), 2, 100)?;
                Ok(account)
            });
            let supervisor = supervisor(&root, BTreeMap::from([("bob".into(), initialize)]))?;
            let (client, server) = client(Rc::clone(&supervisor), 1).await?;
            let error = client
                .request_frame_structured(request(
                    "pruned-structured",
                    "bob",
                    "bus.subscribe",
                    serde_json::json!({"topics":["message.received"],"since_seq":1}),
                ))
                .await
                .err()
                .ok_or_else(|| failure("lost cursor accepted"))?;
            let details = format!("{error:?}");
            assert!(details.contains("floor_seq"));
            assert!(details.contains("head_seq"));
            if let SdkError::LocalBusRefused { code, body, .. } = error {
                assert_eq!(code, "resync_required");
                assert_eq!(body["floor_seq"], 3);
                assert!(body["head_seq"].as_u64().is_some_and(|head| head >= 4));
            } else {
                return Err(failure("refusal is not structured"));
            }
            supervisor.shutdown().await?;
            drop(client);
            server.abort();
            let _ = server.await;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[test]
fn status_transitions_preserve_changes_but_ignore_poll_timestamps() -> Result<(), SdkError> {
    let root = root("status-reduction");
    let account = account(&root, "bob", None, Arc::new(AtomicBool::new(false)))?;
    let db = account.client.account_db()?;
    for (state, at) in [("idle", 10), ("idle", 11), ("error", 12), ("error", 13), ("idle", 14)] {
        super::super::sync_status::record(&account, state, at)?;
    }
    db.persist_actor_state("sync/node-id", &Some("node-two"))?;
    super::super::sync_status::record(&account, "idle", 15)?;
    db.hold_unrouted("pending", 1, b"opaque ciphertext", 16)?;
    super::super::sync_status::record(&account, "idle", 16)?;
    let events = db.journal_after(0, 128)?;
    let sync = events.iter().filter(|e| e.topic == "sync.status").collect::<Vec<_>>();
    assert_eq!(
        sync.iter().map(|e| e.body["state"].as_str()).collect::<Vec<_>>(),
        vec![Some("idle"), Some("error"), Some("idle"), Some("idle")]
    );
    assert_eq!(sync.iter().map(|e| e.at).collect::<Vec<_>>(), vec![10, 12, 14, 16]);
    assert_eq!(sync[3].body["unrouted"], 1);
    let health = events.iter().filter(|e| e.topic == "node.health").collect::<Vec<_>>();
    assert_eq!(health.len(), 4);
    assert!(health[0].body["node_id"].is_null());
    assert_eq!(health[1].body["state"], "unavailable");
    assert_eq!(health[3].body["node_id"], "node-two");
    assert_eq!(
        db.load_actor_state::<serde_json::Value>("sync/status")?
            .ok_or_else(|| failure("latest sample"))?["last_run"],
        16
    );
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
