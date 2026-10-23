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
            assert!(
                one.request(
                    Some("bob".to_owned()),
                    "stream",
                    "bus.subscribe",
                    serde_json::json!({"topics":["message.received"],"since_seq":0})
                )
                .await
                .is_err()
            );
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
