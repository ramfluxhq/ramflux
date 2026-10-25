// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy replay refusals and readable latest samples survive idle periods and restart.
use super::*;
use serde_json::json;
fn initialized(root: &Path, index: AccountIndex) -> Result<LocalBusAccountState, SdkError> {
    let (blocked, _wait) = oneshot::channel();
    account_with_counter(
        root,
        "bob",
        Some(blocked),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicUsize::new(0)),
        Some(index),
    )
}
#[tokio::test(flavor = "current_thread")]
async fn r2_legacy_request_frame_keeps_resync_text_on_a_pruned_cursor() -> Result<(), SdkError> {
    LocalSet::new().run_until(async {
        let root = root("legacy-resync-shape");
        let data = root.clone();
        let init:AccountInitializer=Box::new(move |index| {
            let account=initialized(&data,index)?;
            let db=account.client.account_db()?;
            for n in 0..4 { db.append_journal(&format!("seed:{n}"),"message.received",&json!({}),1000,None)?; }
            db.retain_journal(1000,2,u64::MAX)?;
            Ok(account)
        });
        let supervisor=supervisor(&root,BTreeMap::from([("bob".into(),init)]))?;
        let (mut bus,server)=client(Rc::clone(&supervisor),1).await?;
        let body=json!({"topics":["*"],"since_seq":1});
        let error=bus.request_frame(request("legacy","bob","bus.subscribe",body.clone())).await.err().ok_or_else(||failure("pruned cursor accepted"))?;
        assert!(matches!(error,SdkError::LocalBus(ref text) if text.starts_with("resync_required: ")),"desktop compatibility lost: {error:?}");
        let error=bus.request(Some("bob".into()),"stream","bus.subscribe",body.clone()).await.err().ok_or_else(||failure("pruned cursor accepted"))?;
        assert!(matches!(error,SdkError::LocalBus(ref text) if text.starts_with("resync_required: ")));
        let raw=bus.request_frame_response(request("raw","bob","bus.subscribe",body)).await?;
        assert_eq!(raw.kind,LocalBusFrameKind::Error);
        assert_eq!(raw.body["floor_seq"],3);
        assert!(raw.body["head_seq"].as_u64().is_some_and(|head|head>=4));
        supervisor.shutdown().await?;drop(bus);server.abort();let _=server.await;drop(supervisor);std::fs::remove_dir_all(root)?;Ok(())
    }).await
}
#[tokio::test(flavor = "current_thread")]
async fn r2_a_head_subscriber_and_status_reader_get_idle_samples_across_restart_and_pruning()
-> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("status-snapshot");
            let mut coordinates = None;
            for restart in 0..2 {
                let data = root.clone();
                let (tx, rx) = oneshot::channel();
                let init: AccountInitializer = Box::new(move |index| {
                    let account = initialized(&data, index)?;
                    super::super::sync_status::record(&account, "idle", 1000)?;
                    super::super::sync_status::record(&account, "idle", 2000 + restart)?;
                    let db = account.client.account_db()?;
                    // The last transition's coordinates remain useful after its journal row is pruned.
                    db.retain_journal(5000, 0, 0)?;
                    tx.send(db.open_reader()?).map_err(|_| failure("observer gone"))?;
                    Ok(account)
                });
                let supervisor = supervisor(&root, BTreeMap::from([("bob".into(), init)]))?;
                let db = rx.await.map_err(|_| failure("observer missing"))?;
                let (mut bus, server) = client(Rc::clone(&supervisor), 1).await?;
                let snapshot = bus
                    .request_frame(request("status", "bob", "sync.status.get", json!({})))
                    .await?;
                assert_eq!(snapshot["last_run"], 2000 + restart);
                for field in ["sync_status", "node_health"] {
                    assert_eq!(snapshot[field]["at"], 1000);
                    assert_eq!(snapshot[field]["body"]["last_run"], 2000 + restart);
                    assert!(snapshot[field]["seq"].as_u64().is_some_and(|seq| seq > 0));
                }
                let current = (
                    snapshot["sync_status"]["seq"].clone(),
                    snapshot["node_health"]["seq"].clone(),
                );
                if let Some(previous) = &coordinates {
                    assert_eq!(&current, previous);
                } else {
                    coordinates = Some(current);
                }
                let ack = bus
                    .request_frame(request(
                        "subscribe",
                        "bob",
                        "bus.subscribe",
                        json!({"topics":["sync.status","node.health"]}),
                    ))
                    .await?;
                assert_eq!(ack["sync_status"], snapshot["sync_status"]);
                assert_eq!(ack["node_health"], snapshot["node_health"]);
                assert_eq!(ack["last_run"], 2000 + restart);
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), bus.next_event())
                        .await
                        .is_err()
                );
                assert!(
                    db.journal_after(0, 128)?.iter().all(|event| !matches!(
                        event.topic.as_str(),
                        "sync.status" | "node.health"
                    ))
                );
                supervisor.shutdown().await?;
                drop(bus);
                server.abort();
                let _ = server.await;
                drop(supervisor);
                drop(db);
            }
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}
#[tokio::test(flavor = "current_thread")]
async fn r2_an_unparsable_optional_manifest_keeps_readers_available_and_clears_the_node_binding()
-> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("optional-bad-manifest");
            let data = root.clone();
            let (tx, rx) = oneshot::channel();
            let init: AccountInitializer = Box::new(move |index| {
                let account = initialized(&data, index)?;
                account
                    .client
                    .account_db()?
                    .persist_actor_state("sync/node-id", &Some("stale-node"))?;
                std::fs::write(local_bus_account_manifest_path(&data, "bob"), b"{invalid")?;
                tx.send(account.client.account_db()?.open_reader()?)
                    .map_err(|_| failure("observer gone"))?;
                Ok(account)
            });
            let supervisor = supervisor(&root, BTreeMap::from([("bob".into(), init)]))?;
            let db = rx.await.map_err(|_| failure("observer missing"))?;
            let (bus, server) = client(Rc::clone(&supervisor), 1).await?;
            let response =
                bus.request_frame(request("read", "bob", "conversation.list", json!({}))).await?;
            assert_eq!(response["conversations"], json!([]));
            assert_eq!(db.load_actor_state::<Option<String>>("sync/node-id")?, Some(None));
            let status =
                bus.request_frame(request("status", "bob", "sync.status.get", json!({}))).await?;
            assert!(
                status["node_health"].is_null()
                    || status["node_health"]["body"]["node_id"].is_null()
            );
            supervisor.shutdown().await?;
            drop(bus);
            server.abort();
            let _ = server.await;
            drop(supervisor);
            drop(db);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn r2_older_samples_reuse_retained_coordinates_without_allocating_events()
-> Result<(), SdkError> {
    let root = root("older-status-coordinates");
    let index = AccountIndex::open(&root)?;
    let account = initialized(&root, index)?;
    super::super::sync_status::record(&account, "idle", 1000)?;
    let db = account.client.account_db()?;
    db.remove_actor_state("sync/status/event")?;
    db.remove_actor_state("sync/health/event")?;
    // Exercise the production reader pool without an independent periodic sync writer.
    // A daemon actor may legitimately append status transitions during a socket request.
    let readers = super::super::readers::AccountReaders::start(
        db,
        account.client.owned_device_identity().ok(),
    )?;
    let before = db.journal_bounds()?.head_seq;
    let events = db.journal_after(0, 128)?;
    for _ in 0..32 {
        let snapshot =
            readers.request(request("status", "bob", "sync.status.get", json!({}))).await?;
        for (field, topic) in [("sync_status", "sync.status"), ("node_health", "node.health")] {
            let event = events
                .iter()
                .find(|event| event.topic == topic)
                .ok_or_else(|| failure("transition missing"))?;
            assert_eq!(snapshot[field]["seq"], event.seq);
            assert_eq!(snapshot[field]["at"], event.at);
            assert_eq!(snapshot[field]["body"], event.body);
        }
    }
    assert_eq!(db.journal_bounds()?.head_seq, before);
    readers.stop().await;
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
