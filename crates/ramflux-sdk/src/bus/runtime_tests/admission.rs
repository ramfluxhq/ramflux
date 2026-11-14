// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account requests and the actor share the injected clock used for queue deadlines.

use super::*;
use serde_json::json;
use std::sync::atomic::AtomicBool;

#[tokio::test]
async fn actor_local_fixture_uses_the_production_loop_and_independent_readers()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = super::super::runtime_tests::root("admission-fixture");
            let loaded_root = root.clone();
            let index = AccountIndex::open(&root)?;
            let (events, mut batches) = mpsc::channel::<EventBatch>(64);
            let router = tokio::task::spawn_local(async move {
                while let Some(batch) = batches.recv().await {
                    let _ = batch.accepted.send(());
                }
            });
            let actor = AccountActor::start_local(
                "alice".into(),
                LocalBusConfig::new(root.join("bus.sock"), &root),
                crate::node::NodeStore::default(),
                index,
                events,
                ActorOptions {
                    initial: Some(Box::new(move |_| {
                        super::super::runtime_tests::account(
                            &loaded_root,
                            "alice",
                            None,
                            Arc::new(AtomicBool::new(false)),
                        )
                    })),
                    timeouts: super::super::runtime_limits::RuntimeTimeouts::default(),
                },
            )
            .await?;
            let (outbound, _receive) = mpsc::channel(8);
            let (entered, entered_at) = oneshot::channel();
            let (release, released) = oneshot::channel();
            let held_actor = actor.clone();
            let held_outbound = outbound.clone();
            let held = tokio::task::spawn_local(async move {
                held_actor
                    .request(AccountCommand {
                        admission: None,
                        private: Some(PrivateCommand::HoldLocalMutation {
                            entered,
                            release: released,
                        }),
                        request: LocalBusFrame::request(
                            "held-local",
                            Some("alice".into()),
                            "account",
                            "bot.trust.add",
                            json!({}),
                        ),
                        connection_id: 1,
                        topics: BTreeSet::new(),
                        attended: false,
                        nodes: None,
                        outbound: held_outbound.into(),
                        reply: None,
                    })
                    .await
            });
            entered_at.await?;
            let started = std::time::Instant::now();
            let response = actor
                .request(AccountCommand {
                    admission: None,
                    private: None,
                    request: LocalBusFrame::request(
                        "status",
                        Some("alice".into()),
                        "account",
                        "account.status",
                        json!({}),
                    ),
                    connection_id: 1,
                    topics: BTreeSet::new(),
                    attended: false,
                    nodes: None,
                    outbound: outbound.into(),
                    reply: None,
                })
                .await?;
            assert!(started.elapsed() < Duration::from_secs(1));
            release.send(()).map_err(|()| "local mutation barrier closed")?;
            assert!(held.await?.is_err(), "the private barrier has no product reply");
            assert_eq!(response.body["local_account_id"], "alice");
            assert_eq!(response.body["state"], "unlocked");
            actor.stop().await?;
            drop(actor);
            router.await?;
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}
