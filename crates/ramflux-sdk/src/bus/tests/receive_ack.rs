// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A held inbox ACK leaves the actual account mailbox and both local readers available.

use super::fixture::{AckHold, Case, Fixture};
use crate::bus::events::EventBatch;
use crate::bus::{
    actor::{AccountActor, AccountCommand, ActorOptions},
    runtime_limits::RuntimeTimeouts,
};
use crate::prelude::*;
use serde_json::json;
use std::sync::{Arc, atomic::AtomicBool};

pub(super) struct Started {
    pub actor: AccountActor,
    pub root: PathBuf,
    pub router: tokio::task::JoinHandle<()>,
    peer: LocalBusAccountState,
    sibling: LocalBusAccountState,
    resume: ResumeConfig,
}
impl Started {
    pub(super) fn peer(&mut self) -> &mut LocalBusAccountState {
        &mut self.peer
    }
}
#[tokio::test(flavor = "current_thread")]
async fn held_inbox_ack_does_not_occupy_the_actor_or_its_readers() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let mut fixture = Box::pin(Fixture::new("receive-background-ack")).await?;
    fixture.inbound().await?;
    let hold = Arc::new(AckHold::default());
    fixture.gateway.lock().map_err(|_| "gateway")?.ack_hold = Some(Arc::clone(&hold));
    let gateway = Arc::clone(&fixture.gateway);
    let started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    // The only active receive trigger is Connected; all competing budgets are 600 seconds.
    controls(&started.actor).await?;
    let received = started
        .actor
        .request(command("message.read", json!({"conversation_id":"healthy"})))
        .await?;
    assert!(
        received.body["messages"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|row| row["body_utf8"] == "courier stays responsive"))
    );
    assert!(
        gateway.lock().map_err(|_| "gateway")?.acked.is_empty(),
        "the fake gateway must still be held"
    );
    hold.release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !gateway.lock().map_err(|_| "gateway")?.acked.is_empty() {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let Started { actor, root, router, .. } = started;
    actor.stop().await?;
    drop(actor);
    router.await?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
pub(super) async fn controls(actor: &AccountActor) -> Case {
    for (method, body) in [
        ("account.status", json!({})),
        ("contact.list", json!({})),
        ("contact.requests.policy.set", json!({"contact_requests":"auto_accept"})),
    ] {
        let wall = std::time::Instant::now();
        let response =
            tokio::time::timeout(Duration::from_secs(1), actor.request(command(method, body)))
                .await??;
        assert!(
            wall.elapsed() < Duration::from_secs(1),
            "{method} waited for the held receive step"
        );
        if method == "account.status" {
            assert_eq!(response.body["networking"], "live");
        }
    }
    Ok(())
}

pub(super) async fn start(fixture: Fixture) -> Case<Started> {
    let Fixture { root, mut source, peer, sibling, .. } = fixture;
    let mut engine = source.engine.take().ok_or("fixture engine")?;
    engine.frame_timeout = Duration::from_secs(600);
    let config = source.gateway_config.clone();
    let commitment = source.principal_commitment.clone();
    let relay_options = source.client.node_relay_options.clone();
    let transfer_hook = source.test_transfer_hook.clone();
    drop(source);
    let resume = ResumeConfig { config, commitment, relay_options, transfer_hook };
    let (actor, router) = launch(&root, &resume, Some(engine)).await?;
    Ok(Started { actor, root, router, peer, sibling, resume })
}
#[derive(Clone)]
struct ResumeConfig {
    config: GatewaySessionConfig,
    commitment: String,
    relay_options: Option<RelayTransferOptions>,
    transfer_hook: Option<Arc<crate::bus::transfer_slots::test_hooks::Hook>>,
}
impl Started {
    pub(super) async fn restart(self) -> Case<Self> {
        let Self { actor, root, router, peer, sibling, resume } = self;
        actor.stop().await?;
        drop(actor);
        router.await?;
        let (actor, router) = launch(&root, &resume, None).await?;
        Ok(Self { actor, root, router, peer, sibling, resume })
    }
}
async fn launch(
    root: &Path,
    resume: &ResumeConfig,
    engine: Option<GatewaySessionEngine>,
) -> Case<(AccountActor, tokio::task::JoinHandle<()>)> {
    let loaded_root = root.join("source");
    let data_root = loaded_root.clone();
    let ResumeConfig { config, commitment, relay_options, transfer_hook } = resume.clone();
    let index = AccountIndex::open(&loaded_root)?;
    let (events, mut batches) = mpsc::channel::<EventBatch>(64);
    let router = tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let actor = AccountActor::start_local(
        "sender".into(),
        LocalBusConfig {
            itest_legacy_accounts: true,
            ..LocalBusConfig::new(root.join("bus.sock"), data_root)
        },
        crate::node::NodeStore::default(),
        index,
        events,
        ActorOptions {
            timeouts: limits(),
            initial: Some(Box::new(move |_| {
                let mut account = crate::bus::runtime_tests::account(
                    &loaded_root,
                    "sender",
                    None,
                    Arc::new(AtomicBool::new(false)),
                )?;
                account.principal_commitment = commitment;
                account.gateway_config = config;
                account.client.node_relay_options = relay_options;
                account.test_transfer_hook = transfer_hook;
                account.target_delivery_id = account.gateway_config.target_delivery_id.clone();
                account.engine = None;
                crate::bus::dispatch::object::hydrate_local_object_state(&mut account)?;
                if let Some(engine) = engine {
                    account.install_test_session(engine);
                }
                Ok(account)
            })),
        },
    )
    .await?;
    Ok((actor, router))
}
pub(super) fn limits() -> RuntimeTimeouts {
    RuntimeTimeouts::held_for_test()
}
pub(super) fn command(method: &str, body: serde_json::Value) -> AccountCommand {
    let (outbound, _) = mpsc::channel(1);
    AccountCommand {
        admission: None,
        private: None,
        request: LocalBusFrame::request(method, Some("sender".into()), "test", method, body),
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound,
        reply: None,
    }
}
