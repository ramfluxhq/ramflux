// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actor admission time remains the deadline origin after mailbox and host queue residence.

use super::*;
use crate::bus::{
    connection_manager::{ConnectionHandle, tests::SessionIo},
    runtime_limits::RuntimeTimeouts,
};
use serde_json::json;
use std::sync::atomic::AtomicBool;
use tokio::time::Instant;

type Case = Result<(), Box<dyn std::error::Error>>;
struct Fixture {
    actor: AccountActor,
    connection: ConnectionHandle,
    io: SessionIo,
    reader: AccountDb,
    router: tokio::task::JoinHandle<()>,
    temp: tempfile::TempDir,
}
fn command(method: &str, body: serde_json::Value) -> AccountCommand {
    let (outbound, _) = mpsc::channel(1);
    AccountCommand {
        admission: None,
        private: None,
        request: LocalBusFrame::request(method, Some("alice".into()), "test", method, body),
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: false,
        nodes: None,
        outbound,
        reply: None,
    }
}
async fn fixture(post_claim: Duration) -> Result<Fixture, Box<dyn std::error::Error>> {
    let temp = tempfile::Builder::new().prefix("ramflux-queue-origin-").tempdir()?;
    let root = temp.path().to_path_buf();
    let index = AccountIndex::open(&root)?;
    let (events, mut batches) = mpsc::channel::<EventBatch>(64);
    let router = tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let held = Duration::from_secs(600);
    let limits = RuntimeTimeouts {
        call: held,
        frame: held,
        transport_open: held,
        attempt: held,
        retry_budget: held,
        receipt: held,
        task_approval: held,
        task_submit: held,
        http: held,
        receive_min: held,
        receive_max: held,
        sync: held,
        fetch: held,
        keepalive_idle: held,
        keepalive_call: held,
        post_claim,

        ..RuntimeTimeouts::default()
    };
    let initial_limits = limits.clone();
    let loaded_root = root.clone();
    let (ready, installed) = oneshot::channel();
    let actor = AccountActor::start_local(
        "alice".into(),
        LocalBusConfig::new(root.join("bus.sock"), &root),
        crate::node::NodeStore::default(),
        index,
        events,
        ActorOptions {
            timeouts: limits,
            initial: Some(Box::new(move |_| {
                let mut account = crate::bus::runtime_tests::account(
                    &loaded_root,
                    "alice",
                    None,
                    Arc::new(AtomicBool::new(false)),
                )?;
                let (connection, io) = crate::bus::connection_manager::tests::seeded(
                    account.gateway_config.clone(),
                    initial_limits,
                );
                account.engine = None;
                account.connection = Some(connection.clone());
                let reader = account.client.account_db()?.open_reader()?;
                let _ = ready.send((connection, io, reader));
                Ok(account)
            })),
        },
    )
    .await?;
    let (connection, io, reader) = installed.await?;
    connection.require_live(held).await?;
    Ok(Fixture { actor, connection, io, reader, router, temp })
}

#[tokio::test(start_paused = true)]
async fn command_call_deadline_counts_from_admission_after_three_seconds_in_the_mailbox() -> Case {
    Box::pin(
        tokio::task::LocalSet::new().run_until(crate::bus::connection_manager::tests::watchdog(
            case(Duration::from_secs(600)),
        )),
    )
    .await
}
#[tokio::test(start_paused = true)]
async fn command_fails_within_twenty_five_seconds_of_admission_with_production_caller_wait() -> Case
{
    Box::pin(
        tokio::task::LocalSet::new().run_until(crate::bus::connection_manager::tests::watchdog(
            case(Duration::from_secs(25)),
        )),
    )
    .await
}
async fn case(post_claim: Duration) -> Case {
    // Keep the paused runtime runnable while its independent reader threads answer startup work.
    let clock = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let Fixture { actor, connection, mut io, temp, router, reader } = fixture(post_claim).await?;
    let owner = connection.clone();
    let courier = tokio::spawn(async move {
        owner
            .call(|engine| Box::pin(engine.cursor()), Instant::now() + Duration::from_secs(600))
            .await
    });
    assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Cursor { .. })));
    let (entered, waiting) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let mut hold = command("bot.trust.add", json!({}));
    hold.private = Some(PrivateCommand::HoldLocalMutation { entered, release: released });
    let holder = actor.clone();
    let barrier_task = tokio::task::spawn_local(async move { holder.request(hold).await });
    waiting.await?;
    let start = Instant::now();
    let caller = actor.clone();
    let request = tokio::task::spawn_local(async move {
        caller
            .request(command(
                "message.ack",
                json!({"envelope_id":"queued-b",
            "receiver_device_id":"device-alice","received_at":1}),
            ))
            .await
    });
    while actor.sender.capacity() == 64 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(3)).await;
    release.send(()).map_err(|()| "local barrier closed")?;
    assert!(barrier_task.await?.is_err());
    while connection.queued_calls() == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_millis(21_999)).await;
    assert!(!request.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        request.is_finished(),
        "B must finish at admission + 25 seconds, not claim + 25 seconds"
    );
    assert!(request.await?.is_err());
    assert_eq!(start.elapsed(), Duration::from_secs(25));
    while connection.removals().is_empty() {
        tokio::task::yield_now().await;
    }
    let removals = connection.removals();
    assert_eq!(removals[0].cause, "QueuedCallExpired");
    assert_eq!(removals[0].deadline, start + Duration::from_secs(25));
    assert!(io.output.try_recv().is_err(), "B never reaches the transport");
    assert_eq!(connection.snapshot().state, crate::bus::connection_manager::NetworkingState::Live);
    actor.stop().await?;
    assert!(courier.await?.is_err());
    drop(actor);
    drop(connection);
    router.await?;
    clock.abort();
    let _ = clock.await;
    drop(reader);
    temp.close()?;
    Ok(())
}

#[path = "queue_deadlines/residence.rs"]
mod residence;

#[path = "queue_deadlines/preemption.rs"]
mod preemption;

#[path = "queue_deadlines/receipts.rs"]
mod receipts;
