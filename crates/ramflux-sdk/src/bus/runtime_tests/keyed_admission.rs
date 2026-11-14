// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A pre-effect network refusal leaves a key available for an admitted retry.

use super::*;
use crate::bus::{
    connection_manager::{ConnectionHandle, SessionConnector, SessionFuture, tests::SessionIo},
    mutation_intent::MutationIntent,
    runtime_limits::RuntimeTimeouts,
};
use serde_json::json;
use std::sync::{Mutex, atomic::AtomicBool};
use tokio::sync::Notify;

type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Connector {
    engine: Mutex<Option<GatewaySessionEngine>>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}
impl SessionConnector for Connector {
    fn connect(
        &self,
        _config: GatewaySessionConfig,
        _deadline: tokio::time::Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            self.engine
                .lock()
                .map_err(|_| SdkError::GatewaySessionNotEstablished)?
                .take()
                .ok_or(SdkError::GatewaySessionNotEstablished)
        })
    }
}
struct Fixture {
    actor: AccountActor,
    connection: ConnectionHandle,
    io: SessionIo,
    release: Arc<Notify>,
    reader: AccountDb,
    router: tokio::task::JoinHandle<()>,
    root: ramflux_test_support::TestPath,
}
fn command() -> AccountCommand {
    let (outbound, _) = mpsc::channel(1);
    let mut request = LocalBusFrame::request(
        "keyed",
        Some("alice".into()),
        "test",
        "message.ack",
        json!({"envelope_id":"key-after-admit","receiver_device_id":"device-alice","received_at":1}),
    );
    request.operation_id = Some("key-after-admit".into());
    AccountCommand {
        admission: None,
        private: None,
        request,
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound,
        reply: None,
    }
}
async fn fixture() -> Case<Fixture> {
    let root = crate::bus::runtime_tests::root("keyed-admission");
    let loaded = root.clone();
    let index = AccountIndex::open(&root)?;
    let (events, mut batches) = mpsc::channel::<EventBatch>(64);
    let router = tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let (ready, installed) = oneshot::channel();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let limits = RuntimeTimeouts {
        network_wait: Duration::from_secs(5),
        ..RuntimeTimeouts::held_for_test()
    };
    let initial_limits = limits.clone();
    let initial_entered = Arc::clone(&entered);
    let initial_release = Arc::clone(&release);
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
                    &loaded,
                    "alice",
                    None,
                    Arc::new(AtomicBool::new(false)),
                )?;
                let reader = account.client.account_db()?.open_reader()?;
                let (engine, io) = crate::bus::connection_manager::tests::seeded_engine(
                    account.gateway_config.clone(),
                    &initial_limits,
                );
                let connection = ConnectionHandle::start_with(
                    account.gateway_config.clone(),
                    None,
                    initial_limits,
                    Arc::new(Connector {
                        engine: Mutex::new(Some(engine)),
                        entered: initial_entered,
                        release: initial_release,
                    }),
                    None,
                );
                account.engine = None;
                account.connection = Some(connection.clone());
                let _ = ready.send((connection, io, reader));
                Ok(account)
            })),
        },
    )
    .await?;
    let (connection, io, reader) = installed.await?;
    entered.notified().await;
    Ok(Fixture { actor, connection, io, release, reader, router, root })
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn keyed_network_refusal_leaves_no_receipt_and_the_same_intent_succeeds_after_admission()
-> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let clock = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let Fixture { root: _root, actor, connection, mut io, release, reader, router } =
        fixture().await?;
    let owner = actor.clone();
    let refused = tokio::task::spawn_local(async move { owner.request(command()).await });
    while connection.test_live_waiters() == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    let error = refused.await?.err().ok_or("offline request succeeded")?;
    assert_eq!(crate::bus::io::local_bus_error_code(&error), "NetworkingPending");
    assert!(
        MutationIntent::new(&command().request)?.lookup(&reader)?.is_none(),
        "a pure refusal must not reserve the key"
    );
    release.notify_one();
    connection.require_live(Duration::from_secs(600)).await?;
    let owner = actor.clone();
    let first = tokio::task::spawn_local(async move { owner.request(command()).await });
    assert!(matches!(io.output.recv().await, Some(GatewayClientFrame::Ack { .. })));
    let owner = actor.clone();
    let replay = tokio::task::spawn_local(async move { owner.request(command()).await });
    let cursor = GatewayCursor {
        target_delivery_id: "target".into(),
        inbox_seq: 1,
        last_envelope_id: Some("key-after-admit".into()),
        acked_envelope_ids: vec!["key-after-admit".into()],
        nacked_envelope_ids: BTreeMap::new(),
    };
    io.input.send(serde_json::to_vec(&GatewayServerFrame::Ack { cursor: cursor.clone() })?)?;
    io.input.send(serde_json::to_vec(&GatewayServerFrame::Cursor { cursor: Some(cursor) })?)?;
    let result = first.await??;
    assert_eq!(replay.await??.body, result.body);
    assert_eq!(MutationIntent::new(&command().request)?.lookup(&reader)?, Some(result.body));
    assert!(
        io.output.try_recv().is_err(),
        "same-key requests must produce exactly one wire effect"
    );
    actor.stop().await?;
    drop(actor);
    drop(connection);
    drop(reader);
    router.await?;
    clock.abort();
    Ok(())
}
