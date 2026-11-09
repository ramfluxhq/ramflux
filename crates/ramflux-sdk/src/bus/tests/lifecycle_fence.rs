// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]
//! `lifecycle_fence` through the real account runtime. A real loopback gateway serves one
//! signed message. Generation 1 pulls the page and holds its `ApplyPage` (a held result).
//! The real `account.lock` command stops that connection (bound: under one second). The
//! held result is then released into the actor at generation 1 after a new connection owns
//! generation 2: it must write nothing, apply nothing and ACK nothing. After the reopen, the
//! Connected `PrepareReceive` recovers the staged copy from disk (the router no longer has
//! it) into the plan, and the activated `ApplyPage` turn returns the P20c refusal with 0
//! messages applied and 0 ACKs. Negatives: dropping the actor generation check makes the
//! stale release write the message; dropping the recovery feed leaves the plan without the row.
use super::fixture::{Case, Fixture};
use super::receive_ack::command;
use crate::bus::connection_manager::AccountWork;
use crate::bus::events::EventBatch;
use crate::bus::runtime_limits::RuntimeTimeouts;
use crate::gateway::session_push::{IncarnationId, SessionMode};
use crate::prelude::*;
use ramflux_storage::{ReceiveExpectation, ReceiveStage};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};

const PUSH_E: &str = "0123456789abcdef0123456789abcdef";
const CONVERSATION: &str = "healthy";

fn limits() -> RuntimeTimeouts {
    RuntimeTimeouts::held_for_test()
}

fn open_account(
    root: &Path,
    config: &GatewaySessionConfig,
    commitment: &str,
) -> Result<LocalBusAccountState, SdkError> {
    let mut account = crate::bus::runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    account.principal_commitment = commitment.to_owned();
    account.gateway_config = config.clone();
    account.target_delivery_id = account.gateway_config.target_delivery_id.clone();
    account.engine = None;
    crate::bus::dispatch::object::hydrate_local_object_state(&mut account)?;
    Ok(account)
}

fn runtime_for(account: LocalBusAccountState, root: &Path) -> super::super::AccountRuntime {
    let (commands, receiver) = mpsc::channel(8);
    let (stop, shutdown) = watch::channel(false);
    let (events, mut batches) = mpsc::channel::<EventBatch>(64);
    tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let (connection_sender, connection_work) = mpsc::channel(8);
    let (lifecycle_sender, lifecycle) = mpsc::channel(4);
    let (preempt_sender, preempt) = watch::channel(0_u64);
    std::mem::forget((commands, stop, lifecycle_sender, preempt_sender));
    super::super::AccountRuntime {
        timeouts: limits(),
        id: "sender".into(),
        state: crate::bus::state::LocalBusDaemonState {
            account_index: None,
            config: LocalBusConfig {
                itest_legacy_accounts: true,
                ..LocalBusConfig::new(root.join("bus.sock"), root.join("source"))
            },
            nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::from([("sender".into(), account)]),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        },
        receiver,
        lifecycle,
        preempt,
        readers: Arc::new(std::sync::Mutex::new(None)),
        events,
        shutdown,
        courier: None,
        networking_expiry_pending: None,
        networking_expiry_warned: false,
        networking_observation_warned: false,
        transfers: super::super::uploads::Transfers::start(),
        connection_sender,
        connection_work,
        receive_gate_hook: None,
        courier_events: None,
    }
}

fn account_of(runtime: &super::super::AccountRuntime) -> Result<&LocalBusAccountState, SdkError> {
    runtime.state.accounts.get("sender").ok_or(SdkError::LocalBus("account".into()))
}

fn messages(runtime: &super::super::AccountRuntime) -> Result<usize, SdkError> {
    Ok(account_of(runtime)?.client.direct_messages(CONVERSATION)?.len())
}

fn acked(gateway: &std::sync::Mutex<super::fixture::Gateway>) -> Result<usize, SdkError> {
    Ok(gateway.lock().map_err(|_| SdkError::LocalBus("gateway".into()))?.acked.len())
}

/// Dormant W0 staging: the router delivered this entry and its durable copy is on disk.
fn stage(account: &LocalBusAccountState, entry: &GatewayInboxEntry) -> Case {
    let target = account.target_delivery_id.clone();
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(&target, PUSH_E)?;
    let bytes = serde_json::to_vec(entry)?;
    let expected = ReceiveExpectation {
        target: &target,
        incarnation: PUSH_E,
        cursor: 0,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    };
    db.receive_transaction(expected, 1, |tx| {
        tx.stage(ReceiveStage {
            target: &target,
            incarnation: PUSH_E,
            sequence: entry.inbox_seq,
            entry_json: &bytes,
            admission_key: "authenticated-key",
            retain_until: now_unix_timestamp() + 300,
            first_seen: 1,
        })
    })?;
    Ok(())
}

/// The Push coordinates `actor_turn` reads. The handle owns the live engine, so a dormant
/// engine stands in as the coordinate carrier and is moved to the reopened account.
fn push_engine(mut engine: GatewaySessionEngine) -> Result<GatewaySessionEngine, SdkError> {
    engine.mode = SessionMode::Push {
        incarnation: IncarnationId::try_from(PUSH_E.to_owned())
            .map_err(|error| SdkError::LocalBus(error.to_string()))?,
    };
    Ok(engine)
}

fn generation_of(runtime: &super::super::AccountRuntime) -> Result<u64, SdkError> {
    Ok(account_of(runtime)?
        .connection
        .as_ref()
        .ok_or(SdkError::GatewaySessionNotEstablished)?
        .generation())
}

/// Drives the connection work the way `serve` does until `done` holds. Returns the first
/// `ApplyPage` instead of applying it when `hold` is set (a held page/result).
async fn pump(
    runtime: &mut super::super::AccountRuntime,
    hold: bool,
    mut done: impl FnMut(&super::super::AccountRuntime) -> bool,
) -> Result<Option<AccountWork>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if done(runtime) {
            return Ok(None);
        }
        match tokio::time::timeout(Duration::from_millis(20), runtime.connection_work.recv()).await
        {
            Ok(Some(work)) => {
                if hold && matches!(work, AccountWork::ApplyPage { .. }) {
                    return Ok(Some(work));
                }
                runtime.apply_connection_work(work).await?;
            }
            Ok(None) => return Err("connection work channel closed".into()),
            Err(_) => {}
        }
    }
    Err("pump deadline".into())
}

#[tokio::test(flavor = "current_thread")]
async fn lifecycle_fence() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            Box::pin(held()).await?;
            Box::pin(super::receive_ack::ack_fence()).await
        }))))
        .await
}

async fn held() -> Case {
    let mut fixture = Box::pin(Fixture::new("lifecycle-fence")).await?;
    fixture.inbound().await?;
    let Fixture { root, mut source, peer, sibling, gateway, .. } = fixture;
    let entry = {
        let mut served = gateway.lock().map_err(|_| "gateway")?;
        served.inbox.truncate(1);
        served.inbox.first().cloned().ok_or("signed message")?
    };
    let config = source.gateway_config.clone();
    let commitment = source.principal_commitment.clone();
    let carrier = push_engine(source.engine.take().ok_or("fixture engine")?)?;
    drop(source);

    // Generation 1: the staged copy exists, the router still serves it, the page is held.
    let account = open_account(&root, &config, &commitment)?;
    stage(&account, &entry)?;
    let mut runtime = runtime_for(account, &root);
    runtime.start_connection()?;
    runtime.state.accounts.get_mut("sender").ok_or("account")?.engine = Some(carrier);
    let Some(AccountWork::ApplyPage {
        generation: g1,
        entry: page,
        source,
        backpressure,
        reply,
        turn,
    }) = pump(&mut runtime, true, |_| false).await?
    else {
        return Err("generation 1 must hold an ApplyPage".into());
    };
    assert_eq!(g1, generation_of(&runtime)?, "the page is held at the live generation");
    assert_eq!(messages(&runtime)?, 0, "a held page has applied nothing");
    assert_eq!(acked(&gateway)?, 0, "a held page has acknowledged nothing");

    // The router row is gone: only the staged copy on disk can finish this message.
    gateway.lock().map_err(|_| "gateway")?.inbox.clear();
    let carrier = runtime
        .state
        .accounts
        .get_mut("sender")
        .and_then(|account| account.engine.take())
        .ok_or("carrier")?;

    // Real `account.lock` through the actor, bounded by one second on the lock itself.
    let (lock_reply, lock_response) = oneshot::channel();
    let mut lock = command("account.lock", serde_json::json!({}));
    lock.reply = Some(lock_reply);
    let locked = Instant::now();
    runtime.apply(lock).await?;
    assert!(locked.elapsed() < Duration::from_secs(1), "account lock must finish in under 1s");
    lock_response.await??;
    assert!(runtime.state.accounts.is_empty(), "lock closes the account");
    drop(reply);

    // Unlock: reopen from disk; the runtime starts the connection at a new generation.
    runtime.state.accounts.insert("sender".into(), open_account(&root, &config, &commitment)?);
    runtime.start_connection()?;
    runtime.state.accounts.get_mut("sender").ok_or("account")?.engine = Some(carrier);
    let g2 = generation_of(&runtime)?;
    assert_ne!(g1, g2, "unlock must issue a new connection generation");

    // Release the held result at the OLD generation: no DB write, no apply, no ACK.
    let (stale_reply, stale_response) = oneshot::channel();
    let probe = account_of(&runtime)?.client.account_db()?.observe_sql_work();
    let writes = probe.snapshot().write_statements;
    runtime
        .apply_connection_work(AccountWork::ApplyPage {
            generation: g1,
            entry: page,
            source,
            backpressure,
            reply: stale_reply,
            turn,
        })
        .await?;
    assert!(stale_response.await.is_err(), "a stale ApplyPage must be dropped without a reply");
    assert_eq!(probe.snapshot().write_statements, writes, "old generation writes nothing");
    assert_eq!(messages(&runtime)?, 0, "old generation applies nothing");
    assert_eq!(acked(&gateway)?, 0, "old generation must not ACK");

    // (a) Recovery from disk: the Connected PrepareReceive feeds the staged row into the plan.
    let plan = crate::bus::sync_driver::source::w0::prepare_receive_turn(
        account_of(&runtime)?,
        g2,
        g2,
        crate::bus::connection_manager::ReceiveTrigger::Connected,
    )?;
    assert!(
        plan.retries.iter().any(|prepared| prepared.entry.inbox_seq == entry.inbox_seq),
        "Connected recovery must put the staged sequence {} into the plan",
        entry.inbox_seq
    );

    // (b) The recovered row reaches the activated ApplyPage turn, which returns the P20c
    // refusal: 0 messages applied, 0 ACKs sent.
    let Some(AccountWork::ApplyPage {
        generation: g_page,
        entry: page,
        source,
        backpressure,
        turn,
        ..
    }) = pump(&mut runtime, true, |_| false).await?
    else {
        return Err("recovery must reach an ApplyPage at the new generation".into());
    };
    assert!(g_page >= g2, "the recovered page belongs to the new generation");
    assert_eq!(g_page, generation_of(&runtime)?, "the page is at the live generation");
    let (refused_reply, refused_response) = oneshot::channel();
    runtime
        .apply_connection_work(AccountWork::ApplyPage {
            generation: g_page,
            entry: page,
            source,
            backpressure,
            reply: refused_reply,
            turn,
        })
        .await?;
    let refusal = refused_response.await?.err();
    assert!(
        matches!(&refusal, Some(SdkError::InboundRejected(text))
            if text == crate::bus::push_receiver::apply_w1::routed_refused()),
        "activated ApplyPage must return the P20c refusal: {refusal:?}"
    );
    assert_eq!(messages(&runtime)?, 0, "the refusal applies 0 messages");
    // apply-once + ACK leg: S6b P24b2a/b (controller ruling 2026-11-09)
    assert_eq!(acked(&gateway)?, 0, "the refusal sends 0 ACKs");
    runtime.stop_connection().await;
    drop(runtime);
    drop((peer, sibling));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
