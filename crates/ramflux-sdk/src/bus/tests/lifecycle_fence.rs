// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::unwrap_used, clippy::panic)]
//! `lifecycle_fence`: a held page/result released after lock under the old generation
//! writes nothing and does not ACK; unlock recovers disk. Negative: drop the actor
//! generation argument at commit and the stale row appears.
use super::super::lifecycle_fence::{commit, recover_account, recover_from_disk};
use super::fixture::{Case, Fixture};
use crate::bus::connection_manager::{
    AccountWork, ConnectionEvent, ConnectionHandle, DisconnectReason, ReceiveTrigger, ReceiveTurn,
};
use crate::bus::events::EventBatch;
use crate::bus::runtime_limits::RuntimeTimeouts;
use crate::prelude::*;
use ramflux_storage::{ReceiveExpectation, ReceiveStage, StorageError};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};

const SEQ: u64 = 7;
const INCARNATION: &str = "e";

struct PendingConnect;
impl crate::bus::connection_manager::SessionConnector for PendingConnect {
    fn connect(
        &self,
        _config: GatewaySessionConfig,
        _deadline: tokio::time::Instant,
    ) -> crate::bus::connection_manager::SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(std::future::pending())
    }
}

fn limits() -> RuntimeTimeouts {
    RuntimeTimeouts::held_for_test()
}

fn wire(target: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"inbox_seq":SEQ,"target_delivery_id":target,"envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":"env-7","source_principal_id":"source","source_device_id":"device","target_delivery_id":target,
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":"H7"
    }}))
    .unwrap()
}

fn state(account: &LocalBusAccountState) -> Result<(Option<String>, i64), SdkError> {
    Ok(account.client.account_db()?.receive_state_for_test(SEQ)?)
}

fn seed_epoch(account: &LocalBusAccountState, target: &str) -> Case {
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(target, INCARNATION)?;
    Ok(())
}

fn hold_page(account: &LocalBusAccountState, target: &str, generation: u64) -> Case {
    let db = account.client.account_db()?;
    let expected = ReceiveExpectation {
        target,
        incarnation: INCARNATION,
        cursor: 0,
        generation,
        erasure_generation: db.privacy_erasure_generation()?,
    };
    let entry = wire(target);
    db.receive_transaction(expected, generation, |tx| {
        tx.stage(ReceiveStage {
            target,
            incarnation: INCARNATION,
            sequence: SEQ,
            entry_json: &entry,
            admission_key: "authenticated-key",
            retain_until: now_unix_timestamp() + 300,
            first_seen: 1,
        })?;
        tx.hold_receipt(SEQ)
    })?;
    Ok(())
}

fn fence_runtime(mut account: LocalBusAccountState) -> (super::super::AccountRuntime, u64, String) {
    let handle = ConnectionHandle::start_with(
        account.gateway_config.clone(),
        None,
        limits(),
        Arc::new(PendingConnect),
        None,
    );
    let generation = handle.generation();
    account.connection = Some(handle);
    let target = account.target_delivery_id.clone();
    let (commands, receiver) = mpsc::channel(8);
    drop(commands);
    let (_stop, shutdown) = watch::channel(false);
    let (events, mut batches) = mpsc::channel::<EventBatch>(8);
    tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let (connection_sender, connection_work) = mpsc::channel(8);
    let (_lifecycle_sender, lifecycle) = mpsc::channel(4);
    let (_preempt_sender, preempt) = watch::channel(0_u64);
    let runtime = super::super::AccountRuntime {
        timeouts: limits(),
        id: "sender".into(),
        state: crate::bus::state::LocalBusDaemonState {
            account_index: None,
            config: LocalBusConfig::new(PathBuf::from("fence.sock"), PathBuf::from("fence-data")),
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
    };
    (runtime, generation, target)
}

fn db_of(runtime: &super::super::AccountRuntime) -> Result<&AccountDb, SdkError> {
    runtime
        .state
        .accounts
        .get("sender")
        .ok_or(SdkError::LocalBus("account".into()))?
        .client
        .account_db()
}

fn account_of(runtime: &super::super::AccountRuntime) -> Result<&LocalBusAccountState, SdkError> {
    runtime.state.accounts.get("sender").ok_or(SdkError::LocalBus("account".into()))
}

async fn observe(
    runtime: &mut super::super::AccountRuntime,
    generation: u64,
) -> Result<(), SdkError> {
    runtime
        .apply_connection_work(AccountWork::ReceiveObservation {
            generation,
            event: ConnectionEvent::Connected {
                session_id: "s".into(),
                resumed: false,
                generation,
            },
        })
        .await?;
    Ok(())
}

fn unlock_under_one_second(runtime: &mut super::super::AccountRuntime) -> Case {
    let account = runtime.state.accounts.get_mut("sender").ok_or("account")?;
    account.client.active_account_db = None;
    let locked = Instant::now();
    account.client.unlock_account("sender", b"actor-test-secret")?;
    assert!(locked.elapsed() < Duration::from_secs(1), "account lock must finish in under 1s");
    Ok(())
}

fn bump_handle(runtime: &mut super::super::AccountRuntime) -> Case<u64> {
    let account = runtime.state.accounts.get_mut("sender").ok_or("account")?;
    if let Some(handle) = account.connection.take() {
        handle.request_stop(DisconnectReason::Lock);
    }
    let handle = ConnectionHandle::start_with(
        account.gateway_config.clone(),
        None,
        limits(),
        Arc::new(PendingConnect),
        None,
    );
    let generation = handle.generation();
    account.connection = Some(handle);
    Ok(generation)
}

#[tokio::test(flavor = "current_thread")]
async fn lifecycle_fence() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            held().await?;
            Box::pin(super::receive_ack::ack_fence()).await
        }))))
        .await
}

async fn held() -> Case {
    let fixture = Box::pin(Fixture::new("lifecycle-fence")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    seed_epoch(&fixture.source, &fixture.source.target_delivery_id.clone())?;
    let root = fixture.root.clone();
    let (mut runtime, g1, target) = fence_runtime(fixture.source);
    hold_page(account_of(&runtime)?, &target, g1)?;
    assert_eq!(state(account_of(&runtime)?)?, (Some("held".to_owned()), 1));
    observe(&mut runtime, g1).await?;
    let recovered = recover_account(db_of(&runtime)?, &target, g1)?.ok_or("disk at g1")?;
    assert!(
        recovered.inputs.iter().any(|row| row.sequence == SEQ && row.disposition == "held"),
        "Connected recovers held work from disk: {:?}",
        recovered.inputs
    );
    unlock_under_one_second(&mut runtime)?;
    let g2 = bump_handle(&mut runtime)?;
    assert_ne!(g2, g1, "lock must issue a new handle generation");
    let recovered = recover_account(db_of(&runtime)?, &target, g2)?.ok_or("disk at g2")?;
    assert!(
        recovered.inputs.iter().any(|row| row.sequence == SEQ && row.disposition == "held"),
        "unlock recovers held work from disk: {:?}",
        recovered.inputs
    );
    assert_eq!(state(account_of(&runtime)?)?, (Some("held".to_owned()), 1));
    let probe = db_of(&runtime)?.observe_sql_work();
    let writes = probe.snapshot().write_statements;
    observe(&mut runtime, g1).await?;
    assert_eq!(
        probe.snapshot().write_statements,
        writes,
        "old generation observation writes nothing"
    );
    let (reply, response) = oneshot::channel();
    runtime
        .apply_connection_work(AccountWork::PrepareReceive {
            generation: g1,
            trigger: ReceiveTrigger::Connected,
            reply,
        })
        .await?;
    assert!(response.await.is_err(), "stale PrepareReceive must drop the reply");
    assert!(
        gateway.lock().map_err(|_| "gateway")?.acked.is_empty(),
        "fake transport must not ACK after old-generation release"
    );
    let db = db_of(&runtime)?;
    let old = ReceiveTurn {
        target: target.clone(),
        incarnation: INCARNATION.into(),
        cursor: 0,
        generation: g1,
        erasure_generation: db.privacy_erasure_generation()?,
    };
    let stale = commit(db, g2, old.expected(), |tx| {
        let entry = wire(&target);
        tx.stage(ReceiveStage {
            target: &target,
            incarnation: INCARNATION,
            sequence: SEQ + 1,
            entry_json: &entry,
            admission_key: "authenticated-key",
            retain_until: now_unix_timestamp() + 300,
            first_seen: 1,
        })
    });
    assert!(
        matches!(stale, Err(StorageError::AuthorizationRejected)),
        "old generation must not commit: {stale:?}"
    );
    assert_eq!(state(account_of(&runtime)?)?, (Some("held".to_owned()), 1));
    let fresh = recover_from_disk(
        db,
        g2,
        ReceiveExpectation {
            target: &target,
            incarnation: INCARNATION,
            cursor: 0,
            generation: g2,
            erasure_generation: db.privacy_erasure_generation()?,
        },
    )?;
    assert!(fresh.inputs.iter().any(|row| row.sequence == SEQ && row.disposition == "held"));
    drop(runtime);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
