// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Real native stores, pair crypto, resident host and actor handoff; injected frame transport.
use crate::bus::account_runtime::{AccountRuntime, TransientHost, uploads};
use crate::bus::events::EventBatch;
use crate::bus::state::{LocalBusAccountState, LocalBusDaemonState};
use crate::client::native_test_support::{Fixture, TestResult};
use crate::{GatewayServerFrame, LocalBusConfig};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};

fn runtime(
    account: LocalBusAccountState,
    root: &std::path::Path,
    id: String,
) -> (AccountRuntime, mpsc::Receiver<EventBatch>) {
    let (_, receiver) = mpsc::channel(1);
    let (_, lifecycle) = mpsc::channel(1);
    let (_, preempt) = watch::channel(0);
    let (_, shutdown) = watch::channel(false);
    let (events, batches) = mpsc::channel(8);
    let (connection_sender, connection_work) = mpsc::channel(2);
    (
        AccountRuntime {
            timeouts: crate::bus::runtime_limits::RuntimeTimeouts::default(),
            state: LocalBusDaemonState {
                account_index: None,
                config: LocalBusConfig::new(root.join("bus.sock"), root),
                nodes: crate::node::NodeStore::default(),
                accounts: BTreeMap::from([(id.clone(), account)]),
                active_account_id: None,
                attended_accounts: BTreeSet::new(),
                subscribers: BTreeMap::new(),
            },
            id,
            receiver,
            lifecycle,
            preempt,
            events,
            shutdown,
            readers: Arc::new(Mutex::new(None)),
            courier: None,
            networking_expiry_pending: None,
            networking_expiry_warned: false,
            networking_observation_warned: false,
            transfers: uploads::Transfers::start(),
            connection_sender,
            connection_work,
            ledger: None,
            transient: TransientHost::default(),
            receive_gate_hook: None,
            courier_events: None,
        },
        batches,
    )
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn native_typing_host_consumer_projects_without_durable_intake_and_clears_on_stop()
-> TestResult {
    // Keep runnable work while crossing real store/host barriers; Tokio may not
    // auto-advance the paused clock over non-timer work.
    let witness = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let result = tokio::task::LocalSet::new().run_until(Box::pin(case())).await;
    witness.abort();
    result
}

async fn case() -> TestResult {
    use crate::gateway::access::GatewaySessionAccess;
    let _guard = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b): (Fixture, Fixture) =
        Box::pin(crate::client::routed::native_typing_pair_fixture()).await?;
    let (handle, io) =
        crate::bus::connection_manager::tests::ephemeral_fixture_for(b.config.clone()).await?;
    let now = crate::time::now_unix_timestamp();
    let _wall = crate::time::FixedClock::set(now);
    let (envelope, allowed) = crate::client::routed::native_typing_delivery_fixture(&a, &b)?;
    let before = b.client.account_db()?.test_table_fingerprints(&allowed)?;
    let head = b.client.account_db()?.journal_bounds()?.head_seq;
    let id = b.client.account_db()?.local_account_id.clone();
    let root = b.root.0.clone();
    handle
        .call(
            move |engine| {
                Box::pin(async move {
                    engine.ephemeral_inbox.set_clock(crate::ReceiverClock {
                        local_now_ms: u64::try_from(now).unwrap_or(0).saturating_mul(1000),
                        monotonic_ms: 0,
                    });
                    Ok(())
                })
            },
            tokio::time::Instant::now() + std::time::Duration::from_secs(600),
        )
        .await?;
    let mut account =
        LocalBusAccountState::disconnected(b.client, b.config, b.manifest.principal_commitment);
    account.connection = Some(handle);
    let (mut runtime, mut batches) = runtime(account, &root, id.clone());
    runtime.refresh_transient_host().await;
    assert!(runtime.transient.consumer.is_some());
    let mut port = runtime.state.accounts.get(&id).ok_or("account")?.live_session_client()?;
    assert!(port.take_ephemeral_consumer().await?.is_none(), "actor must own the sole consumer");
    let expires_at_ms = u64::try_from(envelope.created_at)? * 1000 + 5000;
    let mut tampered = envelope.clone();
    tampered.encrypted_payload = ramflux_protocol::encode_base64url([99; 64]);
    io.input.send(serde_json::to_vec(&GatewayServerFrame::Ephemeral {
        envelope: tampered,
        expires_at_ms,
    })?)?;
    io.input
        .send(serde_json::to_vec(&GatewayServerFrame::Ephemeral { envelope, expires_at_ms })?)?;
    let frame = runtime.transient.next(&runtime.state, &id).await;
    assert!(frame.is_some());
    runtime.apply_transient_frame(frame);
    let batch = batches.recv().await.ok_or("transient update")?;
    assert_typing(&batch, &id, true)?;
    let client = &runtime.state.accounts.get(&id).ok_or("account")?.client;
    assert_eq!(client.account_db()?.journal_bounds()?.head_seq, head);
    assert_eq!(client.account_db()?.test_table_fingerprints(&allowed)?, before);
    runtime.stop_connection().await;
    let clear = batches.recv().await.ok_or("source end clear")?;
    assert_typing(&clear, &id, false)?;
    assert!(runtime.transient.consumer.is_none());
    Ok(())
}

fn assert_typing(batch: &EventBatch, account: &str, active: bool) -> TestResult {
    use ramflux_protocol::message::{content, message_update};
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].method, ramflux_protocol::message::TRANSIENT_TOPIC);
    assert_eq!(batch.events[0].seq, Some(0));
    let update = crate::bindings::decode_message_update(&batch.events[0].body)?;
    assert_eq!(update.account_id, account);
    assert_eq!(update.journal_sequence, 0);
    let Some(message_update::State::Content(content)) = update.state else {
        return Err("expected content".into());
    };
    let Some(content::Value::Typing(typing)) = content.value else {
        return Err("expected Typing".into());
    };
    assert_eq!(typing.active, active);
    Ok(())
}
