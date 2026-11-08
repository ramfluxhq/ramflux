// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::panic,
    clippy::type_complexity,
    clippy::needless_pass_by_value
)]
//! `source_prepare_preserves_w0` and the first leg of `staging_survives_router_expiry`: the
//! REAL source-preparation effects (`prepare_inbound_device_manifest` /
//! `apply_inbound_device_manifest`, `accept_fetched_device_manifest`,
//! `accept_group_actor_manifest`, and the own-history chunk, cipher, slot and import commits)
//! each run through the dormant W0 adapter, with a real account DB reopen. P12 is dormant at
//! the SDK level: P20 wires the adapter into the actor.
use super::fixture::{Case, Fixture};
use crate::bus::connection_manager::{ReceiveTrigger, ReceiveTurn};
use crate::bus::sync_driver::source::w0::{SourceW0, actor_turn, prepare_receive_turn};
use crate::client::identity_authority::test_support::public_manifest;
use crate::gateway::session_push::{IncarnationId, SessionMode};
use crate::prelude::*;
use ramflux_storage::{
    ReceiveBind, ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError,
};
use serde_json::json;
use std::cell::Cell;

const INTEGRITY: &str = "source effect requires staged receive work";

fn turn(db: &AccountDb, generation: u64, incarnation: &str) -> Result<ReceiveTurn, SdkError> {
    Ok(ReceiveTurn {
        target: "t".into(),
        incarnation: incarnation.into(),
        cursor: 0,
        generation,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn gate(db: &AccountDb) -> Result<SourceW0<'static>, SdkError> {
    Ok(SourceW0 {
        expected: ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        generation: 1,
    })
}

fn actor_gate(turn: &ReceiveTurn, handle_generation: u64) -> SourceW0<'_> {
    SourceW0::from_actor(turn, handle_generation)
}

fn snap(account: &LocalBusAccountState) -> Result<Vec<String>, SdkError> {
    Ok(account.client.account_db()?.durable_rows_for_test()?)
}

fn wire(sequence: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({"inbox_seq":sequence,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":format!("env-{sequence}"),"source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":format!("H{sequence}")
    }}))
    .unwrap()
}

fn staged(entry: &[u8], sequence: u64) -> ReceiveStage<'_> {
    ReceiveStage {
        target: "t",
        incarnation: "e",
        sequence,
        entry_json: entry,
        admission_key: "authenticated-key",
        retain_until: now_unix_timestamp() + 300,
        first_seen: 1,
    }
}

fn ledger(account: &LocalBusAccountState) -> Case {
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("t", "e")?;
    Ok(())
}

/// A real reopen: the account DB handle is dropped and unlocked again from disk.
fn reopen(account: &mut LocalBusAccountState) -> Case {
    account.client.active_account_db = None;
    account.client.unlock_account("sender", b"actor-test-secret")?;
    Ok(())
}

fn assert_no_input<T: std::fmt::Debug>(label: &str, result: Result<T, SdkError>) {
    assert!(
        matches!(&result, Err(SdkError::Storage(StorageError::Integrity(text))) if *text == INTEGRITY),
        "{label}: {result:?}"
    );
}

fn state(account: &LocalBusAccountState, sequence: u64) -> Result<(Option<String>, i64), SdkError> {
    Ok(account.client.account_db()?.receive_state_for_test(sequence)?)
}

/// Runs one REAL effect through the adapter in every fence situation. `applied` reports the
/// effect's own durable result where it has one.
fn cells(
    account: &mut LocalBusAccountState,
    sequence: u64,
    real: &dyn Fn(&RamfluxClient) -> Result<(), SdkError>,
    applied: Option<&dyn Fn(&RamfluxClient) -> Result<bool, SdkError>>,
) -> Case {
    // Effects with no durable marker of their own are covered by `called` and the fences.
    let applied = |client: &RamfluxClient| applied.map_or(Ok(None), |f| f(client).map(Some));
    let called = Cell::new(0_u32);
    let run = |account: &LocalBusAccountState, gate: &SourceW0<'_>| {
        gate.effect(account.client.account_db()?, sequence, || {
            called.set(called.get() + 1);
            real(&account.client)
        })
    };
    let entry = wire(sequence);
    // (a) No W0: refused before the real function runs; nothing written.
    assert_no_input(
        &format!("a seq{sequence}"),
        run(account, &gate(account.client.account_db()?)?),
    );
    assert_eq!(called.get(), 0);
    assert_ne!(applied(&account.client)?, Some(true));
    // (b) W0 first, then the real effect: applied, and the recovery input is retained.
    let db = account.client.account_db()?;
    assert_eq!(gate(db)?.stage(db, staged(&entry, sequence))?, ReceiveStageResult::Staged);
    run(account, &gate(db)?)?;
    assert_eq!(called.get(), 1);
    assert_ne!(applied(&account.client)?, Some(false));
    assert_eq!(state(account, sequence)?, (Some("staged".to_owned()), 1));
    // (c) Kill after the commit: effect and input survive a reopen; re-driving the effect from
    // the retained input is idempotent.
    reopen(account)?;
    assert_ne!(applied(&account.client)?, Some(false));
    assert_eq!(state(account, sequence)?, (Some("staged".to_owned()), 1));
    run(account, &gate(account.client.account_db()?)?)?;
    assert_eq!(called.get(), 2);
    assert_ne!(applied(&account.client)?, Some(false));
    // (d) A preparation released after an erase (its expectation predates it) writes nothing.
    let db = account.client.account_db()?;
    let stale = gate(db)?;
    crate::bus::push_receiver::erase_support::erase_through_retention(db)?;
    let erased = run(account, &stale);
    assert!(matches!(erased, Err(SdkError::ObjectErased)), "{erased:?}");
    assert_eq!(called.get(), 2);
    // (e) Likewise after the actor generation moved (lock or retirement).
    let mut moved = gate(account.client.account_db()?)?;
    moved.generation = 2;
    let retired = run(account, &moved);
    assert!(
        matches!(retired, Err(SdkError::Storage(StorageError::AuthorizationRejected))),
        "{retired:?}"
    );
    assert_eq!(called.get(), 2);
    // (f) Late W1: the message is deleted before the bind, so the bind erases the input and no
    // further preparation effect is accepted.
    let db = account.client.account_db()?;
    let message = format!("M{sequence}");
    db.send_direct_message("thread", &message, "peer", b"secret")?;
    db.delete_direct_message("thread", &message, "local", "delete")?;
    assert_eq!(gate(db)?.bind(db, sequence, &message)?, ReceiveBind::Erased);
    assert_eq!(state(account, sequence)?, (Some("erased".to_owned()), 0));
    assert_no_input(
        &format!("f seq{sequence}"),
        run(account, &gate(account.client.account_db()?)?),
    );
    assert_eq!(called.get(), 2);
    Ok(())
}

fn reset_prior(
    account: &LocalBusAccountState,
    peer: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Case {
    account.client.account_db()?.upsert_device_directory_entry(
        peer.device_id(),
        peer.root_commitment(),
        "prior-observation",
        1,
    )?;
    Ok(())
}

fn directory_source(
    client: &RamfluxClient,
    peer: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<Option<String>, SdkError> {
    Ok(client.account_db()?.device_directory_entry(peer.storage_key())?.map(|entry| entry.source))
}

#[tokio::test(flavor = "current_thread")]
async fn source_prepare_preserves_w0() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}

async fn case() -> Case {
    let mut fixture = Box::pin(Fixture::new("source-prepare-w0")).await?;
    ledger(&fixture.source)?;
    fixture.inbound().await?;
    let peer = fixture.peer.client.owned_device_identity()?;
    let peer_manifest = public_manifest(&fixture.peer.client)?;

    // Row 1: native.rs prepare, `prepare_inbound_device_manifest` then the committing
    // `apply_inbound_device_manifest` (source "inbound_signature").
    let entry = fixture.gateway.lock().map_err(|_| "gateway")?.inbox[0].clone();
    reset_prior(&fixture.source, &peer)?;
    cells(
        &mut fixture.source,
        1,
        &|client| {
            client.prepare_inbound_device_manifest(&entry, None)?;
            client.apply_inbound_device_manifest(&entry, None)
        },
        Some(
            &|client| Ok(directory_source(client, &peer)?.as_deref() == Some("inbound_signature")),
        ),
    )?;

    // Row 2: client/contact.rs `accept_fetched_device_manifest` (the contact path).
    reset_prior(&fixture.source, &peer)?;
    let root = peer_manifest.principal_commitment.clone();
    cells(
        &mut fixture.source,
        2,
        &|client| {
            client.accept_fetched_device_manifest(peer_manifest.clone(), &root, "w0-contact")?;
            Ok(())
        },
        Some(&|client| Ok(directory_source(client, &peer)?.as_deref() == Some("w0-contact"))),
    )?;

    // Row 3: group.rs `accept_group_actor_manifest` for a received shared-group packet.
    let group_entry = Box::pin(super::receive_group::group_entry(&mut fixture)).await?;
    let local = fixture.source.gateway_config.device_id.clone();
    let (route, body) =
        fixture.source.client.preview_inbound_route(&group_entry, &local)?.ok_or("group route")?;
    let plan = fixture
        .source
        .client
        .group_receive_directory_plan(&group_entry, &route, &body)?
        .ok_or("group directory plan")?;
    cells(
        &mut fixture.source,
        3,
        &|client| client.accept_group_actor_manifest(&plan.actor, &group_entry, &peer_manifest),
        None,
    )?;

    #[cfg(feature = "itest-local-mint")]
    history(&mut fixture).await?;

    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// First leg of `staging_survives_router_expiry` on the contact path: a crash after the commit,
/// the router's retention passes while down, recovery re-drives from the retained input once.
#[tokio::test(flavor = "current_thread")]
async fn staging_survives_router_expiry() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(expiry()))))
        .await
}

async fn expiry() -> Case {
    let mut fixture = Box::pin(Fixture::new("source-router-expiry")).await?;
    ledger(&fixture.source)?;
    let _clock = crate::time::FixedClock::set(now_unix_timestamp());
    let peer = fixture.peer.client.owned_device_identity()?;
    let peer_manifest = public_manifest(&fixture.peer.client)?;
    let root = peer_manifest.principal_commitment.clone();
    reset_prior(&fixture.source, &peer)?;
    let accept = |client: &RamfluxClient| {
        client.accept_fetched_device_manifest(peer_manifest.clone(), &root, "w0-contact")?;
        Ok::<(), SdkError>(())
    };
    let entry = wire(7);
    let source = &mut fixture.source;
    let db = source.client.account_db()?;
    assert_eq!(gate(db)?.stage(db, staged(&entry, 7))?, ReceiveStageResult::Staged);
    gate(db)?.effect(db, 7, || accept(&source.client))?;
    // Crash; the router's retention (300 s) passes, twice over, while the process is down.
    reopen(source)?;
    crate::time::test_clock::set_frozen(Some(now_unix_timestamp() + 700));
    reopen(source)?;
    assert_eq!(state(source, 7)?, (Some("staged".to_owned()), 1));
    assert_eq!(directory_source(&source.client, &peer)?.as_deref(), Some("w0-contact"));
    // Recovery re-drives from the retained input; the commit stays a single effect.
    let db = source.client.account_db()?;
    let entries = db.actor_state_keys("directory/device/")?.len();
    gate(db)?.effect(db, 7, || accept(&source.client))?;
    assert_eq!(db.actor_state_keys("directory/device/")?.len(), entries);
    // Negative: without W0 nothing is recoverable after expiry and nothing is written.
    reset_prior(source, &peer)?;
    assert_no_input("call3", gate(db)?.effect(db, 8, || accept(&source.client)));
    assert_eq!(directory_source(&source.client, &peer)?.as_deref(), Some("prior-observation"));
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// Pins `disposition IN ('staged','held')`: a terminal receipt with a lingering work row
/// must refuse. Dropping the clause would let the JOIN succeed.
#[tokio::test(flavor = "current_thread")]
async fn source_gate_refuses_terminal_receipt_with_lingering_work() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            terminal_receipt_with_work(),
        ))))
        .await
}

async fn terminal_receipt_with_work() -> Case {
    let mut fixture = Box::pin(Fixture::new("source-gate-terminal-work")).await?;
    ledger(&fixture.source)?;
    let entry = wire(9);
    let db = fixture.source.client.account_db()?;
    assert_eq!(gate(db)?.stage(db, staged(&entry, 9))?, ReceiveStageResult::Staged);
    assert_eq!(state(&fixture.source, 9)?, (Some("staged".to_owned()), 1));
    db.set_receipt_disposition_for_test(9, "erased")?;
    assert_eq!(state(&fixture.source, 9)?, (Some("erased".to_owned()), 1));
    let called = Cell::new(0_u32);
    let refused = gate(db)?.effect(db, 9, || {
        called.set(1);
        Ok(())
    });
    assert_no_input("terminal+work", refused);
    assert_eq!(called.get(), 0);
    reopen(&mut fixture.source)?;
    assert_eq!(state(&fixture.source, 9)?, (Some("erased".to_owned()), 1));
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(feature = "itest-local-mint")]
struct HistoryPacket {
    sync: crate::own_device_sync::SdkOwnDeviceSyncEnvelope,
    manifest: crate::SdkDeviceManifestResponse,
    total: u32,
    relay: super::relay_fixture::Relay,
}

#[cfg(feature = "itest-local-mint")]
async fn history_packet(fixture: &mut Fixture) -> Case<HistoryPacket> {
    use super::receive_history_relay::prepare;
    use super::relay_fixture::Relay;
    use std::rc::Rc;

    let relay = Relay::start(Rc::new(|_, _, _| Ok(()))).await?;
    let (mut sync, total) = prepare(fixture, &relay)?;
    // The control envelope is signed by the sibling device, as the received packet is.
    sync.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        fixture.sibling.client.device_branch.as_ref().ok_or("sibling branch")?,
        &crate::own_device_sync::own_device_sync_signing_body(&sync),
    )?;
    let root = sync.principal_commitment.clone();
    let manifest: crate::SdkDeviceManifestResponse = serde_json::from_value(
        fixture
            .gateway
            .lock()
            .map_err(|_| "gateway")?
            .manifests
            .get(&root)
            .cloned()
            .ok_or("own manifest")?,
    )?;
    Ok(HistoryPacket { sync, manifest, total, relay })
}

#[cfg(feature = "itest-local-mint")]
async fn history(fixture: &mut Fixture) -> Case {
    use crate::client::object::fetch_job;
    use crate::client::own_device_sync::receive_job::HistoryPreparation;

    const S: u64 = 41;
    let HistoryPacket { sync, manifest, total, relay } = history_packet(fixture).await?;
    let entry = wire(S);
    let account = &mut fixture.source;
    let called = Cell::new(0_u32);
    let prepare_step = |client: &RamfluxClient| {
        called.set(called.get() + 1);
        client.prepare_own_history_receive(sync.clone(), manifest.clone(), Duration::from_secs(10))
    };
    // (a) No W0: refused before `prepare_own_history_receive` (and its manifest accept) runs.
    let refused =
        gate(account.client.account_db()?)?
            .effect(account.client.account_db()?, S, || prepare_step(&account.client));
    assert!(
        matches!(&refused, Err(SdkError::Storage(StorageError::Integrity(text))) if *text == INTEGRITY),
        "{:?}",
        refused.err()
    );
    assert_eq!(called.get(), 0);
    // W0, then the preparation: the real manifest accept and fetch preparation.
    let db = account.client.account_db()?;
    assert_eq!(gate(db)?.stage(db, staged(&entry, S))?, ReceiveStageResult::Staged);
    let HistoryPreparation::Fetch(fetch) =
        gate(db)?.effect(db, S, || prepare_step(&account.client))?
    else {
        return Err("history preparation must request a fetch".into());
    };
    assert_eq!(called.get(), 1);
    // Every chunk persist (the real `persist_fetch_chunk`) runs through the adapter.
    let mut engine = account.session_client().await?;
    let pool = account.relay_quic_pool()?;
    let chunks = Cell::new(0_u32);
    let client = &account.client;
    let cipher = fetch_job::download(&mut engine, &pool, &fetch.input, |chunk| {
        chunks.set(chunks.get() + 1);
        let result = client.account_db().and_then(|db| {
            gate(db)?.effect(db, S, || {
                client.check_own_history_fetch(&fetch)?;
                client.persist_fetch_chunk(&fetch.input, &chunk)
            })
        });
        async move { result }
    })
    .await?;
    assert_eq!(chunks.get(), total);
    // Kill between every commit: chunks, cipher import, slot commit, history import.
    reopen(account)?;
    assert_eq!(state(account, S)?, (Some("staged".to_owned()), 1));
    gate(account.client.account_db()?)?
        .effect_mut(&mut account.client, S, |c| c.import_own_history_cipher(&fetch, &cipher))?;
    reopen(account)?;
    assert_eq!(state(account, S)?, (Some("staged".to_owned()), 1));
    // Per-chunk ACK checkpoint through the adapter (history.rs:124-147).
    let db = account.client.account_db()?;
    let ack = gate(db)?.effect(db, S, || {
        account.client.check_own_history_fetch(&fetch)?;
        account.client.authorize_fetch_ack(&fetch.input)
    })?;
    assert!(ack, "per-chunk ACK checkpoint must authorize for the staged fetch");
    let mut acks = 0_u32;
    for index in 0..fetch.input.manifest.total_chunks {
        if fetch.input.confirmed.contains(&index) {
            continue;
        }
        let db = account.client.account_db()?;
        gate(db)?.effect(db, S, || {
            account.client.check_own_history_fetch(&fetch)?;
            account.client.persist_received_attachment_ack(&fetch.input.reference, index)
        })?;
        acks += 1;
    }
    assert!(acks > 0, "per-chunk ACK loop must write at least one ACK");
    reopen(account)?;
    assert_eq!(state(account, S)?, (Some("staged".to_owned()), 1));
    let db = account.client.account_db()?;
    gate(db)?.effect(db, S, || account.client.commit_own_history_slot(&fetch))?;
    reopen(account)?;
    assert_eq!(state(account, S)?, (Some("staged".to_owned()), 1));
    let db = account.client.account_db()?;
    let next = gate(db)?.effect(db, S, || account.client.finish_own_history_receive(&fetch))?;
    assert!(next.is_none());
    assert_eq!(account.client.direct_messages("history-thread")?.len(), 1);
    assert_eq!(state(account, S)?, (Some("staged".to_owned()), 1));
    // A preparation released after an erase writes nothing, and a late W1 bind erases the input.
    let db = account.client.account_db()?;
    let stale = gate(db)?;
    crate::bus::push_receiver::erase_support::erase_through_retention(db)?;
    let calls = Cell::new(0_u32);
    let released = stale.effect(db, S, || {
        calls.set(1);
        Ok(())
    });
    assert!(matches!(released, Err(SdkError::ObjectErased)), "{released:?}");
    assert_eq!(calls.get(), 0);
    db.send_direct_message("thread", "MH", "peer", b"secret")?;
    db.delete_direct_message("thread", "MH", "local", "delete-mh")?;
    assert_eq!(gate(db)?.bind(db, S, "MH")?, ReceiveBind::Erased);
    assert_eq!(state(account, S)?, (Some("erased".to_owned()), 0));
    drop(relay);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn source_w0_actor_expectation_refuses_stale_commit() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            stale_commit(),
        ))))
        .await
}

async fn stale_commit() -> Case {
    let mut fixture = Box::pin(Fixture::new("w0-actor-stale")).await?;
    ledger(&fixture.source)?;
    let account = &mut fixture.source;
    let entry = wire(11);
    let coords = {
        let db = account.client.account_db()?;
        let coords = turn(db, 1, "e")?;
        assert_eq!(
            actor_gate(&coords, 1).stage(db, staged(&entry, 11))?,
            ReceiveStageResult::Staged
        );
        coords
    };
    let before = snap(account)?;
    let called = Cell::new(0_u32);
    let refused = actor_gate(&coords, 2).effect(account.client.account_db()?, 11, || {
        called.set(1);
        Ok(())
    });
    assert!(
        matches!(refused, Err(SdkError::Storage(StorageError::AuthorizationRejected))),
        "stale generation must refuse: {refused:?}"
    );
    assert_eq!(called.get(), 0, "stale generation must not run the effect");
    assert_eq!(snap(account)?, before, "stale generation leaves no partial effect");
    let wrong_e = turn(account.client.account_db()?, 1, "other")?;
    let refused = actor_gate(&wrong_e, 1).effect(account.client.account_db()?, 11, || {
        called.set(1);
        Ok(())
    });
    assert!(
        matches!(refused, Err(SdkError::Storage(StorageError::AuthorizationRejected))),
        "stale E must refuse: {refused:?}"
    );
    assert_eq!(called.get(), 0, "stale E must not run the effect");
    assert_eq!(snap(account)?, before, "stale E leaves no partial effect");
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(feature = "itest-local-mint")]
#[tokio::test(flavor = "current_thread")]
async fn own_history_prepare_is_atomic() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            history_atomic(),
        ))))
        .await
}

#[cfg(feature = "itest-local-mint")]
async fn history_atomic() -> Case {
    use crate::client::own_device_sync::receive_job::HistoryPreparation;

    const S: u64 = 42;
    let mut fixture = Box::pin(Fixture::new("w0-history-atomic")).await?;
    ledger(&fixture.source)?;
    let packet = history_packet(&mut fixture).await?;
    let peer = fixture.sibling.client.owned_device_identity()?;
    let account = &mut fixture.source;
    let entry = wire(S);
    let coords = {
        let db = account.client.account_db()?;
        let coords = turn(db, 1, "e")?;
        assert_eq!(
            actor_gate(&coords, 1).stage(db, staged(&entry, S))?,
            ReceiveStageResult::Staged
        );
        coords
    };
    let before = snap(account)?;
    let directory_before = directory_source(&account.client, &peer)?;
    let called = Cell::new(0_u32);
    let prepare = |client: &RamfluxClient| {
        called.set(called.get() + 1);
        client.prepare_own_history_receive(
            packet.sync.clone(),
            packet.manifest.clone(),
            Duration::from_secs(10),
        )
    };
    let refused = crate::bus::sync_driver::source::w0::run(
        crate::bus::sync_driver::source::w0::Fault::BeforeCommit,
        || {
            actor_gate(&coords, 1)
                .effect(account.client.account_db()?, S, || prepare(&account.client))
        },
    );
    assert!(
        matches!(
            &refused,
            Err(SdkError::Storage(StorageError::Integrity(text)))
                if *text == "source w0 before-commit"
        ),
        "mid-prepare fault must fire after the writes: {:?}",
        refused.as_ref().err()
    );
    assert_eq!(called.get(), 1, "prepare must run so the fault is after the last write");
    assert_eq!(snap(account)?, before, "fault after last write leaves no partial effect");
    assert_eq!(
        directory_source(&account.client, &peer)?,
        directory_before,
        "manifest accept must roll back with the receive transaction"
    );
    let HistoryPreparation::Fetch(_) =
        actor_gate(&coords, 1)
            .effect(account.client.account_db()?, S, || prepare(&account.client))?
    else {
        return Err("history preparation must request a fetch".into());
    };
    assert_eq!(called.get(), 2);
    drop(packet.relay);
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

const PUSH_E: &str = "0123456789abcdef0123456789abcdef";

fn activate_push(account: &mut LocalBusAccountState) -> Case {
    let target = account.target_delivery_id.clone();
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(&target, PUSH_E)?;
    let engine = account.engine.as_mut().ok_or("fixture engine")?;
    engine.mode = SessionMode::Push {
        incarnation: IncarnationId::try_from(PUSH_E.to_owned()).map_err(std::io::Error::other)?,
    };
    Ok(())
}

fn stage_on_target(account: &LocalBusAccountState, sequence: u64, generation: u64) -> Case {
    let target = account.target_delivery_id.clone();
    let db = account.client.account_db()?;
    let expected = ReceiveExpectation {
        target: &target,
        incarnation: PUSH_E,
        cursor: 0,
        generation,
        erasure_generation: db.privacy_erasure_generation()?,
    };
    let entry = serde_json::to_vec(
        &json!({"inbox_seq":sequence,"target_delivery_id":target,"envelope":{
            "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
            "envelope_id":format!("env-{sequence}"),"source_principal_id":"source","source_device_id":"device","target_delivery_id":target,
            "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":format!("H{sequence}")
        }}),
    )?;
    db.receive_transaction(expected, generation, |tx| {
        tx.stage(ReceiveStage {
            target: &target,
            incarnation: PUSH_E,
            sequence,
            entry_json: &entry,
            admission_key: "authenticated-key",
            retain_until: now_unix_timestamp() + 300,
            first_seen: 1,
        })
    })?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn prepare_receive_turn_uses_actor_turn() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            prepare_uses_actor(),
        ))))
        .await
}

async fn prepare_uses_actor() -> Case {
    let mut fixture = Box::pin(Fixture::new("w0-prepare-actor")).await?;
    activate_push(&mut fixture.source)?;
    stage_on_target(&fixture.source, 7, 1)?;
    let plan = prepare_receive_turn(&fixture.source, 1, 1, ReceiveTrigger::Connected)?;
    assert_eq!(plan.limit, 64);
    assert_eq!(
        plan.retries.iter().map(|prepared| prepared.entry.inbox_seq).collect::<Vec<_>>(),
        vec![7],
        "Connected recovery feeds the staged row into the receive plan"
    );
    let tick = prepare_receive_turn(&fixture.source, 1, 1, ReceiveTrigger::Tick)?;
    assert!(tick.retries.is_empty(), "only the Connected pass recovers from disk");
    let turn = actor_turn(&fixture.source, 1)?.ok_or("activated Push turn")?;
    assert_eq!(turn.target, fixture.source.target_delivery_id);
    assert_eq!(turn.incarnation, PUSH_E);
    assert_eq!(turn.generation, 1);
    let recovered =
        SourceW0::from_actor(&turn, 1).recover_from_disk(fixture.source.client.account_db()?)?;
    assert_eq!(
        recovered
            .iter()
            .map(|input| (input.sequence, input.disposition.as_str()))
            .collect::<Vec<_>>(),
        vec![(7, "staged")],
        "prepare_receive_turn SourceW0 must recover staged work from disk"
    );
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn from_actor_generation_mismatch_is_reachable() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            mismatch_reachable(),
        ))))
        .await
}

async fn mismatch_reachable() -> Case {
    let mut fixture = Box::pin(Fixture::new("w0-from-actor-mismatch")).await?;
    activate_push(&mut fixture.source)?;
    stage_on_target(&fixture.source, 7, 1)?;
    let plan = prepare_receive_turn(&fixture.source, 1, 2, ReceiveTrigger::Connected)?;
    assert_eq!(plan.limit, 64, "live plan must survive from_actor mismatch");
    assert!(plan.retries.is_empty(), "a refused fence recovers nothing");
    let turn = actor_turn(&fixture.source, 1)?.ok_or("activated Push turn")?;
    let refused =
        SourceW0::from_actor(&turn, 2).recover_from_disk(fixture.source.client.account_db()?);
    assert!(
        matches!(refused, Err(SdkError::Storage(StorageError::AuthorizationRejected))),
        "from_actor mismatch must be reachable: {refused:?}"
    );
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn live_prepare_survives_extra_read_path() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            live_unactivated(),
        ))))
        .await
}

async fn live_unactivated() -> Case {
    let mut fixture = Box::pin(Fixture::new("w0-live-unactivated")).await?;
    let engine = fixture.source.engine.as_mut().ok_or("fixture engine")?;
    engine.mode = SessionMode::Push {
        incarnation: IncarnationId::try_from(PUSH_E.to_owned()).map_err(std::io::Error::other)?,
    };
    assert!(actor_turn(&fixture.source, 1)?.is_none(), "no epoch row skips extra DB reads");
    let plan = prepare_receive_turn(&fixture.source, 1, 1, ReceiveTrigger::Connected)?;
    assert_eq!(plan.limit, 64, "live PrepareReceive must succeed without epoch reads");
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn catch_up_yields_after_sixteen_pages() {
    use crate::bus::connection_manager::receive::{
        RECEIVE_PAGE_LIMIT, RECEIVE_YIELD_AFTER_PAGES, catch_up_yields,
    };
    assert_eq!(RECEIVE_PAGE_LIMIT, 64);
    assert_eq!(RECEIVE_YIELD_AFTER_PAGES, 16);
    assert!(!catch_up_yields(15));
    assert!(catch_up_yields(16));
}
