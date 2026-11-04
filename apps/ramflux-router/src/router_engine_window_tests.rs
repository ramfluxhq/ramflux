// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real submit paths observe durable window closure before attempting federation IO.
use super::*;
use ramflux_node_core::{NodeServiceSigningKey, RouterCore, RouterEnvelopeOrigin, RouterRedbStore};
use ramflux_protocol::home_migration::{HomeRecord, Refusal};
use std::sync::Arc;
pub(super) static FORWARD_IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(super) fn fixture(
    path: &std::path::Path,
) -> Result<ramflux_protocol::home_migration::RecordEvidence> {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?;
    let head: ramflux_protocol::home_migration::RecordEvidence =
        serde_json::from_value(f["committed_home"].clone())?;
    let HomeRecord::Committed { authorization, .. } = &head.record else {
        return Err("commit".into());
    };
    let op = serde_json::json!({"role":"source","phase":"committed",
        "prepare":f["messages"][0]["signed"],"offer":f["messages"][1]["signed"],
        "authorization":authorization,"seal":f["messages"][5]["signed"],
        "proof":f["messages"][6]["signed"],"fence":null,"base":f["genesis"],
        "attestation":f["messages"][8]["signed"],"delivery_map":[],
        "state_version":1,"next_due":0,"expires_at":0,"recovery_guard":false,"live_budget":false});
    let _: ramflux_node_core::MigrationOperation = serde_json::from_value(op.clone())?;
    let db = redb::Database::create(path)?;
    let tx = db.begin_write()?;
    tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("home_head_v1"))?
        .insert(head.record.account_anchor(), serde_json::to_vec(&head)?.as_slice())?;
    tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("home_root_gates_v1"))?.insert(
        head.record.account_anchor(),
        serde_json::to_vec(&Refusal::HomeMigrated)?.as_slice(),
    )?;
    tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_inbox_routes_v1"))?
        .insert("moving", serde_json::to_vec(&serde_json::json!({"anchor":head.record.account_anchor(),
            "migration_id":authorization.body.migration_id,"epoch":head.record.epoch(),"active":false}))?.as_slice())?;
    let key = serde_json::to_string(&(
        head.record.account_anchor(),
        &authorization.body.migration_id,
        "source",
    ))?;
    tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_ops_v1"))?
        .insert(key.as_str(), serde_json::to_vec(&op)?.as_slice())?;
    tx.commit()?;
    Ok(head)
}
pub(super) fn at<T>(now: u64, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<u64>);
    impl Drop for Reset {
        fn drop(&mut self) {
            SUBMISSION_TIME.set(self.0);
        }
    }
    let _reset = Reset(SUBMISSION_TIME.replace(Some(now)));
    run()
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "closure, restart, both ingress paths and real IO positive arm share one fixture"
)]
fn clock_rollback_after_observed_closure_never_reopens_forwarding_after_restart() -> Result {
    let _guard = FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = super::migration_tests::directory()?;
    let path = dir.0.join("window.redb");
    super::drain_tests::seed(&path, 1)?;
    let head = fixture(&path)?;
    let HomeRecord::Committed { commit_proof, .. } = &head.record else {
        return Err("commit".into());
    };
    let end = commit_proof.body.forward_until;
    let state = Arc::new(RouterCore::new());
    state.set_node_service_signer(Some(NodeServiceSigningKey::from_seed([8; 32])));
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: format!("http://{}/forward", listener.local_addr()?),
        admin_token: None,
        source_node_id: "A".into(),
    };
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
    let forward = AsyncForwardContext {
        client: Some(&client),
        semaphore: &semaphore,
        timeout: std::time::Duration::from_millis(100),
    };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let store = RouterRedbStore::open(&path)?;
    // No preseeded floor: actual sync submit is the first observer of closure.
    let response = at(end, || {
        submit_envelope(
            &state,
            &store,
            forward,
            super::migration_tests::envelope("moving", "close")
                .map_err(|e| anyhow::Error::msg(e.to_string()))?,
            Instant::now(),
            RouterEnvelopeOrigin::Federation,
        )
    })?;
    assert_eq!(response.outcome, "rejected_home_node_migrated");
    assert!(response.nack.is_some());
    drop(store);
    let store = RouterRedbStore::open(&path)?;
    for (asynchronous, client_enabled) in
        [(false, true), (true, true), (false, false), (true, false)]
    {
        let forward = AsyncForwardContext { client: client_enabled.then_some(&client), ..forward };
        let response = at(end - 100, || {
            let envelope = super::migration_tests::envelope("moving", "rollback")
                .map_err(|e| anyhow::Error::msg(e.to_string()))?;
            if asynchronous {
                runtime.block_on(submit_envelope_async(
                    &state,
                    &store,
                    forward,
                    envelope,
                    Instant::now(),
                    RouterEnvelopeOrigin::Federation,
                ))
            } else {
                submit_envelope(
                    &state,
                    &store,
                    forward,
                    envelope,
                    Instant::now(),
                    RouterEnvelopeOrigin::Federation,
                )
            }
        })?;
        assert!(response.outcome.starts_with("rejected_home"));
        let nack = response.nack.ok_or("signed rollback refusal")?;
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&nack)?,
            &nack.signed.signature,
            &head.node_record.body.node_signing_public_key,
        )?;
    }
    assert!(
        store.migration_forward_window("moving", end - 100)?.is_none(),
        "drain window hook stays closed"
    );
    let mut position = String::new();
    let mut forwarded = false;
    assert_eq!(
        crate::migration_drain::tick(&store, &mut position, end - 100, |_, _| {
            forwarded = true;
            Ok(ramflux_node_core::MigrationDrainOutcome::Held)
        })?,
        1
    );
    assert!(!forwarded, "drain forwarded after durable closure");
    assert_eq!(store.migration_drain_page("moving", 0)?.len(), 1);
    assert!(store.acquire_home_operation(head.record.account_anchor()).is_err());
    assert_eq!(listener.accept().err().map(|e| e.kind()), Some(std::io::ErrorKind::WouldBlock));
    // Same fixture without closure: real submit reaches the federation socket.
    let positive = dir.0.join("positive.redb");
    fixture(&positive)?;
    let open = RouterRedbStore::open(&positive)?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let until = Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => return Err(e),
            }
        }
    });
    let response = at(end - 100, || {
        submit_envelope(
            &state,
            &open,
            forward,
            super::migration_tests::envelope("moving", "positive")
                .map_err(|e| anyhow::Error::msg(e.to_string()))?,
            Instant::now(),
            RouterEnvelopeOrigin::Federation,
        )
    })?;
    assert_eq!(response.outcome, "forward_in_progress"); // Server drops the reply after accepting IO.
    server.join().map_err(|_| "forward server")??;
    Ok(())
}

#[test]
fn committed_forward_missing_source_operation_is_permanent_and_never_connects() -> Result {
    let _guard = FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = super::migration_tests::directory()?;
    let path = dir.0.join("missing-op.redb");
    let head = fixture(&path)?;
    let HomeRecord::Committed { commit_proof, .. } = &head.record else {
        return Err("commit".into());
    };
    {
        let db = redb::Database::create(&path)?;
        let tx = db.begin_write()?;
        tx.delete_table(redb::TableDefinition::<&str, &[u8]>::new("migration_ops_v1"))?;
        tx.commit()?;
    }
    let store = RouterRedbStore::open(&path)?;
    let state = RouterCore::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: format!("http://{}/forward", listener.local_addr()?),
        admin_token: None,
        source_node_id: "A".into(),
    };
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
    let envelope = super::migration_tests::envelope("moving", "missing-op")?;
    let response = at(commit_proof.body.forward_until - 100, || {
        submit_envelope(
            &state,
            &store,
            AsyncForwardContext {
                client: Some(&client),
                semaphore: &semaphore,
                timeout: std::time::Duration::from_secs(1),
            },
            envelope,
            Instant::now(),
            RouterEnvelopeOrigin::Federation,
        )
    })?;
    assert_eq!(response.outcome, "rejected_security:committed_forward:BaseMismatch");
    assert_eq!(listener.accept().err().map(|e| e.kind()), Some(std::io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "sync/async storage failures and repaired positive arm share the same fixture"
)]
fn window_latch_persist_failure_fails_closed_without_forwarding() -> Result {
    let _guard = FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = super::migration_tests::directory()?;
    let path = dir.0.join("unwritable-window.redb");
    let head = fixture(&path)?;
    let HomeRecord::Committed { commit_proof, .. } = &head.record else {
        return Err("commit".into());
    };
    // A real redb schema error prevents the window transaction from persisting.
    // Unlike a core-only failpoint, this reaches both production submit engines.
    {
        let db = redb::Database::create(&path)?;
        let tx = db.begin_write()?;
        tx.open_table(redb::TableDefinition::<&str, &str>::new("migration_window_closed_v1"))?
            .insert("unwritable", "wrong value type")?;
        tx.commit()?;
    }
    let store = RouterRedbStore::open(&path)?;
    let state = Arc::new(RouterCore::new());
    state.set_node_service_signer(Some(NodeServiceSigningKey::from_seed([8; 32])));
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: format!("http://{}/forward", listener.local_addr()?),
        admin_token: None,
        source_node_id: "A".into(),
    };
    let semaphore = Arc::new(tokio::sync::Semaphore::new(8));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    for now in [commit_proof.body.forward_until - 100, commit_proof.body.forward_until] {
        for asynchronous in [false, true] {
            for client in [Some(&client), None] {
                let forward = AsyncForwardContext {
                    client,
                    semaphore: &semaphore,
                    timeout: std::time::Duration::from_millis(100),
                };
                let response = at(now, || {
                    let envelope = super::migration_tests::envelope("moving", "storage-failure")
                        .map_err(|e| anyhow::Error::msg(e.to_string()))?;
                    if asynchronous {
                        runtime.block_on(submit_envelope_async(
                            &state,
                            &store,
                            forward,
                            envelope,
                            Instant::now(),
                            RouterEnvelopeOrigin::Federation,
                        ))
                    } else {
                        submit_envelope(
                            &state,
                            &store,
                            forward,
                            envelope,
                            Instant::now(),
                            RouterEnvelopeOrigin::Federation,
                        )
                    }
                })?;
                if client.is_some() {
                    assert_eq!(response.outcome, "forward_in_progress");
                } else {
                    assert_eq!(response.migration_refusal, Some(Refusal::StorageUnavailable));
                }
                assert_eq!(response.inbox_seq, None);
                assert_eq!(semaphore.available_permits(), 8);
                assert_eq!(
                    listener.accept().err().map(|e| e.kind()),
                    Some(std::io::ErrorKind::WouldBlock)
                );
            }
        }
    }
    assert_eq!(state.resume("moving", 0, 10), []);
    drop(store);
    // Repair only the failed table. The same request can now reach federation,
    // proving that the negative arm did not poison the tuple reservation.
    {
        let db = redb::Database::create(&path)?;
        let tx = db.begin_write()?;
        tx.delete_table(redb::TableDefinition::<&str, &str>::new("migration_window_closed_v1"))?;
        tx.commit()?;
    }
    let store = RouterRedbStore::open(&path)?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let until = Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => return Err(e),
            }
        }
    });
    at(commit_proof.body.forward_until - 100, || {
        submit_envelope(
            &state,
            &store,
            AsyncForwardContext {
                client: Some(&client),
                semaphore: &semaphore,
                timeout: std::time::Duration::from_millis(100),
            },
            super::migration_tests::envelope("moving", "storage-failure")
                .map_err(|e| anyhow::Error::msg(e.to_string()))?,
            Instant::now(),
            RouterEnvelopeOrigin::Federation,
        )
    })?;
    server.join().map_err(|_| "forward server")??;
    Ok(())
}
