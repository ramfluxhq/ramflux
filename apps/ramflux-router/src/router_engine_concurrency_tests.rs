// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real synchronous and asynchronous submissions share destination permits.
use super::*;
use ramflux_node_core::{RouterCore, RouterEnvelopeOrigin, RouterRedbStore};
use std::{sync::Arc, time::Duration};

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "shared IO fixture covers mixed drain, sync and async concurrency"
)]
fn drain_and_new_forwards_share_peer_limit_of_four_in_flight()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = window_tests::FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = migration_tests::directory()?;
    let path = dir.0.join("concurrent.redb");
    drain_tests::seed(&path, 1)?;
    let head = window_tests::fixture(&path)?;
    let ramflux_protocol::home_migration::HomeRecord::Committed {
        commit_proof, authorization, ..
    } = &head.record
    else {
        return Err("commit".into());
    };
    let now = commit_proof.body.forward_until - 100;
    let store = Arc::new(RouterRedbStore::open(path)?);
    let state = Arc::new(RouterCore::new());
    let semaphore = Arc::new(tokio::sync::Semaphore::new(16));
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: format!("http://{}/forward", listener.local_addr()?),
        admin_token: None,
        source_node_id: "A".into(),
    };
    let mut workers = Vec::new();
    for i in 0..4 {
        let (state, store, semaphore, client) =
            (Arc::clone(&state), Arc::clone(&store), Arc::clone(&semaphore), client.clone());
        workers.push(std::thread::spawn(move || -> anyhow::Result<()> {
            window_tests::at(now, || {
                let envelope = migration_tests::envelope("moving", &format!("concurrent-{i}"))
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let forward = AsyncForwardContext {
                    client: Some(&client),
                    semaphore: &semaphore,
                    timeout: Duration::from_secs(5),
                };
                if i == 0 {
                    crate::migration_drain::tick(&store, &mut String::new(), now, |row, now| {
                        crate::migration_drain::forward(&state, &store, forward, row, now)
                    })?;
                } else if i % 2 == 0 {
                    submit_envelope(
                        &state,
                        &store,
                        forward,
                        envelope,
                        Instant::now(),
                        RouterEnvelopeOrigin::Federation,
                    )?;
                } else {
                    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(
                        submit_envelope_async(
                            &state,
                            &store,
                            forward,
                            envelope,
                            Instant::now(),
                            RouterEnvelopeOrigin::Federation,
                        ),
                    )?;
                }
                Ok(())
            })
        }));
    }
    // Retain each accepted socket without replying: all four IO workers stay in flight.
    let until = Instant::now() + Duration::from_secs(3);
    let mut connections = Vec::new();
    while connections.len() < 4 {
        match listener.accept() {
            Ok((socket, _)) => connections.push(socket),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e.into()),
        }
    }
    assert!(
        crate::migration_forward_limits::acquire(&authorization.body.destination_node).is_err()
    );
    // Another destination has its own permits while this destination is saturated.
    drop(crate::migration_forward_limits::acquire("independent-concurrency-peer")?);
    let fifth = window_tests::at(now, || {
        submit_envelope(
            &state,
            &store,
            AsyncForwardContext {
                client: Some(&client),
                semaphore: &semaphore,
                timeout: Duration::from_millis(100),
            },
            migration_tests::envelope("moving", "fifth")
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            Instant::now(),
            RouterEnvelopeOrigin::Federation,
        )
    })?;
    assert_eq!(fifth.outcome, "forward_in_progress");
    assert_eq!(semaphore.available_permits(), 12);
    assert_eq!(listener.accept().err().map(|e| e.kind()), Some(std::io::ErrorKind::WouldBlock));
    drop(connections);
    for worker in workers {
        worker.join().map_err(|_| "submit worker panicked")??;
    }
    assert_eq!(semaphore.available_permits(), 16);
    drop(crate::migration_forward_limits::acquire(&authorization.body.destination_node)?);
    Ok(())
}

#[test]
fn committed_sync_and_async_forwards_share_four_peer_permits()
-> Result<(), Box<dyn std::error::Error>> {
    drain_and_new_forwards_share_peer_limit_of_four_in_flight()
}
