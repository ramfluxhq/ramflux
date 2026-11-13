// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use std::{io::Read, time::Duration};

fn sockets() -> anyhow::Result<(TcpStream, TcpStream)> {
    let listener = bind_itest_listener("127.0.0.1:0")?;
    let client = TcpStream::connect_timeout(&listener.local_addr()?, Duration::from_secs(3))?;
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    let (server, _) = listener.accept()?;
    server.set_write_timeout(Some(Duration::from_secs(3)))?;
    Ok((client, server))
}

#[test]
fn real_itest_listener_refuses_non_loopback_bind() -> anyhow::Result<()> {
    // Occupying the wildcard address distinguishes our typed refusal from bind failure.
    let wildcard = TcpListener::bind("0.0.0.0:0")?;
    let error = bind_itest_listener(&wildcard.local_addr()?.to_string())
        .expect_err("test: wildcard listener must be refused before bind");
    assert!(
        matches!(
            error.downcast_ref::<ramflux_node_core::NodeCoreError>(),
            Some(ramflux_node_core::NodeCoreError::ItestListenerNonLoopback)
        ),
        "wildcard bind must return the typed policy refusal"
    );
    let listener = bind_itest_listener("127.0.0.1:0")?;
    let client = TcpStream::connect_timeout(&listener.local_addr()?, Duration::from_secs(3))?;
    assert!(
        client.local_addr()?.ip().is_loopback(),
        "permitted listener must accept a real loopback connection"
    );
    assert!(bind_itest_listener("[::]:0").is_err(), "IPv6 wildcard must also be refused");
    Ok(())
}

#[test]
fn policy_commit_releases_state_lock_rejects_overlap_and_preserves_live_updates()
-> anyhow::Result<()> {
    let directory = tempfile::TempDir::new()?;
    let store =
        Arc::new(ramflux_node_core::GatewayRedbStore::open(directory.path().join("gateway.redb"))?);
    let state = Arc::new(Mutex::new(ramflux_node_core::GatewayState::new()));
    let config = ramflux_node_core::GatewayPreAuthConfig {
        per_source_ip_handshake_rate: 1,
        ..Default::default()
    };
    let request = Arc::new(ramflux_node_core::NodeHttpRequest {
        method: "POST".into(),
        path: "/mvp6/preauth/policy".into(),
        body: serde_json::to_vec(&config)?,
        keep_alive: false,
        source_ip_hash: None,
        pre_auth_cookie: None,
        pre_auth_now: None,
        forwarded_proto: None,
        forwarded_for: None,
    });
    let (entered, observed) = std::sync::mpsc::sync_channel(1);
    let (release, waiting) = std::sync::mpsc::sync_channel(1);
    store.pause_next_admission_commit_bounded(entered, waiting)?;
    let (mut client, mut server) = sockets()?;
    let (worker_store, worker_state, worker_request) =
        (Arc::clone(&store), Arc::clone(&state), request.clone());
    let worker = std::thread::spawn(move || {
        handle_preauth_control_request(&mut server, &worker_request, &worker_state, &worker_store)
    });
    observed.recv_timeout(Duration::from_secs(5))?;
    {
        let mut live = state
            .try_lock()
            .map_err(|_| anyhow::anyhow!("policy commit held global state lock"))?;
        live.record_slowloris_timeout();
    }
    let expected = serde_json::to_value(gateway_state(&state)?.pre_auth_metrics())?;
    let (mut busy_client, mut busy_server) = sockets()?;
    assert!(
        handle_preauth_control_request(&mut busy_server, &request, &state, &store)?,
        "overlapping policy request must receive a response"
    );
    let mut status = [0; 12];
    busy_client.read_exact(&mut status)?;
    assert_eq!(&status, b"HTTP/1.1 503", "management overlap must get retryable busy");
    release.send(())?;
    assert!(
        worker.join().map_err(|_| anyhow::anyhow!("management worker panicked"))??,
        "first policy write must complete"
    );
    client.read_exact(&mut status)?;
    assert_eq!(&status, b"HTTP/1.1 200", "first policy write must succeed");
    assert_eq!(
        serde_json::to_value(gateway_state(&state)?.pre_auth_metrics())?,
        expected,
        "policy installation must preserve metrics updated during commit"
    );
    assert_eq!(
        gateway_state(&state)?.pre_auth_policy().per_source_ip_handshake_rate,
        1,
        "committed policy must become live"
    );
    drop(store);
    let store = ramflux_node_core::GatewayRedbStore::open(directory.path().join("gateway.redb"))?;
    let persisted =
        store.load_state()?.ok_or_else(|| anyhow::anyhow!("missing policy checkpoint"))?;
    assert_eq!(
        persisted.pre_auth_policy().per_source_ip_handshake_rate,
        1,
        "policy must survive reopen"
    );
    Ok(())
}

#[test]
fn failed_policy_commit_preserves_live_and_persisted_policy_and_releases_slot() -> anyhow::Result<()>
{
    let directory = tempfile::TempDir::new()?;
    let store = ramflux_node_core::GatewayRedbStore::open(directory.path().join("gateway.redb"))?;
    let state = Arc::new(Mutex::new(ramflux_node_core::GatewayState::new()));
    store.save_state(&gateway_state(&state)?.clone())?;
    let original = gateway_state(&state)?.pre_auth_policy().per_source_ip_handshake_rate;
    let config = ramflux_node_core::GatewayPreAuthConfig {
        per_source_ip_handshake_rate: 1,
        ..Default::default()
    };
    let request = ramflux_node_core::NodeHttpRequest {
        method: "POST".into(),
        path: "/mvp6/preauth/policy".into(),
        body: serde_json::to_vec(&config)?,
        keep_alive: false,
        source_ip_hash: None,
        pre_auth_cookie: None,
        pre_auth_now: None,
        forwarded_proto: None,
        forwarded_for: None,
    };
    let (_client, mut server) = sockets()?;
    store.fail_next_pre_auth_commit();
    assert!(
        handle_preauth_control_request(&mut server, &request, &state, &store).is_err(),
        "failed durable commit must refuse the policy update"
    );
    assert_eq!(
        gateway_state(&state)?.pre_auth_policy().per_source_ip_handshake_rate,
        original,
        "failed update must preserve live policy"
    );
    assert_eq!(
        store
            .load_state()?
            .ok_or_else(|| anyhow::anyhow!("missing baseline policy"))?
            .pre_auth_policy()
            .per_source_ip_handshake_rate,
        original,
        "failed update must preserve persisted policy"
    );
    let _retry = store.try_admit_management_write()?;
    Ok(())
}
