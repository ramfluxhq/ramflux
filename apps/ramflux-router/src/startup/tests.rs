// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pending legacy requests cannot cross the production startup recovery completion.
#![allow(clippy::expect_used, reason = "fixture worker assertions")]
use ramflux_node_core::{
    GatewayFrame, GatewaySession, GatewaySessionLifecycle, GatewayState, RouterCore,
    RouterRedbStore,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

#[test]
fn legacy_surfaces_wait_for_startup_recovery() -> anyhow::Result<()> {
    const NAME: &str = "startup::tests::legacy_surfaces_wait_for_startup_recovery";
    if std::env::var_os("RAMFLUX_LEGACY_STARTUP_CHILD").is_none() {
        for mode in ["redb", "ordinary", "pipeline"] {
            let mut child = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", NAME, "--nocapture"])
                .env("RAMFLUX_LEGACY_STARTUP_CHILD", mode)
                .env("RAMFLUX_ROUTER_WAL", if mode == "redb" { "0" } else { "1" })
                .env("RAMFLUX_ROUTER_WAL_PIPELINE", if mode == "pipeline" { "1" } else { "0" })
                .stdout(std::process::Stdio::null())
                .spawn()?;
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(status) = child.try_wait()? {
                    anyhow::ensure!(status.success(), "legacy child {mode}: {status}");
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill()?;
                    child.wait()?;
                    anyhow::bail!("legacy startup watchdog");
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        return Ok(());
    }
    legacy_child()
}
fn legacy_child() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("legacy-startup-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let path = root.join("db");
    let state = Arc::new(RouterCore::new());
    crate::router_runtime::tests::register_test_device_at(
        &state,
        "alice",
        "alice_phone",
        "target_alice",
        1,
        i64::try_from(ramflux_node_core::now_unix_seconds())?,
    )?;
    let store = Arc::new(RouterRedbStore::open(&path)?);
    store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    let handle = crate::router_runtime::RouterHandle::tokio(state, store, None);
    let envelope =
        crate::router_runtime::tests::current_envelope("startup-accepted", "startup-target")?;
    let accepted = handle.submit_envelope_from(
        envelope.clone(),
        std::time::Instant::now(),
        ramflux_node_core::RouterEnvelopeOrigin::Gateway,
    )?;
    assert_eq!(accepted.outcome, "offline_queued");
    drop(handle);
    let listeners: Vec<_> =
        (0..4).map(|_| TcpListener::bind("127.0.0.1:0")).collect::<std::io::Result<_>>()?;
    let mut clients: Vec<_> = listeners
        .iter()
        .map(|listener| TcpStream::connect(listener.local_addr()?))
        .collect::<std::io::Result<_>>()?;
    for client in &mut clients {
        client.write_all(b"pending legacy request")?;
        client.set_read_timeout(Some(Duration::from_millis(30)))?;
    }
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let observer_guard = ramflux_node_core::durability_test_hooks::observe(
        root.clone(),
        Arc::new(move |_, operation, completed| {
            if operation == "immediate_commit" && completed {
                entered_tx.send(()).map_err(std::io::Error::other)?;
                release_rx
                    .lock()
                    .expect("release")
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
            }
            Ok(())
        }),
    );
    let worker = thread::spawn(move || -> anyhow::Result<()> {
        let (state, store) = super::load(path)?;
        let handle =
            crate::router_runtime::RouterHandle::tokio(Arc::new(state), Arc::new(store), None);
        for (index, listener) in listeners.into_iter().enumerate() {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0; b"pending legacy request".len()];
            stream.read_exact(&mut request)?;
            let body = response(index, &handle, &envelope)?;
            ramflux_node_core::write_itest_json_response(&mut stream, "200 OK", &body)?;
        }
        Ok(())
    });
    entered_rx.recv_timeout(Duration::from_secs(10))?;
    for client in &mut clients {
        let mut byte = [0];
        let error = client.read(&mut byte).expect_err("legacy response escaped recovery");
        anyhow::ensure!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }
    release_tx.send(())?;
    for client in &mut clients {
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        anyhow::ensure!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        anyhow::ensure!(response.contains("startup-accepted"), "{response}");
    }
    worker.join().expect("startup worker")?;
    drop(observer_guard);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn response(
    index: usize,
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<serde_json::Value> {
    Ok(match index {
        0 => serde_json::to_value(handle.state().resume("startup-target", 0, 100))?,
        1 => {
            let response = crate::handlers::handle_mesh_request_value(
                ramflux_transport::MeshHttpRequest {
                    method: "GET".into(),
                    path: "/mvp1/inbox/startup-target".into(),
                    body: Vec::new(),
                },
                handle,
                "ramflux-gateway",
            )?;
            assert_eq!(response.status, "200 OK");
            serde_json::from_slice(&response.body)?
        }
        2 => {
            let reply = handle.submit_envelope_from(
                envelope.clone(),
                std::time::Instant::now(),
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            )?;
            assert!(reply.outcome.contains("replay"));
            serde_json::json!({"envelope_id": envelope.envelope_id, "reply": reply})
        }
        _ => {
            let mut gateway = GatewayState::new();
            gateway.open_session(GatewaySession {
                session_id: "live".into(),
                target_delivery_id: "startup-target".into(),
                device_id: "receiver".into(),
                opened_at: 0,
                last_heartbeat_at: 0,
                lifecycle: GatewaySessionLifecycle::Live,
            });
            gateway.deliver(GatewayFrame::Deliver {
                session_id: "live".into(),
                envelope_id: envelope.envelope_id.clone(),
                payload_hash: envelope.payload_hash.clone(),
            })?;
            serde_json::to_value(gateway)?
        }
    })
}
