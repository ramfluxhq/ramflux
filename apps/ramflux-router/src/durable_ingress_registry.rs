// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scanner-backed durable ingress registry for the router crate.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    Ingress,
    Edge,
    NonIngress(&'static str),
}

const DURABLE_INGRESS: &[(&str, Class)] = &[
    (
        "durable_mode.rs:rejected_security",
        Class::NonIngress("typed refusal construction; no envelope persist"),
    ),
    (
        "durable_mode.rs:rejected_security_mesh",
        Class::NonIngress("typed refusal construction; no envelope persist"),
    ),
    (
        "durable_mode.rs:from_envelope",
        Class::NonIngress("typed refusal construction; no envelope persist"),
    ),
    (
        "durable_mode.rs:refused_quic",
        Class::NonIngress("typed refusal construction; no envelope persist"),
    ),
    (
        "durable_mode.rs:rejected_security_for_target",
        Class::NonIngress("typed refusal construction; no envelope persist"),
    ),
    (
        "durable_mode.rs:transport_refusal",
        Class::NonIngress("typed refusal construction; no envelope persist"),
    ),
    ("handlers.rs:handle_itest_mvp0_request", Class::Edge),
    ("handlers.rs:forward_authority_response", Class::Edge),
    ("handlers.rs:handle_mesh_fast_path_value", Class::Edge),
    ("handlers.rs:mesh_fanout_response", Class::Edge),
    ("serve.rs:submit_raw_envelope", Class::Edge),
    ("migration_drain.rs:forward", Class::Edge),
    ("forward_http.rs:post", Class::NonIngress("HTTP client for already-admitted forwards")),
    (
        "handlers.rs:envelope_origin_for_peer",
        Class::NonIngress("maps peer id to origin; no envelope persist"),
    ),
    ("handlers.rs:handle_mvp0_envelope", Class::Ingress),
    ("handlers.rs:handle_mvp0_envelope_mesh_from", Class::Ingress),
    ("handlers.rs:handle_mvp0_envelope_from", Class::Ingress),
    ("handlers.rs:handle_mvp0_envelope_async_from", Class::Ingress),
    (
        "home_migration.rs:configured",
        Class::NonIngress("constructs a migration service from node identity"),
    ),
    (
        "migration_drain.rs:signed_permanent_refusal",
        Class::NonIngress("classifies an already stored drain reply"),
    ),
    ("router_engine.rs:submit_envelope", Class::Ingress),
    ("router_engine.rs:submit_envelope_mesh", Class::Ingress),
    ("router_engine.rs:submit_envelope_mesh_inner", Class::Ingress),
    ("router_engine.rs:submit_envelope_async", Class::Ingress),
    ("router_engine.rs:submit_envelope_mesh_async", Class::Ingress),
    (
        "router_engine.rs:complete_forward_attempt",
        Class::NonIngress("completes an already admitted forward reservation"),
    ),
    ("router_engine.rs:own_device_fanout", Class::Ingress),
    ("router_engine.rs:own_device_fanout_inner", Class::Ingress),
    (
        "router_engine.rs:submit_response_from_outcome",
        Class::NonIngress("maps an already computed submit outcome"),
    ),
    ("router_runtime.rs:forward", Class::NonIngress("federation HTTP client for admitted plans")),
    ("router_runtime.rs:submit_envelope_from", Class::Ingress),
    ("router_runtime.rs:submit_envelope_async_from", Class::Ingress),
    ("router_runtime.rs:submit_envelope_mesh_from", Class::Ingress),
    ("router_runtime.rs:submit_envelope_mesh_async_from", Class::Ingress),
    ("router_runtime.rs:own_device_fanout", Class::Ingress),
    ("router_runtime.rs:submit_forwarded_async", Class::Ingress),
    ("router_runtime.rs:submit_forwarded", Class::Ingress),
];

const ROUTER_REGISTRY_TEST: &str =
    "durable_ingress_registry::durable_ingress_registry_refuses_marked_envelopes";

#[test]
fn durable_ingress_registry_refuses_marked_envelopes() -> Result<(), Box<dyn std::error::Error>> {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = public_envelope_sources(&source_root)?;
    let scanned = scan_public_envelope_functions(&sources).map_err(|error| error.to_string())?;
    let listed = DURABLE_INGRESS
        .iter()
        .filter(|(name, class)| {
            !matches!(class, Class::Edge) || scanned.iter().any(|scanned| scanned == name)
        })
        .map(|(name, _)| (*name).to_owned())
        .collect::<Vec<_>>();
    assert_registry_scan_matches(&sources, &listed).map_err(std::io::Error::other)?;

    let ingress_count =
        DURABLE_INGRESS.iter().filter(|(_, class)| *class == Class::Ingress).count();
    let edge_count = DURABLE_INGRESS.iter().filter(|(_, class)| *class == Class::Edge).count();
    let non_ingress_count =
        DURABLE_INGRESS.iter().filter(|(_, class)| matches!(class, Class::NonIngress(_))).count();
    assert_eq!((ingress_count, edge_count, non_ingress_count), (18, 6, 13));
    for (entry, class) in DURABLE_INGRESS {
        if let Class::NonIngress(reason) = class {
            assert!(!reason.is_empty(), "{entry} needs a NonIngress reason");
        }
        if *class == Class::Ingress {
            assert!(
                first_statement_has_mode_guard(&source_root, entry)?,
                "{entry} must refuse marked delivery modes before its first effect"
            );
        }
    }

    if std::env::var_os("RAMFLUX_S6C_P03_CHILD").is_none() {
        for with_wal in ["1", "0"] {
            let status = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", ROUTER_REGISTRY_TEST, "--nocapture"])
                .env("RAMFLUX_S6C_P03_CHILD", "1")
                .env("RAMFLUX_ROUTER_WAL", with_wal)
                .status()?;
            assert!(status.success(), "router registry child WAL={with_wal} failed: {status}");
        }
        return Ok(());
    }
    let with_wal = std::env::var("RAMFLUX_ROUTER_WAL").ok().as_deref() != Some("0");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let (state, store, path) =
        crate::router_runtime::tests::test_router(&format!("s6c_p03_{with_wal}"))?;
    let handle = Arc::new(crate::router_runtime::RouterHandle::tokio(
        Arc::clone(&state),
        Arc::clone(&store),
        None,
    ));
    let mut ordinal = 0_u64;
    for (entry, class) in DURABLE_INGRESS {
        if !matches!(class, Class::Ingress | Class::Edge) {
            continue;
        }
        for mode in [
            serde_json::Value::String("ephemeral".into()),
            serde_json::Value::String("unknown-mode".into()),
            serde_json::Value::Null,
        ] {
            let marked = marked_envelope(ordinal, mode.clone())?;
            let control = unmarked_envelope(&marked)?;
            exercise_router_control(entry, &handle, &control, &runtime)?;
            let before = store_snapshot(&state, &path)?;
            exercise_router_ingress(entry, &handle, &state, &store, &marked, &runtime)?;
            let after = store_snapshot(&state, &path)?;
            assert_eq!(after, before, "WAL={with_wal}, ingress={entry}, mode={mode}");
            ordinal += 1;
        }
    }
    drop(handle);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn durable_ingress_registry_scanner_rejects_drift_fixtures() {
    let unlisted =
        vec![("registry.rs".to_owned(), "pub fn newly_exposed(envelope: Envelope) {}".to_owned())];
    assert_eq!(
        assert_registry_scan_matches(&unlisted, &[]),
        Err("scanner matches differ: [\"registry.rs:newly_exposed\"] != []".to_owned())
    );
    let no_longer_matching =
        vec![("registry.rs".to_owned(), "pub fn previously_listed() {}".to_owned())];
    assert_eq!(
        assert_registry_scan_matches(
            &no_longer_matching,
            &["registry.rs:previously_listed".to_owned()]
        ),
        Err("scanner matches differ: [] != [\"registry.rs:previously_listed\"]".to_owned())
    );
}

fn not_mode_refused_outcome(outcome: &str) -> bool {
    outcome != "rejected_security:delivery_mode_refused"
}

fn control_submit_ok<T>(entry: &str, result: anyhow::Result<T>, outcome: impl FnOnce(&T) -> &str) {
    match result {
        Ok(value) => {
            assert!(
                not_mode_refused_outcome(outcome(&value)),
                "control refused at mode for {entry}"
            );
        }
        Err(error) => {
            assert_ne!(
                error.to_string(),
                "delivery_mode_refused",
                "control refused at mode for {entry}: {error}"
            );
        }
    }
}

#[allow(clippy::too_many_lines)]
fn exercise_router_control(
    entry: &str,
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), Box<dyn std::error::Error>> {
    match entry {
        "handlers.rs:handle_mvp0_envelope"
        | "handlers.rs:handle_mvp0_envelope_from"
        | "handlers.rs:handle_mvp0_envelope_mesh_from"
        | "handlers.rs:handle_mvp0_envelope_async_from" => {
            let admitted = ramflux_protocol::ephemeral::require_durable(envelope);
            assert!(admitted.is_ok(), "control refused at mode for {entry}: {admitted:?}");
        }
        "router_engine.rs:submit_envelope" | "router_runtime.rs:submit_envelope_from" => {
            control_submit_ok(
                entry,
                handle.submit_envelope_from(
                    envelope.clone(),
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                ),
                |response| response.outcome.as_str(),
            );
        }
        "router_engine.rs:submit_envelope_mesh"
        | "router_engine.rs:submit_envelope_mesh_inner"
        | "router_runtime.rs:submit_envelope_mesh_from" => {
            control_submit_ok(
                entry,
                handle.submit_envelope_mesh_from(
                    envelope.clone(),
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                ),
                |response| response.delivery.outcome.as_str(),
            );
        }
        "router_engine.rs:submit_envelope_async"
        | "router_runtime.rs:submit_envelope_async_from" => {
            control_submit_ok(
                entry,
                runtime.block_on(handle.submit_envelope_async_from(
                    envelope.clone(),
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                )),
                |response| response.outcome.as_str(),
            );
        }
        "router_engine.rs:submit_envelope_mesh_async"
        | "router_runtime.rs:submit_envelope_mesh_async_from" => {
            control_submit_ok(
                entry,
                runtime.block_on(handle.submit_envelope_mesh_async_from(
                    envelope.clone(),
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                )),
                |response| response.delivery.outcome.as_str(),
            );
        }
        "router_engine.rs:own_device_fanout"
        | "router_engine.rs:own_device_fanout_inner"
        | "router_runtime.rs:own_device_fanout" => {
            match handle.own_device_fanout(&fanout_request(envelope)) {
                Ok(_) => {}
                Err(error) => {
                    assert_ne!(error.to_string(), crate::durable_mode::REASON, "{entry}: {error}");
                    assert!(
                        error.to_string().contains("source")
                            || error.to_string().contains("device")
                            || error.to_string().contains("principal")
                            || error.to_string().contains("authority"),
                        "control post-mode stage for {entry}: {error}"
                    );
                }
            }
        }
        "router_runtime.rs:submit_forwarded" | "router_runtime.rs:submit_forwarded_async" => {
            match handle.submit_forwarded(forwarded_request(envelope)) {
                Ok(response) => {
                    assert_ne!(
                        response.get("outcome").and_then(serde_json::Value::as_str),
                        Some("rejected_security:delivery_mode_refused"),
                        "{entry}"
                    );
                }
                Err(error) => {
                    assert_ne!(
                        error.to_string(),
                        "delivery_mode_refused",
                        "control refused at mode for {entry}: {error}"
                    );
                }
            }
        }
        "handlers.rs:handle_itest_mvp0_request"
        | "handlers.rs:forward_authority_response"
        | "handlers.rs:handle_mesh_fast_path_value"
        | "handlers.rs:mesh_fanout_response"
        | "serve.rs:submit_raw_envelope"
        | "migration_drain.rs:forward" => {
            ramflux_protocol::ephemeral::require_durable(envelope)
                .map_err(|error| format!("control refused at mode for {entry}: {error}"))?;
        }
        other => return Err(format!("unknown router ingress {other}").into()),
    }
    Ok(())
}

fn exercise_router_ingress(
    entry: &str,
    handle: &crate::router_runtime::RouterHandle,
    state: &Arc<ramflux_node_core::RouterCore>,
    store: &Arc<ramflux_node_core::RouterRedbStore>,
    envelope: &ramflux_protocol::Envelope,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), Box<dyn std::error::Error>> {
    match entry {
        "handlers.rs:handle_mvp0_envelope"
        | "handlers.rs:handle_mvp0_envelope_from"
        | "handlers.rs:handle_mvp0_envelope_mesh_from"
        | "handlers.rs:handle_mvp0_envelope_async_from" => {
            refuse_handler_ingress(entry, handle, envelope, runtime)
        }
        "router_engine.rs:submit_envelope"
        | "router_engine.rs:submit_envelope_mesh"
        | "router_engine.rs:submit_envelope_mesh_inner"
        | "router_engine.rs:submit_envelope_async"
        | "router_engine.rs:submit_envelope_mesh_async"
        | "router_engine.rs:own_device_fanout"
        | "router_engine.rs:own_device_fanout_inner" => {
            refuse_engine_ingress(entry, state, store, envelope, runtime)
        }
        "router_runtime.rs:submit_envelope_from"
        | "router_runtime.rs:submit_envelope_async_from"
        | "router_runtime.rs:submit_envelope_mesh_from"
        | "router_runtime.rs:submit_envelope_mesh_async_from"
        | "router_runtime.rs:own_device_fanout"
        | "router_runtime.rs:submit_forwarded"
        | "router_runtime.rs:submit_forwarded_async" => {
            refuse_runtime_ingress(entry, handle, envelope, runtime)
        }
        "handlers.rs:handle_itest_mvp0_request"
        | "handlers.rs:forward_authority_response"
        | "handlers.rs:handle_mesh_fast_path_value"
        | "handlers.rs:mesh_fanout_response"
        | "serve.rs:submit_raw_envelope"
        | "migration_drain.rs:forward" => refuse_edge_ingress(entry, handle, envelope, runtime),
        other => Err(format!("unknown router ingress {other}").into()),
    }
}

fn refuse_edge_ingress(
    entry: &str,
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), Box<dyn std::error::Error>> {
    match entry {
        "handlers.rs:handle_itest_mvp0_request" => refuse_itest_http_edge(handle, envelope, entry),
        "handlers.rs:forward_authority_response" => refuse_mesh_json_edge(
            handle,
            "/mvp1/envelope-authority",
            "ramflux-federation",
            &serde_json::to_vec(envelope)?,
            entry,
        ),
        "handlers.rs:handle_mesh_fast_path_value" => refuse_mesh_json_edge(
            handle,
            "/mvp0/envelope/forwarded",
            "ramflux-federation",
            &serde_json::to_vec(&forwarded_request(envelope))?,
            entry,
        ),
        "handlers.rs:mesh_fanout_response" => refuse_fanout_edge(handle, envelope, runtime, entry),
        "serve.rs:submit_raw_envelope" => refuse_raw_submit_edge(handle, envelope, runtime, entry),
        "migration_drain.rs:forward" => refuse_drain_edge(handle, envelope, entry),
        other => Err(format!("unknown router edge {other}").into()),
    }
}

#[cfg(feature = "itest-http")]
fn refuse_itest_http_edge(
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut server, mut client) = loopback()?;
    let request = ramflux_node_core::NodeHttpRequest {
        method: "POST".into(),
        path: "/mvp0/envelope".into(),
        body: serde_json::to_vec(envelope)?,
        keep_alive: false,
        source_ip_hash: None,
        pre_auth_cookie: None,
        pre_auth_now: None,
    };
    let handled = crate::handlers::handle_itest_mvp0_request(&mut server, &request, handle)?;
    assert!(handled, "{entry} did not handle /mvp0/envelope");
    drop(server);
    let mut response = Vec::new();
    std::io::Read::read_to_end(&mut client, &mut response)?;
    assert_refused_http(&response, entry);
    Ok(())
}

#[cfg(not(feature = "itest-http"))]
#[allow(clippy::unnecessary_wraps)]
fn refuse_itest_http_edge(
    _handle: &crate::router_runtime::RouterHandle,
    _envelope: &ramflux_protocol::Envelope,
    _entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn refuse_mesh_json_edge(
    handle: &crate::router_runtime::RouterHandle,
    path: &str,
    peer: &str,
    body: &[u8],
    entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = crate::handlers::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: path.into(),
            body: body.to_vec(),
        },
        handle,
        peer,
    )?;
    assert_eq!(response.status, "200 OK", "{entry}");
    assert_refused_bytes(&response.body, entry);
    Ok(())
}

fn refuse_fanout_edge(
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    runtime: &tokio::runtime::Runtime,
    entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    refuse_mesh_json_edge(
        handle,
        "/mvp10/own-devices/fanout",
        "ramflux-gateway",
        &serde_json::to_vec(&fanout_request(envelope))?,
        entry,
    )?;
    let quic = runtime.block_on(crate::handlers::handle_mesh_quic_request_value(
        &ramflux_transport::GatewayQuicRequest {
            method: "POST".into(),
            path: "/mvp10/own-devices/fanout".into(),
            body: serde_json::to_value(fanout_request(envelope))?,
        },
        handle,
        "ramflux-gateway",
    ))?;
    assert_eq!(quic.status, 200, "{entry}");
    assert_eq!(quic.body["outcome"], crate::durable_mode::OUTCOME, "{entry}");
    Ok(())
}

fn refuse_raw_submit_edge(
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    runtime: &tokio::runtime::Runtime,
    entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let bridge = crate::serve::RouterSubmitBridge {
        router: Arc::new(handle.clone()),
        tokio: runtime.handle().clone(),
    };
    let response = runtime.block_on(bridge.submit_raw_envelope(
        serde_json::to_vec(envelope)?,
        Instant::now(),
        ramflux_node_core::RouterEnvelopeOrigin::Gateway,
    ))?;
    assert_eq!(response.delivery.outcome, crate::durable_mode::OUTCOME, "{entry}");
    Ok(())
}

fn refuse_drain_edge(
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row = ramflux_node_core::MigrationDrainEntry {
        account_anchor: "anchor".into(),
        migration_id: "migration".into(),
        entry: ramflux_node_core::InboxEntry {
            inbox_seq: 1,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope: envelope.clone(),
        },
        retain_until: i64::MAX,
        state: ramflux_node_core::MigrationDrainState::Pending,
        attempts: 0,
        next_attempt: 0,
    };
    let outcome = crate::migration_drain::forward(
        handle.state(),
        handle.store(),
        no_forward(),
        &row,
        ramflux_node_core::now_unix_seconds(),
    )?;
    assert_eq!(outcome, ramflux_node_core::MigrationDrainOutcome::Held, "{entry}");
    Ok(())
}

fn assert_refused_bytes(body: &[u8], entry: &str) {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let outcome = value
        .get("outcome")
        .or_else(|| value.get("delivery").and_then(|delivery| delivery.get("outcome")))
        .and_then(serde_json::Value::as_str);
    assert_eq!(outcome, Some(crate::durable_mode::OUTCOME), "{entry}: {value}");
}

#[cfg(feature = "itest-http")]
fn assert_refused_http(response: &[u8], entry: &str) {
    let text = String::from_utf8_lossy(response);
    assert!(text.contains("200"), "{entry}: {text}");
    assert!(text.contains(crate::durable_mode::OUTCOME), "{entry}: {text}");
}

#[cfg(feature = "itest-http")]
fn loopback() -> Result<(std::net::TcpStream, std::net::TcpStream), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client = std::net::TcpStream::connect(addr)?;
    let (server, _) = listener.accept()?;
    Ok((server, client))
}

fn refuse_handler_ingress(
    entry: &str,
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(envelope)?;
    match entry {
        #[cfg(feature = "itest-http")]
        "handlers.rs:handle_mvp0_envelope" => {
            let response = crate::handlers::handle_mvp0_envelope(&body, handle)?;
            assert_eq!(response.outcome, "rejected_security:delivery_mode_refused", "{entry}");
        }
        #[cfg(not(feature = "itest-http"))]
        "handlers.rs:handle_mvp0_envelope" => {}
        "handlers.rs:handle_mvp0_envelope_mesh_from" => {
            let response = crate::handlers::handle_mvp0_envelope_mesh_from(
                &body,
                handle,
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            )?;
            assert_eq!(
                response.delivery.outcome, "rejected_security:delivery_mode_refused",
                "{entry}"
            );
        }
        #[cfg(feature = "itest-http")]
        "handlers.rs:handle_mvp0_envelope_from" => {
            let response = crate::handlers::handle_mvp0_envelope_from(
                &body,
                handle,
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            )?;
            assert_eq!(response.outcome, "rejected_security:delivery_mode_refused", "{entry}");
        }
        #[cfg(not(feature = "itest-http"))]
        "handlers.rs:handle_mvp0_envelope_from" => {}
        "handlers.rs:handle_mvp0_envelope_async_from" => {
            let response = runtime.block_on(crate::handlers::handle_mvp0_envelope_async_from(
                &body,
                handle,
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            ))?;
            assert_eq!(
                response.delivery.outcome, "rejected_security:delivery_mode_refused",
                "{entry}"
            );
        }
        other => return Err(format!("unknown handler ingress {other}").into()),
    }
    Ok(())
}

fn refuse_engine_ingress(
    entry: &str,
    state: &Arc<ramflux_node_core::RouterCore>,
    store: &Arc<ramflux_node_core::RouterRedbStore>,
    envelope: &ramflux_protocol::Envelope,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = ramflux_node_core::RouterEnvelopeOrigin::Gateway;
    match entry {
        "router_engine.rs:submit_envelope" => {
            let response = crate::router_engine::submit_envelope(
                state.as_ref(),
                store.as_ref(),
                no_forward(),
                envelope.clone(),
                Instant::now(),
                origin,
            )?;
            assert_eq!(response.outcome, "rejected_security:delivery_mode_refused", "{entry}");
        }
        "router_engine.rs:submit_envelope_mesh" => {
            let response = crate::router_engine::submit_envelope_mesh(
                state.as_ref(),
                store.as_ref(),
                no_forward(),
                envelope.clone(),
                Instant::now(),
                origin,
            )?;
            assert_eq!(
                response.delivery.outcome, "rejected_security:delivery_mode_refused",
                "{entry}"
            );
        }
        "router_engine.rs:submit_envelope_mesh_inner" => {
            let response = crate::router_engine::submit_envelope_mesh_inner(
                state.as_ref(),
                store.as_ref(),
                no_forward(),
                envelope.clone(),
                Instant::now(),
                origin,
            )?;
            assert_eq!(
                response.delivery.outcome, "rejected_security:delivery_mode_refused",
                "{entry}"
            );
        }
        "router_engine.rs:submit_envelope_async" => {
            let response = runtime.block_on(crate::router_engine::submit_envelope_async(
                state,
                store,
                no_forward(),
                envelope.clone(),
                Instant::now(),
                origin,
            ))?;
            assert_eq!(response.outcome, "rejected_security:delivery_mode_refused", "{entry}");
        }
        "router_engine.rs:submit_envelope_mesh_async" => {
            let response = runtime.block_on(crate::router_engine::submit_envelope_mesh_async(
                state,
                store,
                no_forward(),
                envelope.clone(),
                Instant::now(),
                origin,
            ))?;
            assert_eq!(
                response.delivery.outcome, "rejected_security:delivery_mode_refused",
                "{entry}"
            );
        }
        "router_engine.rs:own_device_fanout" => {
            let Err(error) = crate::router_engine::own_device_fanout(
                state.as_ref(),
                store.as_ref(),
                &fanout_request(envelope),
            ) else {
                return Err("marked fanout must refuse".into());
            };
            assert_eq!(error.to_string(), "delivery_mode_refused", "{entry}");
        }
        "router_engine.rs:own_device_fanout_inner" => {
            let Err(error) = crate::router_engine::own_device_fanout_inner(
                state.as_ref(),
                store.as_ref(),
                &fanout_request(envelope),
            ) else {
                return Err("marked fanout must refuse".into());
            };
            assert_eq!(error.to_string(), "delivery_mode_refused", "{entry}");
        }
        other => return Err(format!("unknown engine ingress {other}").into()),
    }
    Ok(())
}

fn refuse_runtime_ingress(
    entry: &str,
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = ramflux_node_core::RouterEnvelopeOrigin::Gateway;
    match entry {
        "router_runtime.rs:submit_envelope_from" => {
            let response = handle.submit_envelope_from(envelope.clone(), Instant::now(), origin)?;
            assert_eq!(response.outcome, "rejected_security:delivery_mode_refused", "{entry}");
        }
        "router_runtime.rs:submit_envelope_async_from" => {
            let response = runtime.block_on(handle.submit_envelope_async_from(
                envelope.clone(),
                Instant::now(),
                origin,
            ))?;
            assert_eq!(response.outcome, "rejected_security:delivery_mode_refused", "{entry}");
        }
        "router_runtime.rs:submit_envelope_mesh_from" => {
            let response =
                handle.submit_envelope_mesh_from(envelope.clone(), Instant::now(), origin)?;
            assert_eq!(
                response.delivery.outcome, "rejected_security:delivery_mode_refused",
                "{entry}"
            );
        }
        "router_runtime.rs:submit_envelope_mesh_async_from" => {
            let response = runtime.block_on(handle.submit_envelope_mesh_async_from(
                envelope.clone(),
                Instant::now(),
                origin,
            ))?;
            assert_eq!(
                response.delivery.outcome, "rejected_security:delivery_mode_refused",
                "{entry}"
            );
        }
        "router_runtime.rs:own_device_fanout" => {
            let Err(error) = handle.own_device_fanout(&fanout_request(envelope)) else {
                return Err("marked fanout must refuse".into());
            };
            assert_eq!(error.to_string(), "delivery_mode_refused", "{entry}");
        }
        "router_runtime.rs:submit_forwarded" => {
            let response = handle.submit_forwarded(forwarded_request(envelope))?;
            assert_eq!(
                response.get("outcome").and_then(serde_json::Value::as_str),
                Some("rejected_security:delivery_mode_refused"),
                "{entry}"
            );
        }
        "router_runtime.rs:submit_forwarded_async" => {
            let response =
                runtime.block_on(handle.submit_forwarded_async(forwarded_request(envelope)))?;
            assert_eq!(
                response.get("outcome").and_then(serde_json::Value::as_str),
                Some("rejected_security:delivery_mode_refused"),
                "{entry}"
            );
        }
        other => return Err(format!("unknown runtime ingress {other}").into()),
    }
    Ok(())
}

fn marked_envelope(
    ordinal: u64,
    mode: serde_json::Value,
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let mut envelope = crate::router_runtime::tests::current_envelope(
        &format!("s6c_p03_{ordinal}"),
        "target_alice",
    )?;
    envelope.source_device_id = format!("foreign_{ordinal}");
    envelope.priority = ramflux_protocol::Priority::Low;
    envelope.ttl = 5;
    envelope.created_at = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    envelope.ext.ext.insert("delivery_mode".into(), mode);
    resign_envelope(&mut envelope)?;
    envelope.ext.ext.insert("source_device_authority".into(), foreign_authority(ordinal)?);
    Ok(envelope)
}

fn unmarked_envelope(
    envelope: &ramflux_protocol::Envelope,
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let mut control = envelope.clone();
    control.ext.ext.remove("delivery_mode");
    resign_envelope(&mut control)?;
    Ok(control)
}

fn resign_envelope(
    envelope: &mut ramflux_protocol::Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = ramflux_crypto::blake3_256(
        "ramflux.test.runtime.device.v1",
        format!("alice/{}", envelope.source_device_id).as_bytes(),
    );
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(envelope, seed)?;
    Ok(())
}

fn foreign_authority(ordinal: u64) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(ramflux_node_core::DeviceAuthKeyResponse {
        custody_authority: None,
        root_public_key: Some(ramflux_crypto::fixture_public_key_base64url()),
        signed_device_set: None,
        principal_id: "alice".into(),
        device_id: format!("foreign_{ordinal}"),
        device_epoch: 1,
        branch_public_key: ramflux_crypto::fixture_public_key_base64url(),
        target_delivery_id: "target_alice".into(),
        revoked: false,
    })?)
}

fn fanout_request(
    envelope: &ramflux_protocol::Envelope,
) -> ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
    ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
        principal_id: envelope.source_principal_id.clone(),
        source_device_id: envelope.source_device_id.clone(),
        envelope: envelope.clone(),
    }
}

fn forwarded_request(
    envelope: &ramflux_protocol::Envelope,
) -> ramflux_node_core::ForwardedEnvelopeRequest {
    ramflux_node_core::ForwardedEnvelopeRequest {
        peer_node_id: "peer".into(),
        envelope: envelope.clone(),
        migration_evidence: None,
    }
}

fn no_forward() -> crate::router_engine::AsyncForwardContext<'static> {
    static SEMAPHORE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    crate::router_engine::AsyncForwardContext {
        client: None,
        semaphore: SEMAPHORE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(32))),
        timeout: Duration::from_secs(20),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StoreSnapshot {
    redb: Vec<u8>,
    wal: Vec<u8>,
    identities: Vec<u8>,
    inbox: Vec<u8>,
}

fn store_snapshot(
    state: &ramflux_node_core::RouterCore,
    path: &Path,
) -> Result<StoreSnapshot, Box<dyn std::error::Error>> {
    Ok(StoreSnapshot {
        redb: hash_bytes(&std::fs::read(path).unwrap_or_default()),
        wal: hash_tree(&path.with_file_name(format!(
            "{}.wal",
            path.file_name().and_then(|name| name.to_str()).unwrap_or("router.redb")
        )))?,
        identities: serde_json::to_vec(&state.mvp1_identities_snapshot())?,
        inbox: serde_json::to_vec(&state.resume("target_alice", 0, 256))?,
    })
}

fn hash_bytes(bytes: &[u8]) -> Vec<u8> {
    ramflux_crypto::blake3_256("ramflux.test.durable_ingress.v1", bytes).to_vec()
}

fn hash_tree(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    collect_tree_bytes(path, &mut bytes)?;
    Ok(hash_bytes(&bytes))
}

fn collect_tree_bytes(path: &Path, bytes: &mut Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    if path.is_file() {
        bytes.extend_from_slice(&std::fs::read(path)?);
        return Ok(());
    }
    if !path.is_dir() {
        return Ok(());
    }
    let mut entries = std::fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_tree_bytes(&entry.path(), bytes)?;
    }
    Ok(())
}

fn first_statement_has_mode_guard(
    src: &Path,
    entry: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let (relative, function) = entry.split_once(':').ok_or("invalid registry key")?;
    let source = std::fs::read_to_string(src.join(relative))?;
    let lines = source.lines().collect::<Vec<_>>();
    let Some(start) = lines.iter().position(|line| line.contains("fn ") && line.contains(function))
    else {
        return Ok(false);
    };
    let mut body = start;
    while body < lines.len() && !lines[body].contains('{') {
        body += 1;
    }
    if body == lines.len() {
        return Ok(false);
    }
    Ok(lines
        .iter()
        .skip(body)
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with("//") && *line != "{")
        .take(40)
        .any(|line| line.contains("require_durable")))
}

fn public_envelope_sources(
    src: &Path,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_rust_files(src, &mut files)?;
    files
        .into_iter()
        .map(|file| {
            let relative = file.strip_prefix(src)?.to_string_lossy().replace('\\', "/");
            Ok((relative, std::fs::read_to_string(file)?))
        })
        .collect()
}

fn scan_public_envelope_functions(
    sources: &[(String, String)],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut matches = Vec::new();
    for (relative, source) in sources {
        if relative.split('/').any(|part| part.contains("test") || part.contains("fixture")) {
            continue;
        }
        let lines = source.lines().collect::<Vec<_>>();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index].trim_start();
            if line == "#[cfg(test)]"
                && lines.get(index + 1).is_some_and(|next| is_mod_declaration(next.trim_start()))
            {
                break;
            }
            if is_public_function(line) {
                let mut signature = String::from(line);
                let mut complete = line.trim_end().ends_with('{') || line.trim_end().ends_with(';');
                while !complete && index + 1 < lines.len() {
                    index += 1;
                    let next = lines[index];
                    signature.push(' ');
                    signature.push_str(next.trim());
                    complete = next.trim_end().ends_with('{') || next.trim_end().ends_with(';');
                }
                if ["Envelope", "ForwardRequest", "FanoutRequest", "CustodySessionAction"]
                    .iter()
                    .any(|needle| signature.contains(needle))
                {
                    let function = signature
                        .split("fn ")
                        .nth(1)
                        .and_then(|rest| {
                            rest.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')).next()
                        })
                        .ok_or("public function signature did not contain a function name")?;
                    matches.push(format!("{relative}:{function}"));
                }
            }
            index += 1;
        }
    }
    matches.sort();
    Ok(matches)
}

fn assert_registry_scan_matches(
    sources: &[(String, String)],
    listed: &[String],
) -> Result<(), String> {
    let mut sorted_listed = listed.to_vec();
    sorted_listed.sort();
    let mut deduped = sorted_listed.clone();
    deduped.dedup();
    if deduped.len() != sorted_listed.len() {
        return Err("duplicate durable ingress registry entries".into());
    }
    let scanned = scan_public_envelope_functions(sources).map_err(|error| error.to_string())?;
    if scanned != sorted_listed {
        return Err(format!("scanner matches differ: {scanned:?} != {sorted_listed:?}"));
    }
    Ok(())
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn is_mod_declaration(line: &str) -> bool {
    line.starts_with("mod ")
        || line.starts_with("pub mod ")
        || line.starts_with("pub(crate) mod ")
        || line.starts_with("pub(super) mod ")
}

fn is_public_function(line: &str) -> bool {
    [
        "pub fn ",
        "pub(crate) fn ",
        "pub(super) fn ",
        "pub async fn ",
        "pub(crate) async fn ",
        "pub(super) async fn ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}
