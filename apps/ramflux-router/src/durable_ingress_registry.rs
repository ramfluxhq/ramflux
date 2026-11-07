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
    assert_transport_matrix(&handle, &runtime)?;
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
            let marked = marked_envelope(&handle, ordinal, mode.clone())?;
            let control = unmarked_envelope(&handle, &marked)?;
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

const CONTROL_AUTHORITY_ERR: &str = "source authority refused: AuthorityMismatch";
const CONTROL_FORWARDED: &str = "sender_authority_refused";

fn control_submit_ok<T>(
    entry: &str,
    result: anyhow::Result<T>,
    expected: &str,
    outcome: impl FnOnce(&T) -> &str,
) {
    match result {
        Ok(value) => assert_eq!(outcome(&value), expected, "{entry}"),
        Err(error) => assert_eq!(error.to_string(), expected, "{entry}"),
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
            control_handler_submit(entry, handle, envelope, runtime)?;
        }
        "router_engine.rs:submit_envelope" | "router_runtime.rs:submit_envelope_from" => {
            control_submit_ok(
                entry,
                handle.submit_envelope_from(
                    envelope.clone(),
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                ),
                CONTROL_AUTHORITY_ERR,
                |response| response.outcome.as_str(),
            );
        }
        "router_engine.rs:submit_envelope_mesh" | "router_runtime.rs:submit_envelope_mesh_from" => {
            control_submit_ok(
                entry,
                handle.submit_envelope_mesh_from(
                    envelope.clone(),
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                ),
                CONTROL_AUTHORITY_ERR,
                |response| response.delivery.outcome.as_str(),
            );
        }
        "router_engine.rs:submit_envelope_mesh_inner" => {
            control_submit_ok(
                entry,
                crate::router_engine::submit_envelope_mesh_inner(
                    handle.state(),
                    handle.store(),
                    no_forward(),
                    envelope.clone(),
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                ),
                CONTROL_AUTHORITY_ERR,
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
                CONTROL_AUTHORITY_ERR,
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
                CONTROL_AUTHORITY_ERR,
                |response| response.delivery.outcome.as_str(),
            );
        }
        "router_engine.rs:own_device_fanout" | "router_runtime.rs:own_device_fanout" => {
            control_fanout_captured(entry, handle, envelope)?;
        }
        "router_engine.rs:own_device_fanout_inner" => {
            let Err(error) = crate::router_engine::own_device_fanout_inner(
                handle.state(),
                handle.store(),
                &fanout_request(envelope),
            ) else {
                return Err(format!("control {entry} admitted unexpectedly").into());
            };
            assert_eq!(error.to_string(), CONTROL_AUTHORITY_ERR, "{entry}");
        }
        "router_runtime.rs:submit_forwarded" => {
            control_forwarded_value(entry, handle.submit_forwarded(forwarded_request(envelope)));
        }
        "router_runtime.rs:submit_forwarded_async" => {
            control_forwarded_value(
                entry,
                runtime.block_on(handle.submit_forwarded_async(forwarded_request(envelope))),
            );
        }
        "handlers.rs:handle_itest_mvp0_request" => control_itest_http(handle, envelope, entry)?,
        "handlers.rs:forward_authority_response" => control_authority(handle, envelope, entry)?,
        "handlers.rs:handle_mesh_fast_path_value" => {
            let response = crate::handlers::handle_mesh_request_value(
                ramflux_transport::MeshHttpRequest {
                    method: "POST".into(),
                    path: "/mvp0/envelope/forwarded".into(),
                    body: serde_json::to_vec(&forwarded_request(envelope))?,
                },
                handle,
                "ramflux-federation",
            );
            match response {
                Ok(reply) => {
                    assert_eq!(reply.status, "200 OK", "{entry}");
                    let value: serde_json::Value = serde_json::from_slice(&reply.body)?;
                    assert_eq!(
                        value.get("reason").and_then(serde_json::Value::as_str),
                        Some(CONTROL_FORWARDED),
                        "{entry}: {value}"
                    );
                }
                Err(error) => assert_eq!(error.to_string(), CONTROL_FORWARDED, "{entry}"),
            }
        }
        "handlers.rs:mesh_fanout_response" => {
            control_mesh_fanout(entry, handle, envelope)?;
        }
        "serve.rs:submit_raw_envelope" => {
            let bridge = crate::serve::RouterSubmitBridge {
                router: Arc::new(handle.clone()),
                tokio: runtime.handle().clone(),
            };
            control_submit_ok(
                entry,
                runtime.block_on(bridge.submit_raw_envelope(
                    serde_json::to_vec(envelope)?,
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                )),
                CONTROL_AUTHORITY_ERR,
                |response| response.delivery.outcome.as_str(),
            );
        }
        "migration_drain.rs:forward" => {
            let before = crate::migration_drain::DRAIN_PAST_MODE_GUARD
                .load(std::sync::atomic::Ordering::SeqCst);
            let outcome = crate::migration_drain::forward(
                handle.state(),
                handle.store(),
                drain_forward(),
                &drain_row(envelope),
                ramflux_node_core::now_unix_seconds(),
            )?;
            let passed = crate::migration_drain::DRAIN_PAST_MODE_GUARD
                .load(std::sync::atomic::Ordering::SeqCst)
                .saturating_sub(before);
            assert_eq!(
                outcome,
                ramflux_node_core::MigrationDrainOutcome::Held,
                "{entry} unmarked drain has no reachable peer and must hold"
            );
            assert_eq!(
                passed, 1,
                "{entry} unmarked drain must pass the mode guard, outcome={outcome:?}"
            );
        }
        other => return Err(format!("unknown router ingress {other}").into()),
    }
    Ok(())
}

fn control_handler_submit(
    entry: &str,
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(envelope)?;
    match entry {
        #[cfg(feature = "itest-http")]
        "handlers.rs:handle_mvp0_envelope" => {
            control_submit_ok(
                entry,
                crate::handlers::handle_mvp0_envelope(&body, handle),
                CONTROL_AUTHORITY_ERR,
                |response| response.outcome.as_str(),
            );
        }
        #[cfg(not(feature = "itest-http"))]
        "handlers.rs:handle_mvp0_envelope" => {}
        "handlers.rs:handle_mvp0_envelope_mesh_from" => {
            control_submit_ok(
                entry,
                crate::handlers::handle_mvp0_envelope_mesh_from(
                    &body,
                    handle,
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                ),
                CONTROL_AUTHORITY_ERR,
                |response| response.delivery.outcome.as_str(),
            );
        }
        #[cfg(feature = "itest-http")]
        "handlers.rs:handle_mvp0_envelope_from" => {
            control_submit_ok(
                entry,
                crate::handlers::handle_mvp0_envelope_from(
                    &body,
                    handle,
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                ),
                CONTROL_AUTHORITY_ERR,
                |response| response.outcome.as_str(),
            );
        }
        #[cfg(not(feature = "itest-http"))]
        "handlers.rs:handle_mvp0_envelope_from" => {}
        "handlers.rs:handle_mvp0_envelope_async_from" => {
            control_submit_ok(
                entry,
                runtime.block_on(crate::handlers::handle_mvp0_envelope_async_from(
                    &body,
                    handle,
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                )),
                CONTROL_AUTHORITY_ERR,
                |response| response.delivery.outcome.as_str(),
            );
        }
        other => return Err(format!("unknown handler control {other}").into()),
    }
    Ok(())
}

fn control_authority(
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = crate::handlers::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/mvp1/envelope-authority".into(),
            body: serde_json::to_vec(envelope)?,
        },
        handle,
        "ramflux-federation",
    );
    let reply = response?;
    assert_eq!(reply.status, "409 Conflict", "{entry}");
    let refusal: ramflux_node_core::EnvelopeAuthorityRefusal = serde_json::from_slice(&reply.body)?;
    assert_eq!(
        refusal.reason_code,
        ramflux_node_core::EnvelopeAuthorityReason::AuthorityMismatch,
        "{entry}"
    );
    Ok(())
}

fn control_forwarded_value(entry: &str, result: anyhow::Result<serde_json::Value>) {
    match result {
        Ok(value) => {
            assert_eq!(
                value.get("reason").and_then(serde_json::Value::as_str),
                Some(CONTROL_FORWARDED),
                "{entry}: {value}"
            );
        }
        Err(error) => assert_eq!(error.to_string(), CONTROL_FORWARDED, "{entry}"),
    }
}

fn control_fanout_captured(
    entry: &str,
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let Err(error) = handle.own_device_fanout(&fanout_request(envelope)) else {
        return Err(format!("control {entry} admitted unexpectedly").into());
    };
    assert_eq!(error.to_string(), CONTROL_AUTHORITY_ERR, "{entry}");
    Ok(())
}

fn control_mesh_fanout(
    entry: &str,
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = crate::handlers::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/mvp10/own-devices/fanout".into(),
            body: serde_json::to_vec(&fanout_request(envelope))?,
        },
        handle,
        "ramflux-gateway",
    );
    match response {
        Ok(reply) => {
            let value: serde_json::Value = serde_json::from_slice(&reply.body)?;
            return Err(format!("control {entry} admitted: {value}").into());
        }
        Err(error) => assert_eq!(error.to_string(), CONTROL_AUTHORITY_ERR, "{entry}"),
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn control_itest_http(
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
    entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match post_itest_http(handle, "/mvp0/envelope", &serde_json::to_vec(envelope)?) {
        Ok((status, body)) => {
            return Err(format!("control {entry} admitted: {status} {body}").into());
        }
        Err(error) => assert_eq!(error.to_string(), CONTROL_AUTHORITY_ERR, "{entry}"),
    }
    Ok(())
}

#[cfg(not(feature = "itest-http"))]
#[allow(clippy::unnecessary_wraps)]
fn control_itest_http(
    _handle: &crate::router_runtime::RouterHandle,
    _envelope: &ramflux_protocol::Envelope,
    _entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
    assert_refused_http(&response, envelope, entry)?;
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
    assert_refused_bytes(&response.body, &d2_submit(&envelope_from_body(body)?), entry)?;
    Ok(())
}

fn envelope_from_body(
    body: &[u8],
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    if let Ok(envelope) = serde_json::from_slice::<ramflux_protocol::Envelope>(body) {
        return Ok(envelope);
    }
    if let Ok(request) =
        serde_json::from_slice::<ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest>(body)
    {
        return Ok(request.envelope);
    }
    Ok(serde_json::from_slice::<ramflux_node_core::ForwardedEnvelopeRequest>(body)?.envelope)
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
    assert_d2_body(&quic.body, &d2_quic(envelope), entry);
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
    let before =
        crate::migration_drain::DRAIN_PAST_MODE_GUARD.load(std::sync::atomic::Ordering::SeqCst);
    let outcome = crate::migration_drain::forward(
        handle.state(),
        handle.store(),
        drain_forward(),
        &drain_row(envelope),
        ramflux_node_core::now_unix_seconds(),
    )?;
    let passed = crate::migration_drain::DRAIN_PAST_MODE_GUARD
        .load(std::sync::atomic::Ordering::SeqCst)
        .saturating_sub(before);
    assert_eq!(outcome, ramflux_node_core::MigrationDrainOutcome::Held, "{entry}");
    assert_eq!(passed, 0, "{entry} marked drain must refuse at the mode guard");
    Ok(())
}

fn drain_row(envelope: &ramflux_protocol::Envelope) -> ramflux_node_core::MigrationDrainEntry {
    ramflux_node_core::MigrationDrainEntry {
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
    }
}

// Literal expected D2 bodies. They must not call the handler helpers under test,
// so a change to `rejected_security*` or `refused_quic` fails these pins.

/// Direct submit routes: `EnvelopeSubmitResponse` with `migration_refusal` and `nack` skipped.
fn d2_submit(envelope: &ramflux_protocol::Envelope) -> serde_json::Value {
    serde_json::json!({
        "outcome": "rejected_security:delivery_mode_refused",
        "target_delivery_id": envelope.target_delivery_id,
        "inbox_seq": null,
        "cursor": null,
    })
}

/// Mesh/TLS/QUIC envelope routes: `SessionPushSubmitResponse` flattens the submit body and adds session fields.
fn d2_mesh(envelope: &ramflux_protocol::Envelope) -> serde_json::Value {
    serde_json::json!({
        "outcome": "rejected_security:delivery_mode_refused",
        "target_delivery_id": envelope.target_delivery_id,
        "inbox_seq": null,
        "cursor": null,
        "incarnation_id": null,
        "retain_until": null,
    })
}

/// QUIC fanout route: the `refused_quic` body with every field written out.
fn d2_quic(envelope: &ramflux_protocol::Envelope) -> serde_json::Value {
    serde_json::json!({
        "migration_refusal": null,
        "outcome": "rejected_security:delivery_mode_refused",
        "target_delivery_id": envelope.target_delivery_id,
        "inbox_seq": null,
        "cursor": null,
        "nack": null,
    })
}

fn assert_refused_bytes(
    body: &[u8],
    expected: &serde_json::Value,
    entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    assert_d2_body(&value, expected, entry);
    Ok(())
}

fn assert_d2_body(actual: &serde_json::Value, expected: &serde_json::Value, entry: &str) {
    assert_eq!(actual, expected, "{entry}: {actual}");
}

#[cfg(feature = "itest-http")]
fn assert_refused_http(
    response: &[u8],
    envelope: &ramflux_protocol::Envelope,
    entry: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::str::from_utf8(response)?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("missing HTTP header terminator")?;
    let status = head.lines().next().ok_or("missing HTTP status line")?;
    assert_eq!(status, "HTTP/1.1 200 OK", "{entry}: {text}");
    let value: serde_json::Value = serde_json::from_str(body.trim_end())?;
    assert_d2_body(&value, &d2_submit(envelope), entry);
    Ok(())
}

#[cfg(feature = "itest-http")]
fn loopback() -> Result<(std::net::TcpStream, std::net::TcpStream), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client = std::net::TcpStream::connect(addr)?;
    let (server, _) = listener.accept()?;
    Ok((server, client))
}

fn assert_transport_matrix(
    handle: &crate::router_runtime::RouterHandle,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), Box<dyn std::error::Error>> {
    let pki = MeshPki::new("s6c-p03-m1")?;
    for (index, mode) in [
        serde_json::Value::String("ephemeral".into()),
        serde_json::Value::String("unknown-mode".into()),
        serde_json::Value::Null,
    ]
    .into_iter()
    .enumerate()
    {
        let envelope = marked_envelope(handle, 9_000 + u64::try_from(index)?, mode)?;
        assert_http_families(handle, &envelope)?;
        assert_tls_families(handle, &pki, &envelope)?;
        assert_quic_families(handle, runtime, &envelope)?;
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn assert_http_families(
    handle: &crate::router_runtime::RouterHandle,
    envelope: &ramflux_protocol::Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, body) = post_itest_http(handle, "/mvp0/envelope", &serde_json::to_vec(envelope)?)?;
    assert_eq!(status, "HTTP/1.1 200 OK", "http envelope: {status}");
    assert_d2_body(&body, &d2_submit(envelope), "http envelope");
    let (status, body) = post_itest_http(
        handle,
        "/mvp10/own-devices/fanout",
        &serde_json::to_vec(&fanout_request(envelope))?,
    )?;
    assert_eq!(status, "HTTP/1.1 200 OK", "http fanout: {status}");
    assert_d2_body(&body, &d2_submit(envelope), "http fanout");
    let (status, body) =
        post_itest_http(handle, "/mvp1/envelope-authority", &serde_json::to_vec(envelope)?)?;
    assert_eq!(status, "HTTP/1.1 200 OK", "http authority: {status}");
    assert_d2_body(&body, &d2_submit(envelope), "http authority");
    Ok(())
}

#[cfg(not(feature = "itest-http"))]
#[allow(clippy::unnecessary_wraps)]
fn assert_http_families(
    _handle: &crate::router_runtime::RouterHandle,
    _envelope: &ramflux_protocol::Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(feature = "itest-http")]
fn post_itest_http(
    handle: &crate::router_runtime::RouterHandle,
    path: &str,
    body: &[u8],
) -> Result<(String, serde_json::Value), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let mut client = std::net::TcpStream::connect(listener.local_addr()?)?;
    let (mut server, _) = listener.accept()?;
    write!(
        client,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    client.write_all(body)?;
    crate::handlers::handle_itest_request(&mut server, handle)?;
    drop(server);
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    let text = String::from_utf8(response)?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("missing HTTP header terminator")?;
    let status = head.lines().next().ok_or("missing HTTP status line")?.to_owned();
    Ok((status, serde_json::from_str(body.trim_end())?))
}

fn assert_tls_families(
    handle: &crate::router_runtime::RouterHandle,
    pki: &MeshPki,
    envelope: &ramflux_protocol::Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, envelope_body) =
        tls_marked_post(handle, pki, "/mvp0/envelope", "ramflux-gateway", envelope, &pki.gateway)?;
    assert_eq!(status, 200, "tls envelope");
    assert_d2_body(&envelope_body, &d2_mesh(envelope), "tls envelope");
    let (status, fanout_body) = tls_marked_post(
        handle,
        pki,
        "/mvp10/own-devices/fanout",
        "ramflux-gateway",
        &fanout_request(envelope),
        &pki.gateway,
    )?;
    assert_eq!(status, 200, "tls fanout");
    assert_d2_body(&fanout_body, &d2_submit(envelope), "tls fanout");
    let (status, authority_body) = tls_marked_post(
        handle,
        pki,
        "/mvp1/envelope-authority",
        "ramflux-federation",
        envelope,
        &pki.federation,
    )?;
    assert_eq!(status, 200, "tls authority");
    assert_d2_body(&authority_body, &d2_submit(envelope), "tls authority");
    Ok(())
}

fn tls_marked_post<T: serde::Serialize>(
    handle: &crate::router_runtime::RouterHandle,
    pki: &MeshPki,
    path: &str,
    peer: &str,
    payload: &T,
    client_tls: &ramflux_transport::MeshTlsConfig,
) -> Result<(u16, serde_json::Value), Box<dyn std::error::Error>> {
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &pki.router)?;
    let endpoint = server.local_addr()?.to_string();
    let handle = handle.clone();
    let peer = peer.to_owned();
    let worker = std::thread::spawn(move || -> Result<(), String> {
        let mut stream = server.accept().map_err(|error| error.to_string())?;
        let tcp = stream.sock.try_clone().map_err(|error| error.to_string())?;
        let set = ramflux_node_core::ConnectionSet::new(4);
        let guard = set.register(&tcp).map_err(|error| error.to_string())?.ok_or("tls register")?;
        crate::handlers::handle_mesh_request(&mut stream, &handle, &peer, &guard)
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    let (status, body) = ramflux_transport::mesh_http_post_status_body(
        &endpoint,
        path,
        client_tls,
        "ramflux-router",
        payload,
    )?;
    worker.join().map_err(|_| "tls worker panicked")??;
    Ok((status, serde_json::from_slice(&body)?))
}

fn assert_quic_families(
    handle: &crate::router_runtime::RouterHandle,
    runtime: &tokio::runtime::Runtime,
    envelope: &ramflux_protocol::Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let submit = runtime.block_on(crate::handlers::handle_mesh_quic_request_value(
        &ramflux_transport::GatewayQuicRequest {
            method: "POST".into(),
            path: "/mvp0/envelope".into(),
            body: serde_json::to_value(envelope)?,
        },
        handle,
        "ramflux-gateway",
    ))?;
    assert_eq!(submit.status, 200, "quic envelope");
    assert_d2_body(&submit.body, &d2_mesh(envelope), "quic envelope");
    let fanout = runtime.block_on(crate::handlers::handle_mesh_quic_request_value(
        &ramflux_transport::GatewayQuicRequest {
            method: "POST".into(),
            path: "/mvp10/own-devices/fanout".into(),
            body: serde_json::to_value(fanout_request(envelope))?,
        },
        handle,
        "ramflux-gateway",
    ))?;
    assert_eq!(fanout.status, 200, "quic fanout");
    assert_d2_body(&fanout.body, &d2_quic(envelope), "quic fanout");
    let authority = runtime.block_on(crate::handlers::handle_mesh_quic_request_value(
        &ramflux_transport::GatewayQuicRequest {
            method: "POST".into(),
            path: "/mvp1/envelope-authority".into(),
            body: serde_json::to_value(envelope)?,
        },
        handle,
        "ramflux-federation",
    ))?;
    assert_eq!(authority.status, 200, "quic authority");
    assert_d2_body(&authority.body, &d2_submit(envelope), "quic authority");
    Ok(())
}

struct MeshPki {
    root: PathBuf,
    router: ramflux_transport::MeshTlsConfig,
    gateway: ramflux_transport::MeshTlsConfig,
    federation: ramflux_transport::MeshTlsConfig,
}

impl Drop for MeshPki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl MeshPki {
    fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-s6c-p03-{name}-{}-{}",
            std::process::id(),
            ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
        ));
        std::fs::create_dir_all(&root)?;
        let ca_key = root.join("ca-key.pem");
        let ca = root.join("ca.pem");
        openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&ca_key)?])?;
        openssl(&[
            "req",
            "-x509",
            "-new",
            "-key",
            path_str(&ca_key)?,
            "-out",
            path_str(&ca)?,
            "-days",
            "1",
            "-subj",
            "/CN=S6c P03 CA",
        ])?;
        Ok(Self {
            router: mesh_service(&root, &ca_key, &ca, "ramflux-router")?,
            gateway: mesh_service(&root, &ca_key, &ca, "ramflux-gateway")?,
            federation: mesh_service(&root, &ca_key, &ca, "ramflux-federation")?,
            root,
        })
    }
}

fn mesh_service(
    root: &Path,
    ca_key: &Path,
    ca: &Path,
    id: &str,
) -> Result<ramflux_transport::MeshTlsConfig, Box<dyn std::error::Error>> {
    let dir = root.join(id);
    std::fs::create_dir_all(&dir)?;
    let key = dir.join("key.pem");
    let csr = dir.join("req.csr");
    let cert = dir.join("cert.pem");
    let ext = dir.join("ext.cnf");
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&key)?])?;
    openssl(&[
        "req",
        "-new",
        "-key",
        path_str(&key)?,
        "-out",
        path_str(&csr)?,
        "-subj",
        &format!("/CN={id}"),
    ])?;
    std::fs::write(
        &ext,
        format!(
            "subjectAltName = DNS:{id}, DNS:localhost, URI:spiffe://node-a/{id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
        ),
    )?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        path_str(&csr)?,
        "-CA",
        path_str(ca)?,
        "-CAkey",
        path_str(ca_key)?,
        "-CAcreateserial",
        "-out",
        path_str(&cert)?,
        "-days",
        "1",
        "-extfile",
        path_str(&ext)?,
    ])?;
    Ok(ramflux_transport::MeshTlsConfig {
        ca_cert: ca.to_path_buf(),
        service_cert: cert,
        service_key: key,
    })
}

fn openssl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("openssl").args(args).status()?;
    if status.success() { Ok(()) } else { Err(format!("openssl {args:?} failed: {status}").into()) }
}

fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| "utf8 path".into())
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
    _handle: &crate::router_runtime::RouterHandle,
    ordinal: u64,
    mode: serde_json::Value,
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let mut envelope = crate::router_runtime::tests::current_envelope(
        &format!("s6c_p03_{ordinal}"),
        "target_alice",
    )?;
    envelope.priority = ramflux_protocol::Priority::Low;
    envelope.ttl = ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS_U32;
    envelope.created_at = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    envelope.ext.ext.insert("delivery_mode".into(), mode);
    resign_envelope(&mut envelope)?;
    Ok(envelope)
}

fn unmarked_envelope(
    _handle: &crate::router_runtime::RouterHandle,
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
    let seed = ramflux_crypto::blake3_256("ramflux.test.runtime.device.v1", b"alice/alice_phone");
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(envelope, seed)?;
    Ok(())
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

fn drain_forward() -> crate::router_engine::AsyncForwardContext<'static> {
    static SEMAPHORE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    static CLIENT: std::sync::OnceLock<crate::router_runtime::LocalFederationForwardClient> =
        std::sync::OnceLock::new();
    crate::router_engine::AsyncForwardContext {
        client: Some(CLIENT.get_or_init(|| crate::router_runtime::LocalFederationForwardClient {
            url: "http://127.0.0.1:1/forward".into(),
            admin_token: None,
            source_node_id: "A".into(),
        })),
        semaphore: SEMAPHORE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(32))),
        timeout: Duration::from_millis(50),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StoreSnapshot {
    redb: Vec<u8>,
    wal: Vec<u8>,
    identities: Vec<u8>,
    inbox: Vec<u8>,
    replay: Vec<u8>,
    foreign_device_heads: Vec<u8>,
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
        replay: serde_json::to_vec(&state.replay_guard_test_snapshot())?,
        foreign_device_heads: state.foreign_device_heads_test_bytes(),
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
