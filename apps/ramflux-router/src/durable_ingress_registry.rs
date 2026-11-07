// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scanner-backed durable ingress registry for the router crate.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    Ingress,
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
    let listed = DURABLE_INGRESS.iter().map(|(name, _)| (*name).to_owned()).collect::<Vec<_>>();
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = public_envelope_sources(&source_root)?;
    assert_registry_scan_matches(&sources, &listed).map_err(std::io::Error::other)?;

    let ingress_count =
        DURABLE_INGRESS.iter().filter(|(_, class)| *class == Class::Ingress).count();
    let non_ingress_count =
        DURABLE_INGRESS.iter().filter(|(_, class)| matches!(class, Class::NonIngress(_))).count();
    assert_eq!((ingress_count, non_ingress_count), (18, 9));
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
    let handle =
        crate::router_runtime::RouterHandle::tokio(Arc::clone(&state), Arc::clone(&store), None);
    let mut ordinal = 0_u64;
    for (entry, class) in DURABLE_INGRESS {
        if *class != Class::Ingress {
            continue;
        }
        for mode in [
            serde_json::Value::String("ephemeral".into()),
            serde_json::Value::String("unknown-mode".into()),
            serde_json::Value::Null,
        ] {
            let marked = marked_envelope(ordinal, mode.clone())?;
            let control = unmarked_envelope(&marked);
            exercise_router_control(entry, &handle, &control, &runtime)?;
            let before = store_snapshot(&path)?;
            exercise_router_ingress(entry, &handle, &state, &store, &marked, &runtime)?;
            let after = store_snapshot(&path)?;
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
            ramflux_protocol::ephemeral::require_durable(envelope)?;
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
            control_submit_ok(entry, handle.own_device_fanout(&fanout_request(envelope)), |_| "");
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
        other => Err(format!("unknown router ingress {other}").into()),
    }
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
    envelope.priority = ramflux_protocol::Priority::Low;
    envelope.ttl = 5;
    envelope.ext.ext.insert("delivery_mode".into(), mode);
    Ok(envelope)
}

fn unmarked_envelope(envelope: &ramflux_protocol::Envelope) -> ramflux_protocol::Envelope {
    let mut control = envelope.clone();
    control.ext.ext.remove("delivery_mode");
    control
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

fn store_snapshot(path: &Path) -> Result<(u64, Vec<u8>), Box<dyn std::error::Error>> {
    let meta = std::fs::metadata(path)?;
    let bytes = std::fs::read(path).unwrap_or_default();
    Ok((meta.len(), ramflux_crypto::blake3_256("ramflux.test.durable_ingress.v1", &bytes).to_vec()))
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
