// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scanner-backed durable ingress registry for the gateway crate.

#[cfg(feature = "itest-http")]
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ramflux_node_core::GatewayServerFrame;

const GATEWAY_REGISTRY_TEST: &str =
    "durable_ingress_registry::durable_ingress_registry_refuses_marked_envelopes";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    NonIngress(&'static str),
    Edge,
}

const DURABLE_INGRESS: &[(&str, Class)] = &[
    (
        "clients.rs:notify_offline_wake",
        Class::NonIngress("offline wake notify; no envelope persist"),
    ),
    (
        "clients.rs:notification_class_for_envelope",
        Class::NonIngress("pure notification class mapping"),
    ),
    (
        "durable_mode.rs:rejected_security",
        Class::NonIngress("typed refusal construction; no envelope persist"),
    ),
    ("itest_http.rs:dispatch_protected_itest_request", Class::Edge),
    ("quic_dispatch.rs:forward_quic_envelope", Class::Edge),
    ("session.rs:handle_gateway_submit", Class::Edge),
    ("session.rs:handle_gateway_own_device_fanout", Class::Edge),
    (
        "session.rs:dispatch_offline_wake",
        Class::NonIngress("offline wake via spawn_blocking; no envelope persist"),
    ),
    (
        "session_push.rs:submit_reply",
        Class::NonIngress("session-push reply framing; no envelope persist"),
    ),
    (
        "submit_source.rs:bind_source",
        Class::NonIngress("binds authenticated session source; no persist"),
    ),
];

#[test]
fn durable_ingress_registry_refuses_marked_envelopes() -> Result<(), Box<dyn std::error::Error>> {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = public_envelope_sources(&source_root)?;
    let scanned = scan_public_envelope_functions(&sources).map_err(|error| error.to_string())?;
    let listed_scan = DURABLE_INGRESS
        .iter()
        .filter(|(name, class)| {
            !matches!(class, Class::Edge) || scanned.iter().any(|scanned| scanned == name)
        })
        .map(|(name, _)| (*name).to_owned())
        .collect::<Vec<_>>();
    assert_registry_scan_matches(&sources, &listed_scan).map_err(std::io::Error::other)?;

    let non_ingress_count =
        DURABLE_INGRESS.iter().filter(|(_, class)| matches!(class, Class::NonIngress(_))).count();
    let edge_count = DURABLE_INGRESS.iter().filter(|(_, class)| *class == Class::Edge).count();
    assert_eq!((non_ingress_count, edge_count), (6, 4));
    for (entry, class) in DURABLE_INGRESS {
        if let Class::NonIngress(reason) = class {
            assert!(!reason.is_empty(), "{entry} needs a NonIngress reason");
        }
        if matches!(class, Class::Edge) {
            assert!(
                first_statement_has_mode_guard(&source_root, entry)?,
                "{entry} must refuse marked delivery modes before its first effect"
            );
        }
    }

    if std::env::var_os("RAMFLUX_S6C_P03_CHILD").is_none() {
        for with_wal in ["1", "0"] {
            let capture = std::env::temp_dir().join(format!(
                "ramflux-s6c-p03-gw-{}-{}-{}.jsonl",
                with_wal,
                std::process::id(),
                ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
            ));
            let status = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", GATEWAY_REGISTRY_TEST, "--nocapture"])
                .env("RAMFLUX_S6C_P03_CHILD", "1")
                .env("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON", &capture)
                .status()?;
            let _ = std::fs::remove_file(&capture);
            assert!(status.success(), "gateway registry child WAL={with_wal} failed: {status}");
        }
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let mut ordinal = 0_u64;
        for (entry, class) in DURABLE_INGRESS {
            if *class != Class::Edge {
                continue;
            }
            for mode in [
                serde_json::Value::String("ephemeral".into()),
                serde_json::Value::String("unknown-mode".into()),
                serde_json::Value::Null,
            ] {
                drive_gateway_edge(entry, ordinal, mode).await?;
                ordinal += 1;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
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

async fn drive_gateway_edge(
    entry: &str,
    ordinal: u64,
    mode: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let runtime = crate::session::submit_fixtures::test_runtime()?;
    let mut submit = crate::session::submit_fixtures::signed_submit(&runtime, now)?;
    submit.envelope.priority = ramflux_protocol::Priority::Low;
    submit.envelope.ttl = 5;
    submit.envelope.ext.ext.insert("delivery_mode".into(), mode.clone());
    resign_submit(&mut submit)?;
    let mut control = crate::session::submit_fixtures::signed_submit(&runtime, now)?;
    control.envelope.ext.ext.remove("delivery_mode");
    resign_submit(&mut control)?;
    ramflux_protocol::ephemeral::require_durable(&control.envelope)
        .map_err(|error| format!("control refused at mode for {entry}: {error}"))?;
    drive_control_gateway_edge(entry, &runtime, &control).await?;
    drive_marked_gateway_edge(entry, ordinal, &runtime, &submit).await
}

async fn drive_control_gateway_edge(
    entry: &str,
    runtime: &crate::GatewaySessionRuntime,
    control: &ramflux_node_core::GatewaySubmitFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    match entry {
        "session.rs:handle_gateway_submit" => {
            let context = crate::session::tests::test_gateway_context()?;
            let (send, frames) = frame_sink();
            match crate::session::handle_gateway_submit(&send, &context, runtime, control).await {
                Ok(()) => assert_eq!(nack_reason(&frames)?, CONTROL_SUBMIT_ERR, "{entry}"),
                Err(error) => assert_eq!(error.to_string(), CONTROL_SUBMIT_ERR, "{entry}"),
            }
        }
        "session.rs:handle_gateway_own_device_fanout" => {
            let context = crate::session::tests::test_gateway_context()?;
            let fanout = fanout_frame(runtime, control);
            let (send, frames) = frame_sink();
            match crate::session::handle_gateway_own_device_fanout(
                &send, &context, runtime, &fanout,
            )
            .await
            {
                Ok(()) => assert_eq!(nack_reason(&frames)?, CONTROL_FANOUT_NACK, "{entry}"),
                Err(error) => assert_eq!(error.to_string(), CONTROL_FANOUT_NACK, "{entry}"),
            }
        }
        "quic_dispatch.rs:forward_quic_envelope" => {
            let body = serde_json::to_value(&control.envelope)?;
            match crate::quic_dispatch::forward_quic_envelope(
                &crate::session::tests::test_gateway_context()?.router,
                body,
            )
            .await
            {
                Ok(response) => {
                    return Err(format!("control {entry} admitted: {response}").into());
                }
                Err(error) => assert_eq!(error.to_string(), CONTROL_QUIC_ERR, "{entry}"),
            }
        }
        "itest_http.rs:dispatch_protected_itest_request" => {
            drive_itest_http_control(entry, control)?;
        }
        other => return Err(format!("unknown gateway edge {other}").into()),
    }
    Ok(())
}

async fn drive_marked_gateway_edge(
    entry: &str,
    ordinal: u64,
    runtime: &crate::GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture = capture_path(ordinal);
    match entry {
        "session.rs:handle_gateway_submit" => {
            let context = crate::session::tests::test_gateway_context()?;
            let before = capture_snapshot(&capture);
            let store_before = gateway_store_snapshot(&context)?;
            let (send, frames) = frame_sink();
            crate::session::handle_gateway_submit(&send, &context, runtime, submit).await?;
            let frames = frames.lock().map_err(|error| error.to_string())?.clone();
            assert_eq!(frames.len(), 1, "{entry}");
            assert!(
                matches!(&frames[0], GatewayServerFrame::Nack { reason } if reason == crate::durable_mode::NACK_REASON),
                "{entry}: {frames:?}"
            );
            assert_eq!(capture_snapshot(&capture), before, "{entry} capture file changed");
            assert_eq!(
                gateway_store_snapshot(&context)?,
                store_before,
                "{entry} gateway store changed"
            );
        }
        "session.rs:handle_gateway_own_device_fanout" => {
            let context = crate::session::tests::test_gateway_context()?;
            let before = capture_snapshot(&capture);
            let store_before = gateway_store_snapshot(&context)?;
            let fanout = fanout_frame(runtime, submit);
            let (send, frames) = frame_sink();
            crate::session::handle_gateway_own_device_fanout(&send, &context, runtime, &fanout)
                .await?;
            let frames = frames.lock().map_err(|error| error.to_string())?.clone();
            assert!(
                matches!(&frames[..], [GatewayServerFrame::Nack { reason }] if reason == crate::durable_mode::NACK_REASON),
                "{entry}: {frames:?}"
            );
            assert_eq!(capture_snapshot(&capture), before, "{entry} capture file changed");
            assert_eq!(
                gateway_store_snapshot(&context)?,
                store_before,
                "{entry} gateway store changed"
            );
        }
        "quic_dispatch.rs:forward_quic_envelope" => {
            let body = serde_json::to_value(&submit.envelope)?;
            let response = crate::quic_dispatch::forward_quic_envelope(
                &crate::session::tests::test_gateway_context()?.router,
                body,
            )
            .await?;
            assert_eq!(response["outcome"], "rejected_security:delivery_mode_refused", "{entry}");
        }
        "itest_http.rs:dispatch_protected_itest_request" => {
            drive_itest_http_marked(entry, submit)?;
        }
        other => return Err(format!("unknown gateway edge {other}").into()),
    }
    Ok(())
}

fn fanout_frame(
    runtime: &crate::GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> ramflux_node_core::GatewayOwnDeviceFanoutFrame {
    ramflux_node_core::GatewayOwnDeviceFanoutFrame {
        signed_request: submit.signed_request.clone(),
        principal_id: runtime.principal_id.clone(),
        source_device_id: runtime.device_id.clone(),
        envelope: submit.envelope.clone(),
    }
}

#[cfg(target_os = "macos")]
const CONTROL_CONNECT: &str = "I/O error: Connection refused (os error 61)";
#[cfg(not(target_os = "macos"))]
const CONTROL_CONNECT: &str = "I/O error: Connection refused (os error 111)";
#[cfg(target_os = "macos")]
const CONTROL_FANOUT_NACK: &str =
    "own-device fanout rejected: I/O error: Connection refused (os error 61)";
#[cfg(not(target_os = "macos"))]
const CONTROL_FANOUT_NACK: &str =
    "own-device fanout rejected: I/O error: Connection refused (os error 111)";
const CONTROL_SUBMIT_ERR: &str = CONTROL_CONNECT;
const CONTROL_QUIC_ERR: &str = CONTROL_CONNECT;

fn nack_reason(
    frames: &Mutex<Vec<GatewayServerFrame>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let frames = frames.lock().map_err(|error| error.to_string())?.clone();
    match frames.as_slice() {
        [GatewayServerFrame::Nack { reason }] => Ok(reason.clone()),
        other => Err(format!("expected one nack, got {other:?}").into()),
    }
}

#[cfg(feature = "itest-http")]
fn drive_itest_http_control(
    entry: &str,
    control: &ramflux_node_core::GatewaySubmitFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    let context = crate::session::tests::test_gateway_context()?;
    let (mut server, mut client) = loopback()?;
    let request = envelope_http_request(&control.envelope)?;
    match crate::itest_http::dispatch_protected_itest_request(
        &mut server,
        &context.router,
        &request,
        &context.gateway_id,
    ) {
        Ok(()) => {
            drop(server);
            let mut response = Vec::new();
            client.read_to_end(&mut response)?;
            let text = String::from_utf8_lossy(&response);
            return Err(format!("control {entry} admitted: {text}").into());
        }
        Err(error) => assert_eq!(error.to_string(), CONTROL_SUBMIT_ERR, "{entry}"),
    }
    Ok(())
}

#[cfg(not(feature = "itest-http"))]
#[allow(clippy::unnecessary_wraps)]
fn drive_itest_http_control(
    _entry: &str,
    _control: &ramflux_node_core::GatewaySubmitFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(feature = "itest-http")]
fn drive_itest_http_marked(
    entry: &str,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    let context = crate::session::tests::test_gateway_context()?;
    let (mut server, mut client) = loopback()?;
    let request = envelope_http_request(&submit.envelope)?;
    crate::itest_http::dispatch_protected_itest_request(
        &mut server,
        &context.router,
        &request,
        &context.gateway_id,
    )?;
    drop(server);
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    let text = std::str::from_utf8(&response)?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("missing HTTP header terminator")?;
    let status = head.lines().next().ok_or("missing HTTP status line")?;
    assert_eq!(status, "HTTP/1.1 200 OK", "{entry}: {text}");
    let value: serde_json::Value = serde_json::from_str(body.trim_end())?;
    assert_eq!(
        value.get("outcome").and_then(serde_json::Value::as_str),
        Some("rejected_security:delivery_mode_refused"),
        "{entry}: {value}"
    );
    Ok(())
}

#[cfg(not(feature = "itest-http"))]
#[allow(clippy::unnecessary_wraps)]
fn drive_itest_http_marked(
    _entry: &str,
    _submit: &ramflux_node_core::GatewaySubmitFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(feature = "itest-http")]
fn envelope_http_request(
    envelope: &ramflux_protocol::Envelope,
) -> Result<ramflux_node_core::NodeHttpRequest, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::NodeHttpRequest {
        method: "POST".into(),
        path: "/mvp0/envelope".into(),
        body: serde_json::to_vec(envelope)?,
        keep_alive: false,
        source_ip_hash: None,
        pre_auth_cookie: None,
        pre_auth_now: None,
        forwarded_proto: None,
        forwarded_for: None,
    })
}

#[cfg(feature = "itest-http")]
fn loopback() -> Result<(std::net::TcpStream, std::net::TcpStream), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client = std::net::TcpStream::connect(addr)?;
    let (server, _) = listener.accept()?;
    Ok((server, client))
}

struct TestFrameSink(std::sync::Arc<Mutex<Vec<GatewayServerFrame>>>);

impl ramflux_transport::GatewaySessionFrameSink for TestFrameSink {
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), ramflux_transport::TransportError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.0
                .lock()
                .map_err(|_| ramflux_transport::TransportError::Quic("test sink mutex".into()))?
                .push(serde_json::from_slice(body)?);
            Ok(())
        })
    }
}

fn frame_sink() -> (crate::GatewaySendHandle, std::sync::Arc<Mutex<Vec<GatewayServerFrame>>>) {
    let frames = std::sync::Arc::new(Mutex::new(Vec::new()));
    (std::sync::Arc::new(tokio::sync::Mutex::new(Box::new(TestFrameSink(frames.clone())))), frames)
}

fn gateway_store_snapshot(
    context: &crate::GatewayQuicContext,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(serde_json::to_vec(&context.store.load_state()?)?)
}

fn capture_snapshot(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

fn resign_submit(
    submit: &mut ramflux_node_core::GatewaySubmitFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    submit.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&submit.envelope)?,
        [4; 32],
    );
    submit.signed_request.body_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        &ramflux_protocol::canonical_json_bytes(&submit.envelope)?,
    );
    submit.signed_request.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(&submit.signed_request)?,
        [4; 32],
    );
    Ok(())
}

fn capture_path(ordinal: u64) -> PathBuf {
    std::env::var_os("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON").map_or_else(
        || {
            std::env::temp_dir()
                .join(format!("ramflux-s6c-p03-capture-{ordinal}-{}.jsonl", std::process::id()))
        },
        PathBuf::from,
    )
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
