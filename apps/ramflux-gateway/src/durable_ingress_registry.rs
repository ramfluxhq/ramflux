// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scanner-backed durable ingress registry for the gateway crate.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ramflux_node_core::GatewayServerFrame;

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
    ("quic_dispatch.rs:forward_quic_envelope", Class::Edge),
    ("session.rs:handle_gateway_submit", Class::Edge),
    ("session.rs:handle_gateway_own_device_fanout", Class::Edge),
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
    let listed_scan = DURABLE_INGRESS
        .iter()
        .filter(|(_, class)| !matches!(class, Class::Edge))
        .map(|(name, _)| (*name).to_owned())
        .collect::<Vec<_>>();
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = public_envelope_sources(&source_root)?;
    assert_registry_scan_matches(&sources, &listed_scan).map_err(std::io::Error::other)?;

    let non_ingress_count =
        DURABLE_INGRESS.iter().filter(|(_, class)| matches!(class, Class::NonIngress(_))).count();
    let edge_count = DURABLE_INGRESS.iter().filter(|(_, class)| *class == Class::Edge).count();
    assert_eq!((non_ingress_count, edge_count), (5, 3));
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

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        for with_wal in [true, false] {
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
                    drive_gateway_edge(entry, ordinal, mode, with_wal).await?;
                    ordinal += 1;
                }
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
    with_wal: bool,
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
    ramflux_protocol::ephemeral::require_durable(&control.envelope)?;

    match entry {
        "session.rs:handle_gateway_submit" => {
            let capture = capture_path(ordinal, with_wal);
            let context = crate::session::tests::test_gateway_context()?;
            let before = capture_snapshot(&capture);
            let store_before = gateway_store_snapshot(&context)?;
            let (send, frames) = frame_sink();
            crate::session::handle_gateway_submit(&send, &context, &runtime, &submit).await?;
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
            let store_before = gateway_store_snapshot(&context)?;
            let fanout = ramflux_node_core::GatewayOwnDeviceFanoutFrame {
                signed_request: submit.signed_request.clone(),
                principal_id: runtime.principal_id.clone(),
                source_device_id: runtime.device_id.clone(),
                envelope: submit.envelope.clone(),
            };
            let (send, frames) = frame_sink();
            crate::session::handle_gateway_own_device_fanout(&send, &context, &runtime, &fanout)
                .await?;
            let frames = frames.lock().map_err(|error| error.to_string())?.clone();
            assert!(
                matches!(&frames[..], [GatewayServerFrame::Nack { reason }] if reason == crate::durable_mode::NACK_REASON),
                "{entry}: {frames:?}"
            );
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
        other => return Err(format!("unknown gateway edge {other}").into()),
    }
    Ok(())
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

fn capture_path(ordinal: u64, with_wal: bool) -> PathBuf {
    std::env::var_os("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON").map_or_else(
        || {
            std::env::temp_dir().join(format!(
                "ramflux-s6c-p03-capture-{with_wal}-{ordinal}-{}.json",
                std::process::id()
            ))
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
