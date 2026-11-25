// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node side of the central node report (CENTRAL-SERVICE-NODE-REPORT-EXT-01 section 3, rv = 1).
//! Only `hello` is sent. Nothing runs unless `[node_report]` is configured explicitly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ramflux_node_core::{NodeReportConfig, NodeReportRegionConfig, NodeServiceConfig};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use crate::FederationDiscoverySurface;

/// ALPN of the report stream (one request per bidirectional stream).
pub(crate) const ALPN: &[u8] = b"rfc-node-1";
/// Domain string of `m` (section 3.1), including its NUL terminator.
const DOMAIN: &[u8] = b"rfc-node-report\0";
const FRAME_VERSION: u8 = 1;
const ALG_ED25519: u8 = 1;
const SIGNATURE_LEN: usize = 64;
/// `fv || alg || n:u16be` in front of the body.
const PAYLOAD_HEADER_LEN: usize = 4;
const MAX_PAYLOAD_LEN: usize = 4096;
const MAX_BODY_LEN: usize = MAX_PAYLOAD_LEN - PAYLOAD_HEADER_LEN - SIGNATURE_LEN;
const MIN_BODY_LEN: usize = 2;
/// Bound on the reply (`u32be || JSON`), read before parsing.
const MAX_REPLY_LEN: usize = 16 * 1024;
const RV: u64 = 1;
const HELLO_KV: u64 = 1;
/// Application close reason the edge uses when it closes a connection whose key is no longer `active`.
const ACCESS_CLOSE_REASON: &[u8] = b"access";
/// Version of the node's field set (`reg` in ext); the registry file is not yet pinned.
const NODE_FIELD_REGISTRY: u64 = 1;
const MAX_LABEL_LEN: usize = 64;
const MAX_CAPS: usize = 16;
const MAX_JSON_INT: u64 = (1 << 53) - 1;
/// A retry resends the same bytes only while `ts` is this close to now (section 3.3).
const RETRY_WINDOW_MS: u64 = 50_000;
const DEFAULT_FULL_EVERY_S: u64 = 3600;
const MIN_FULL_EVERY_S: u64 = 300;
const MAX_FULL_EVERY_S: u64 = 86_400;
const DEFAULT_RETRY_MS: u64 = 2000;
const MAX_RETRY_MS: u64 = 3_600_000;
const CONNECT_BACKOFF: Duration = Duration::from_secs(60);
/// Back-off after `unknown_key` or `suspended_key` (section 3.4): 5 min, doubling to 60 min.
const REFUSAL_BACKOFF_MIN: Duration = Duration::from_mins(5);
const REFUSAL_BACKOFF_MAX: Duration = Duration::from_hours(1);
const UNSUPPORTED_RETRY: Duration = Duration::from_secs(3600);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReportError {
    Body(&'static str),
    Frame(&'static str),
    Signing,
}

/// The signed message `m` of section 3.1, exactly as the centre rebuilds it.
pub(crate) fn signing_message(centre_id: &str, body: &[u8]) -> Result<Vec<u8>, ReportError> {
    let centre_len = u16::try_from(centre_id.len()).map_err(|_| ReportError::Frame("centre_id"))?;
    let body_len = u16::try_from(body.len()).map_err(|_| ReportError::Frame("body length"))?;
    let mut message = Vec::with_capacity(DOMAIN.len() + 4 + 2 + centre_id.len() + 2 + body.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&[FRAME_VERSION, ALG_ED25519]);
    message.extend_from_slice(&centre_len.to_be_bytes());
    message.extend_from_slice(centre_id.as_bytes());
    message.extend_from_slice(&body_len.to_be_bytes());
    message.extend_from_slice(body);
    Ok(message)
}

/// `L:u32be || fv || alg || n:u16be || body || sig`, with `L = 4 + n + 64`.
pub(crate) fn encode_frame(
    seed: &[u8; 32],
    centre_id: &str,
    body: &[u8],
) -> Result<Vec<u8>, ReportError> {
    if !(MIN_BODY_LEN..=MAX_BODY_LEN).contains(&body.len()) {
        return Err(ReportError::Frame("body length outside 2..=4028"));
    }
    let message = signing_message(centre_id, body)?;
    let signature = ramflux_protocol::decode_base64url(
        &ramflux_crypto::sign_canonical_bytes_with_seed(&message, *seed),
    )
    .map_err(|_| ReportError::Signing)?;
    if signature.len() != SIGNATURE_LEN {
        return Err(ReportError::Signing);
    }
    let body_len = u16::try_from(body.len()).map_err(|_| ReportError::Frame("body length"))?;
    let payload_len = PAYLOAD_HEADER_LEN + body.len() + SIGNATURE_LEN;
    let frame_len = u32::try_from(payload_len).map_err(|_| ReportError::Frame("frame length"))?;
    let mut frame = Vec::with_capacity(4 + payload_len);
    frame.extend_from_slice(&frame_len.to_be_bytes());
    frame.extend_from_slice(&[FRAME_VERSION, ALG_ED25519]);
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(body);
    frame.extend_from_slice(&signature);
    Ok(frame)
}

/// Values of a hello that do not change between reports of one process.
#[derive(Clone)]
pub(crate) struct StaticFacts {
    ext: Map<String, Value>,
}

pub(crate) struct HelloInput<'a> {
    pub label: &'a str,
    pub node_key: &'a str,
    pub key_gen: u64,
    pub boot_id: &'a str,
    pub boot_ts: u64,
    pub seq: u64,
    pub ts: u64,
    pub ext: Map<String, Value>,
}

/// Body core members of a `full` hello (section 3.2). Serialised once; the bytes are the signed bytes.
pub(crate) fn hello_body(input: &HelloInput<'_>) -> Result<Vec<u8>, ReportError> {
    validate_label(input.label)?;
    for value in [input.boot_ts, input.seq, input.ts, input.key_gen] {
        if value > MAX_JSON_INT {
            return Err(ReportError::Body("integer above 2^53-1"));
        }
    }
    if input.seq == 0 {
        return Err(ReportError::Body("seq starts at 1"));
    }
    let body = json!({
        "rv": RV,
        "kind": "hello",
        "kv": HELLO_KV,
        "node_key": input.node_key,
        "key_gen": input.key_gen,
        "boot_id": input.boot_id,
        "boot_ts": input.boot_ts,
        "seq": input.seq,
        "ts": input.ts,
        "label": input.label,
        "full": true,
        "base_seq": Value::Null,
        "ext": input.ext,
    });
    serde_json::to_vec(&body).map_err(|_| ReportError::Body("serialize"))
}

fn validate_label(label: &str) -> Result<(), ReportError> {
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(ReportError::Body("label must be 1-64 bytes"));
    }
    let controls = label
        .chars()
        .any(|c| c.is_control() || matches!(u32::from(c), 0x202A..=0x202E | 0x2066..=0x2069));
    if controls {
        return Err(ReportError::Body("label has controls or bidi marks"));
    }
    Ok(())
}

fn printable(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && value.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// Ext members for `hello` (section 4, P0 registry entries). Region is sent only when configured.
pub(crate) fn static_facts(
    sw_version: &str,
    core_rev: &str,
    caps: &[String],
    region: Option<&NodeReportRegionConfig>,
) -> Result<StaticFacts, ReportError> {
    if !printable(sw_version, 64) {
        return Err(ReportError::Body("sw_version"));
    }
    if caps.len() > MAX_CAPS || !caps.iter().all(|cap| printable(cap, 128)) {
        return Err(ReportError::Body("caps"));
    }
    let mut ext = Map::new();
    ext.insert("sw_version".into(), json!(sw_version));
    let rev_ok = core_rev.len() == 12 && core_rev.bytes().all(|b| b.is_ascii_hexdigit());
    if rev_ok {
        ext.insert("core_rev".into(), json!(core_rev.to_ascii_lowercase()));
    }
    ext.insert("reg".into(), json!(NODE_FIELD_REGISTRY));
    ext.insert("rv_max".into(), json!(RV));
    ext.insert("caps".into(), json!(caps));
    if let Some(region) = region {
        ext.insert("country".into(), json!(region.country));
        if let Some(subdivision) = &region.subdivision {
            ext.insert("subdivision".into(), json!(subdivision));
        }
    }
    Ok(StaticFacts { ext })
}

/// Directives the centre advertised (section 3.3). Before any reply the P0 defaults apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Directives {
    rv_max: u64,
    hello_kv_max: u64,
    min_rv: u64,
    min_hello_kv: u64,
    full_every_s: u64,
}

impl Default for Directives {
    fn default() -> Self {
        Self {
            rv_max: RV,
            hello_kv_max: HELLO_KV,
            min_rv: 0,
            min_hello_kv: 0,
            full_every_s: DEFAULT_FULL_EVERY_S,
        }
    }
}

impl Directives {
    /// Only a version the centre advertised is used (G2). A reply without `kinds.hello` advertises none.
    fn accepts_hello(&self) -> bool {
        self.rv_max >= RV
            && self.min_rv <= RV
            && self.hello_kv_max >= HELLO_KV
            && self.min_hello_kv <= HELLO_KV
    }

    /// Applies a `dir` object. Unknown members are ignored (G3); an out-of-range interval keeps the old value.
    fn apply(&mut self, dir: &Value) {
        let uint = |key: &str| dir.get(key).and_then(Value::as_u64).unwrap_or(0);
        let kind = |key: &str| {
            dir.get("kinds").and_then(|kinds| kinds.get(key)).and_then(Value::as_u64).unwrap_or(0)
        };
        let min_kind = |key: &str| {
            dir.get("min_kv").and_then(|kinds| kinds.get(key)).and_then(Value::as_u64).unwrap_or(0)
        };
        self.rv_max = uint("rv_max");
        self.hello_kv_max = kind("hello");
        self.min_rv = uint("min_rv");
        self.min_hello_kv = min_kind("hello");
        if let Some(seconds) = dir.get("full_every_s").and_then(Value::as_u64)
            && (MIN_FULL_EVERY_S..=MAX_FULL_EVERY_S).contains(&seconds)
        {
            self.full_every_s = seconds;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    Accepted { dir: Option<Value> },
    Retry { after: Duration },
    Rejected { reason: String },
}

/// Parses `u32be || JSON`. Unknown status, bad JSON or a bad length count as `unavailable` (G3).
pub(crate) fn parse_reply(bytes: &[u8]) -> Reply {
    let retry = Reply::Retry { after: Duration::from_millis(DEFAULT_RETRY_MS) };
    let Some((len_bytes, json_bytes)) = bytes.split_first_chunk::<4>() else {
        return retry;
    };
    if u32::from_be_bytes(*len_bytes) as usize != json_bytes.len() {
        return retry;
    }
    let Ok(value) = ramflux_protocol::parse_i_json::<Value>(json_bytes) else {
        return retry;
    };
    match value.get("status").and_then(Value::as_str) {
        Some("accepted") => Reply::Accepted { dir: value.get("dir").cloned() },
        Some("rejected") => Reply::Rejected {
            reason: value.get("reason").and_then(Value::as_str).unwrap_or("").to_owned(),
        },
        Some("throttled" | "unavailable") => {
            let ms = value
                .get("retry_after_ms")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_RETRY_MS)
                .min(MAX_RETRY_MS);
            Reply::Retry { after: Duration::from_millis(ms) }
        }
        _ => retry,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// Adds up to 10% so reports from many nodes do not line up.
fn jitter(base: Duration) -> Duration {
    let byte = ramflux_crypto::random_32().map_or(0, |bytes| bytes.first().copied().unwrap_or(0));
    base + base.mul_f64(f64::from(byte) / 2550.0)
}

/// Refusal back-off with jitter, bounded to 5..=60 minutes (section 3.4, owner-decided range).
fn refusal_wait(step: Duration) -> Duration {
    jitter(step).clamp(REFUSAL_BACKOFF_MIN, REFUSAL_BACKOFF_MAX)
}

/// Doubles the refusal back-off, staying within 5..=60 minutes.
fn next_refusal_step(step: Duration) -> Duration {
    step.saturating_mul(2).clamp(REFUSAL_BACKOFF_MIN, REFUSAL_BACKOFF_MAX)
}

/// What one request produced. `AccessClosed` is the edge closing the connection with application reason `access`.
enum Sent {
    Reply(Vec<u8>),
    AccessClosed,
    Failed(String),
}

fn access_closed(error: &quinn::ConnectionError) -> bool {
    matches!(error, quinn::ConnectionError::ApplicationClosed(close) if close.reason.as_ref() == ACCESS_CLOSE_REASON)
}

struct Reporter {
    seed: [u8; 32],
    centre_id: String,
    node_key: String,
    key_gen: u64,
    label: String,
    facts: StaticFacts,
    boot_id: String,
    boot_ts: u64,
    seq: u64,
}

impl Reporter {
    /// Returns the frame and its `ts`; the frame is what a retry resends.
    fn next_hello(&mut self) -> Result<(Vec<u8>, u64), ReportError> {
        self.seq = self.seq.checked_add(1).ok_or(ReportError::Body("seq overflow"))?;
        let ts = now_ms();
        let body = hello_body(&HelloInput {
            label: &self.label,
            node_key: &self.node_key,
            key_gen: self.key_gen,
            boot_id: &self.boot_id,
            boot_ts: self.boot_ts,
            seq: self.seq,
            ts,
            ext: self.facts.ext.clone(),
        })?;
        Ok((encode_frame(&self.seed, &self.centre_id, &body)?, ts))
    }
}

fn client_config(ca_path: &str) -> Result<quinn::ClientConfig, String> {
    let pem = std::fs::read(ca_path).map_err(|error| format!("read ca_cert: {error}"))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots
            .add(cert.map_err(|error| format!("parse ca_cert: {error}"))?)
            .map_err(|error| error.to_string())?;
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| error.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| error.to_string())?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

/// One request on one bidirectional stream.
async fn send_once(
    endpoint: &quinn::Endpoint,
    centre: SocketAddr,
    server_name: &str,
    frame: &[u8],
) -> Sent {
    let connection = match endpoint.connect(centre, server_name) {
        Ok(connecting) => match tokio::time::timeout(IO_TIMEOUT, connecting).await {
            Err(_) => return Sent::Failed("connect timeout".to_owned()),
            Ok(Err(error)) if access_closed(&error) => return Sent::AccessClosed,
            Ok(Err(error)) => return Sent::Failed(error.to_string()),
            Ok(Ok(connection)) => connection,
        },
        Err(error) => return Sent::Failed(error.to_string()),
    };
    let (mut send, mut recv) = match connection.open_bi().await {
        Ok(streams) => streams,
        Err(error) if access_closed(&error) => return Sent::AccessClosed,
        Err(error) => return Sent::Failed(error.to_string()),
    };
    match send.write_all(frame).await {
        Err(quinn::WriteError::ConnectionLost(error)) if access_closed(&error) => {
            return Sent::AccessClosed;
        }
        Err(error) => return Sent::Failed(error.to_string()),
        Ok(()) => {}
    }
    if let Err(error) = send.finish() {
        return Sent::Failed(error.to_string());
    }
    let read = tokio::time::timeout(IO_TIMEOUT, recv.read_to_end(MAX_REPLY_LEN)).await;
    let reply = match read {
        Err(_) => return Sent::Failed("reply timeout".to_owned()),
        Ok(Ok(reply)) => reply,
        Ok(Err(quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(error))))
            if access_closed(&error) =>
        {
            return Sent::AccessClosed;
        }
        Ok(Err(error)) => return Sent::Failed(error.to_string()),
    };
    connection.close(0u32.into(), b"");
    Sent::Reply(reply)
}

async fn sleep_or_cancel(wait: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        () = tokio::time::sleep(wait) => true,
        () = shutdown.cancelled() => false,
    }
}

async fn run(
    mut reporter: Reporter,
    endpoint: quinn::Endpoint,
    centre: SocketAddr,
    server_name: String,
    shutdown: CancellationToken,
) {
    let mut directives = Directives::default();
    let mut pending: Option<(Vec<u8>, u64)> = None;
    let mut refusal_step = REFUSAL_BACKOFF_MIN;
    loop {
        if !directives.accepts_hello() {
            tracing::warn!("node report: centre advertises no hello; retrying hourly");
            pending = None;
            if !sleep_or_cancel(UNSUPPORTED_RETRY, &shutdown).await {
                return;
            }
            continue;
        }
        let (frame, ts) = match pending.take() {
            Some((frame, ts)) if now_ms().saturating_sub(ts) <= RETRY_WINDOW_MS => (frame, ts),
            _ => match reporter.next_hello() {
                Ok(built) => built,
                Err(error) => {
                    tracing::error!(
                        ?error,
                        "node report: hello could not be built; sender stopped"
                    );
                    return;
                }
            },
        };
        let wait = match send_once(&endpoint, centre, &server_name, &frame).await {
            Sent::Failed(error) => {
                tracing::warn!(%error, "node report: centre unreachable");
                jitter(CONNECT_BACKOFF)
            }
            Sent::AccessClosed => {
                // The key is no longer active; the next report learns which refusal applies.
                tracing::warn!("node report: edge closed the connection (access); backing off");
                let wait = refusal_wait(refusal_step);
                refusal_step = next_refusal_step(refusal_step);
                wait
            }
            Sent::Reply(bytes) => match parse_reply(&bytes) {
                Reply::Accepted { dir } => {
                    refusal_step = REFUSAL_BACKOFF_MIN;
                    if let Some(dir) = dir {
                        directives.apply(&dir);
                    }
                    jitter(Duration::from_secs(directives.full_every_s))
                }
                Reply::Retry { after } => {
                    pending = Some((frame, ts));
                    jitter(after)
                }
                Reply::Rejected { reason } => match reason.as_str() {
                    "revoked_key" => {
                        tracing::error!(
                            "node report: centre revoked this key; reports stopped until the configuration changes"
                        );
                        return;
                    }
                    "unknown_key" | "suspended_key" => {
                        let wait = refusal_wait(refusal_step);
                        refusal_step = next_refusal_step(refusal_step);
                        tracing::warn!(
                            %reason,
                            retry_in_s = wait.as_secs(),
                            "node report: key not admitted; reports paused with back-off"
                        );
                        wait
                    }
                    "unsupported" => {
                        tracing::warn!(%reason, "node report: centre does not accept this report");
                        jitter(UNSUPPORTED_RETRY)
                    }
                    _ => {
                        tracing::warn!(%reason, "node report: rejected");
                        jitter(Duration::from_secs(directives.full_every_s))
                    }
                },
            },
        };
        if !sleep_or_cancel(wait, &shutdown).await {
            return;
        }
    }
}

/// Starts the sender when `[node_report]` is configured. Errors stay local: the node keeps serving.
pub(crate) fn start(
    config: &NodeServiceConfig,
    discovery: &FederationDiscoverySurface,
    seed: [u8; 32],
) {
    let report = match ramflux_node_core::load_node_report_config(std::env::args().skip(1)) {
        Ok(Some(report)) => report,
        Ok(None) => return,
        Err(error) => {
            tracing::error!(%error, "node report not started: invalid [node_report]");
            return;
        }
    };
    if let Err(error) = spawn(config, discovery, seed, &report) {
        tracing::error!(%error, "node report not started");
    }
}

fn spawn(
    config: &NodeServiceConfig,
    discovery: &FederationDiscoverySurface,
    seed: [u8; 32],
    report: &NodeReportConfig,
) -> Result<(), String> {
    let facts = static_facts(
        ramflux_node_core::version::VERSION,
        ramflux_node_core::version::GIT_SHA,
        &discovery.node_capabilities,
        report.region.as_ref(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let random = ramflux_crypto::random_32().map_err(|_| "boot_id randomness".to_owned())?;
    let boot_id =
        ramflux_protocol::encode_base64url(random.iter().take(16).copied().collect::<Vec<u8>>());
    let reporter = Reporter {
        seed,
        centre_id: report.centre.id.clone(),
        node_key: discovery.node_public_key.clone(),
        key_gen: report.key_gen,
        label: config.node_id.clone(),
        facts,
        boot_id,
        boot_ts: now_ms(),
        seq: 0,
    };
    let centre: SocketAddr = report.centre.addr.parse().map_err(|_| "centre addr".to_owned())?;
    let client = client_config(&report.centre.ca_cert)?;
    let server_name = report.centre.server_name.clone();
    ramflux_node_core::spawn_service_worker("ramflux-node-report", move |shutdown| {
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(%error, "node report runtime");
                return;
            }
        };
        runtime.block_on(async move {
            let unspecified = if centre.is_ipv6() {
                IpAddr::from(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::from(Ipv4Addr::UNSPECIFIED)
            };
            let bind = SocketAddr::new(unspecified, 0);
            let Ok(mut endpoint) = quinn::Endpoint::client(bind) else {
                tracing::error!("node report: endpoint bind failed");
                return;
            };
            endpoint.set_default_client_config(client);
            run(reporter, endpoint, centre, server_name, shutdown).await;
        });
    })
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_and_limits() {
        let seed = [7u8; 32];
        let body = br#"{"rv":1}"#;
        let frame = encode_frame(&seed, "rfc-qa", body).expect("test: small frame encodes");
        let payload_len =
            u32::from_be_bytes(*frame.first_chunk::<4>().expect("test: length prefix"));
        assert_eq!(payload_len as usize, 4 + body.len() + 64, "L must be 4 + n + 64");
        assert_eq!(frame.get(4..6), Some(&[1u8, 1][..]), "fv=1, alg=1 at the start of the payload");
        assert_eq!(
            frame.get(6..8),
            Some(&u16::try_from(body.len()).expect("test: body fits u16").to_be_bytes()[..]),
            "n:u16be"
        );
        let max_body = vec![b' '; MAX_BODY_LEN];
        let max = encode_frame(&seed, "rfc-qa", &max_body).expect("test: max body fits 4096");
        assert_eq!(max.len(), 4 + MAX_PAYLOAD_LEN, "frame at the L limit");
        assert!(
            encode_frame(&seed, "rfc-qa", &vec![b' '; MAX_BODY_LEN + 1]).is_err(),
            "over the L limit is refused"
        );
        assert!(encode_frame(&seed, "rfc-qa", b"{").is_err(), "n below 2 is refused");
    }

    #[test]
    fn signing_message_layout() {
        let message = signing_message("rfc-qa", b"{}").expect("test: message builds");
        let mut expected = b"rfc-node-report\0".to_vec();
        expected.extend_from_slice(&[1, 1, 0, 6]);
        expected.extend_from_slice(b"rfc-qa");
        expected.extend_from_slice(&[0, 2]);
        expected.extend_from_slice(b"{}");
        assert_eq!(
            message, expected,
            "m = domain || fv || alg || len(centre_id) || centre_id || n || body"
        );
    }
}
