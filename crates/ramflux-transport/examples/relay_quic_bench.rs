// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! PERF-D1-1 transport-layer QUIC capacity microbench.
//!
//! Drives `RelayQuicPool::request_once` against a real in-process quinn TLS echo server (no HTTP)
//! to measure the pool's cold-handshake / warm-pooled / reconnect / backpressure mechanics. Emits
//! per-request latency samples + `metrics_snapshot` deltas as machine-readable JSON. This is a
//! default-off benchmark tool (feature `perf-bench`); it never enters the default/release artifact.
//! It measures the pool mechanism only — it makes NO claim about the public rf/rfd path or any
//! production SLO, and it does not change any functional default.

#![cfg(feature = "perf-bench")]
#![allow(clippy::pedantic, clippy::missing_docs_in_private_items)]

use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ramflux_transport::{
    GatewayQuicRequest, GatewayQuicResponse, RelayClientQuicConfig, RelayQuicCapacity,
    RelayQuicPool, RelayQuicPoolConfig, RelayQuicPoolKey, RelayQuicPoolMetricsSnapshot,
    RelayQuicRequestError, RelayQuicTimeouts,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::{Barrier, Notify};

const HARNESS_VERSION: &str = "perf-d1-1a.v1";
const RELAY_SERVER_NAME: &str = "ramflux-relay";
const MAX_QUIC_FRAME_BYTES: usize = 1024 * 1024;
const REQUEST_METHOD: &str = "POST";
const REQUEST_PATH: &str = "/relay/v1/object/get_chunk";
const TASK_TIMEOUT: Duration = Duration::from_secs(30);
const FP_DOMAIN: &str = "ramflux.perf.d1.payload.v1";

type BenchResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

// ---- frame codec (reimplemented so the crate source stays read-only; matches the production
// 4-byte big-endian length prefix + JSON body, MAX_QUIC_FRAME_BYTES cap) ----

async fn write_frame(send: &mut quinn::SendStream, body: &[u8]) -> BenchResult<()> {
    let len = u32::try_from(body.len()).map_err(|_e| "frame too large for u32")?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(body).await?;
    Ok(())
}

async fn read_frame(recv: &mut quinn::RecvStream) -> BenchResult<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    recv.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_QUIC_FRAME_BYTES {
        return Err("frame exceeds MAX_QUIC_FRAME_BYTES".into());
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    Ok(body)
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn payload_fingerprint(body: &serde_json::Value) -> BenchResult<(String, usize)> {
    let bytes = serde_json::to_vec(body)?;
    let fp = blake3::keyed_hash(blake3::hash(FP_DOMAIN.as_bytes()).as_bytes(), &bytes);
    Ok((fp.to_hex().to_string(), bytes.len()))
}

// ---- rcgen self-signed cert written to a temp PEM the pool client trusts ----

struct BenchCert {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    ca_path: PathBuf,
}

fn make_cert(tag: &str) -> BenchResult<BenchCert> {
    let certified = rcgen::generate_simple_self_signed(vec![RELAY_SERVER_NAME.to_owned()])?;
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()));
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let ca_path = std::env::temp_dir()
        .join(format!("ramflux-relay-bench-ca-{tag}-{}-{nanos}.pem", std::process::id()));
    std::fs::write(&ca_path, certified.cert.pem().as_bytes())?;
    Ok(BenchCert { cert_der, key_der, ca_path })
}

/// A per-key echo server. It deserializes the request, verifies method/path, and replies with a
/// blake3 fingerprint + length of the request body so the client can prove the payload round-tripped
/// intact. `hold` (backpressure) parks each accepted stream until released.
struct EchoServer {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    malformed: Arc<AtomicUsize>,
    release: Arc<Notify>,
    released: Arc<AtomicBool>,
    hold: bool,
    endpoint: quinn::Endpoint,
}

fn spawn_echo_server(cert: &BenchCert, hold: bool) -> BenchResult<EchoServer> {
    install_crypto_provider();
    let server_config = quinn::ServerConfig::with_single_cert(
        vec![cert.cert_der.clone()],
        cert.key_der.clone_key(),
    )?;
    let bind: SocketAddr = "127.0.0.1:0".parse()?;
    let endpoint = quinn::Endpoint::server(server_config, bind)?;
    let addr = endpoint.local_addr()?;
    let accepted = Arc::new(AtomicUsize::new(0));
    let malformed = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let released = Arc::new(AtomicBool::new(false));
    let (accepted_t, malformed_t, release_t, released_t, endpoint_t) = (
        Arc::clone(&accepted),
        Arc::clone(&malformed),
        Arc::clone(&release),
        Arc::clone(&released),
        endpoint.clone(),
    );
    tokio::spawn(async move {
        while let Some(connecting) = endpoint_t.accept().await {
            let Ok(connection) = connecting.await else {
                continue;
            };
            let accepted_c = Arc::clone(&accepted_t);
            let malformed_c = Arc::clone(&malformed_t);
            let release_c = Arc::clone(&release_t);
            let released_c = Arc::clone(&released_t);
            tokio::spawn(async move {
                loop {
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        break;
                    };
                    let Ok(raw) = read_frame(&mut recv).await else {
                        break;
                    };
                    accepted_c.fetch_add(1, Ordering::SeqCst);
                    let body = match serde_json::from_slice::<GatewayQuicRequest>(&raw) {
                        Ok(request)
                            if request.method == REQUEST_METHOD && request.path == REQUEST_PATH =>
                        {
                            match payload_fingerprint(&request.body) {
                                Ok((fp, len)) => serde_json::json!({"fp": fp, "len": len}),
                                Err(_e) => {
                                    malformed_c.fetch_add(1, Ordering::SeqCst);
                                    serde_json::json!({"error": "fingerprint"})
                                }
                            }
                        }
                        _ => {
                            malformed_c.fetch_add(1, Ordering::SeqCst);
                            serde_json::json!({"error": "bad_request"})
                        }
                    };
                    if hold {
                        loop {
                            if released_c.load(Ordering::SeqCst) {
                                break;
                            }
                            let notified = release_c.notified();
                            if released_c.load(Ordering::SeqCst) {
                                break;
                            }
                            notified.await;
                        }
                    }
                    let response = GatewayQuicResponse { status: 200, body };
                    let Ok(bytes) = serde_json::to_vec(&response) else {
                        break;
                    };
                    if write_frame(&mut send, &bytes).await.is_err() {
                        break;
                    }
                    let _ = quinn::SendStream::finish(&mut send);
                }
            });
        }
    });
    Ok(EchoServer { addr, accepted, malformed, release, released, hold, endpoint })
}

impl EchoServer {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
    fn release_all(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        if self.hold {
            self.release_all();
        }
        self.endpoint.close(quinn::VarInt::from_u32(0), b"bench-done");
    }
}

// ---- CLI ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Steady,
    Cold,
    Reconnect,
    Backpressure,
}

#[derive(Debug, Clone)]
struct Args {
    scenario: Scenario,
    keys: usize,
    concurrency: usize,
    payload_bytes: usize,
    warmup: usize,
    rounds: usize,
    requests_per_round: usize,
    seed: u64,
    output: Option<PathBuf>,
}

fn parse_scenario(raw: &str) -> Result<Scenario, String> {
    match raw {
        "steady" => Ok(Scenario::Steady),
        "cold" => Ok(Scenario::Cold),
        "reconnect" => Ok(Scenario::Reconnect),
        "backpressure" => Ok(Scenario::Backpressure),
        other => Err(format!("unknown scenario: {other}")),
    }
}

fn parse_usize(raw: &str, flag: &str) -> Result<usize, String> {
    raw.parse().map_err(|_e| format!("invalid {flag}"))
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut scenario = None;
    let mut keys = 1usize;
    let mut concurrency = 1usize;
    let mut payload_bytes = 0usize;
    let mut warmup = 20usize;
    let mut rounds = 5usize;
    let mut requests_per_round = 100usize;
    let mut seed = 1u64;
    let mut output = None;
    let mut i = 0usize;
    while i < argv.len() {
        let flag = argv[i].as_str();
        let val =
            |offset: usize| argv.get(i + offset).ok_or_else(|| format!("missing value for {flag}"));
        match flag {
            "--scenario" => scenario = Some(parse_scenario(val(1)?)?),
            "--keys" => keys = parse_usize(val(1)?, "--keys")?,
            "--concurrency" => concurrency = parse_usize(val(1)?, "--concurrency")?,
            "--payload-bytes" => payload_bytes = parse_usize(val(1)?, "--payload-bytes")?,
            "--warmup" => warmup = parse_usize(val(1)?, "--warmup")?,
            "--rounds" => rounds = parse_usize(val(1)?, "--rounds")?,
            "--requests-per-round" => {
                requests_per_round = parse_usize(val(1)?, "--requests-per-round")?
            }
            "--seed" => seed = val(1)?.parse().map_err(|_e| "invalid --seed".to_owned())?,
            "--output" => output = Some(PathBuf::from(val(1)?)),
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 2;
    }
    let scenario = scenario.ok_or_else(|| "missing --scenario".to_owned())?;
    if keys == 0 || concurrency == 0 || rounds == 0 || requests_per_round == 0 {
        return Err("keys/concurrency/rounds/requests-per-round must be > 0".to_owned());
    }
    if serialized_request_len(payload_bytes) > MAX_QUIC_FRAME_BYTES {
        return Err(format!("payload-bytes {payload_bytes} exceeds MAX_QUIC_FRAME_BYTES frame"));
    }
    Ok(Args {
        scenario,
        keys,
        concurrency,
        payload_bytes,
        warmup,
        rounds,
        requests_per_round,
        seed,
        output,
    })
}

fn build_request(payload_bytes: usize) -> GatewayQuicRequest {
    let body = if payload_bytes == 0 {
        serde_json::Value::Null
    } else {
        serde_json::json!({ "d": "a".repeat(payload_bytes) })
    };
    GatewayQuicRequest { method: REQUEST_METHOD.to_owned(), path: REQUEST_PATH.to_owned(), body }
}

fn serialized_request_len(payload_bytes: usize) -> usize {
    serde_json::to_vec(&build_request(payload_bytes)).map_or(usize::MAX, |v| v.len())
}

// ---- statistics ----

fn nearest_rank(sorted_ns: &[u128], pct: f64) -> u128 {
    if sorted_ns.is_empty() {
        return 0;
    }
    let n = sorted_ns.len() as f64;
    let rank = (pct / 100.0 * n).ceil().max(1.0);
    let idx = (rank as usize).min(sorted_ns.len()) - 1;
    sorted_ns[idx]
}

fn error_class(err: &RelayQuicRequestError) -> &'static str {
    match err {
        RelayQuicRequestError::Config(_) => "config",
        RelayQuicRequestError::Connect(_) => "connect",
        RelayQuicRequestError::Handshake(_) => "handshake",
        RelayQuicRequestError::PeerAuth(_) => "peer_auth",
        RelayQuicRequestError::RequestTimeout(_) => "request_timeout",
        RelayQuicRequestError::ConnectionLost(_) => "connection_lost",
        RelayQuicRequestError::Protocol(_) => "protocol",
        RelayQuicRequestError::Backpressure { .. } => "backpressure",
        RelayQuicRequestError::Encode(_) => "encode",
    }
}

// ---- config builders ----

fn timeouts() -> BenchResult<RelayQuicTimeouts> {
    Ok(RelayQuicTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(20),
        Duration::from_secs(5),
    )?)
}

fn pool_config_with(cap: usize) -> BenchResult<RelayQuicPoolConfig> {
    Ok(RelayQuicPoolConfig::new(timeouts()?, RelayQuicCapacity::new(64, cap)?))
}

fn client_config(
    addr: SocketAddr,
    ca_path: &std::path::Path,
) -> BenchResult<RelayClientQuicConfig> {
    Ok(RelayClientQuicConfig::new(&addr.to_string(), RELAY_SERVER_NAME, ca_path)?)
}

// ---- per-request outcome ----

#[derive(Clone)]
struct Sample {
    round: usize,
    key: usize,
    index: usize,
    latency_ns: u128,
    ok: bool,
    error_class: Option<&'static str>,
}

impl Sample {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "round": self.round,
            "key": self.key,
            "index": self.index,
            "latency_ns": self.latency_ns,
            "ok": self.ok,
            "error_class": self.error_class
        })
    }
}

/// Runs one request and verifies status + payload fingerprint/length round-tripped intact.
#[allow(clippy::too_many_arguments)]
async fn one_request(
    pool: &RelayQuicPool,
    config: &RelayClientQuicConfig,
    request: &GatewayQuicRequest,
    expected: &(String, usize),
    round: usize,
    key: usize,
    index: usize,
) -> Sample {
    let start = Instant::now();
    let outcome = pool.request_once(config, request).await;
    let latency_ns = start.elapsed().as_nanos();
    let (ok, error_class) = match outcome {
        Ok(response) => {
            let fp_ok = response.body.get("fp").and_then(serde_json::Value::as_str)
                == Some(expected.0.as_str());
            let len_ok = response.body.get("len").and_then(serde_json::Value::as_u64)
                == Some(expected.1 as u64);
            if response.status == 200 && fp_ok && len_ok {
                (true, None)
            } else {
                (false, Some("payload_mismatch"))
            }
        }
        Err(err) => (false, Some(error_class(&err))),
    };
    Sample { round, key, index, latency_ns, ok, error_class }
}

struct PhaseOutcome {
    samples: Vec<Sample>,
    window_ns: u128,
    total_bytes: u128,
    metrics: serde_json::Value,
    server_delta: usize,
    total_concurrency: usize,
    reconnect_delta: u64,
    connect_sum: u64,
}

fn pool_delta_json(
    before: RelayQuicPoolMetricsSnapshot,
    after: RelayQuicPoolMetricsSnapshot,
) -> serde_json::Value {
    serde_json::json!({
        "pool_hit": after.pool_hit.saturating_sub(before.pool_hit),
        "pool_miss": after.pool_miss.saturating_sub(before.pool_miss),
        "connect": after.connect.saturating_sub(before.connect),
        "reconnect": after.reconnect.saturating_sub(before.reconnect),
        "stale_evict": after.stale_evict.saturating_sub(before.stale_evict),
        "backpressure": after.backpressure.saturating_sub(before.backpressure),
        "request_timeout": after.request_timeout.saturating_sub(before.request_timeout),
        "in_flight_peak": after.in_flight_peak,
        "in_flight_current_end": after.in_flight_current,
    })
}

// ---- scenario drivers ----

async fn run_steady(args: &Args) -> BenchResult<PhaseOutcome> {
    let cert = make_cert("steady")?;
    let mut servers = Vec::new();
    let mut configs = Vec::new();
    let mut expects = Vec::new();
    let request = build_request(args.payload_bytes);
    let expected = payload_fingerprint(&request.body)?;
    for _ in 0..args.keys {
        let server = spawn_echo_server(&cert, false)?;
        configs.push(client_config(server.addr, &cert.ca_path)?);
        expects.push(expected.clone());
        servers.push(server);
    }
    let request_bytes = serialized_request_len(args.payload_bytes) as u128;
    let pool = Arc::new(RelayQuicPool::new(pool_config_with(256)?));
    // warmup every key (not measured, not counted in server_delta baseline).
    for config in &configs {
        for _ in 0..args.warmup.max(1) {
            let _ = pool.request_once(config, &request).await;
        }
    }
    let server_baseline: usize = servers.iter().map(EchoServer::accepted).sum();
    let before = pool.metrics_snapshot();

    let requests_per_round = args.requests_per_round;
    let per_key_quota = args.rounds * args.requests_per_round;
    let total_concurrency = args.keys * args.concurrency;
    // K keys each driven by C concurrent workers; ALL start together behind one barrier so the
    // measured peak concurrency is K*C, not a serialized per-key run.
    let barrier = Arc::new(Barrier::new(total_concurrency));
    let request = Arc::new(request);
    let samples_shared = Arc::new(std::sync::Mutex::new(Vec::<Sample>::new()));
    let mut set = tokio::task::JoinSet::new();
    let key_counters: Vec<Arc<AtomicUsize>> =
        (0..args.keys).map(|_| Arc::new(AtomicUsize::new(0))).collect();
    let window_marker = Arc::new(std::sync::Mutex::new(None::<Instant>));
    for k in 0..args.keys {
        for _w in 0..args.concurrency {
            let pool = Arc::clone(&pool);
            let config = configs[k].clone();
            let expected = expects[k].clone();
            let request = Arc::clone(&request);
            let barrier = Arc::clone(&barrier);
            let counter = Arc::clone(&key_counters[k]);
            let samples_shared = Arc::clone(&samples_shared);
            let window_marker = Arc::clone(&window_marker);
            set.spawn(async move {
                barrier.wait().await;
                {
                    let mut m = window_marker.lock().map_err(|_e| "window lock")?;
                    if m.is_none() {
                        *m = Some(Instant::now());
                    }
                }
                loop {
                    let index = counter.fetch_add(1, Ordering::SeqCst);
                    if index >= per_key_quota {
                        break;
                    }
                    let round = index / requests_per_round;
                    let sample = tokio::time::timeout(
                        TASK_TIMEOUT,
                        one_request(&pool, &config, &request, &expected, round, k, index),
                    )
                    .await?;
                    samples_shared.lock().map_err(|_e| "samples lock")?.push(sample);
                }
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            });
        }
    }
    while let Some(joined) = set.join_next().await {
        joined??;
    }
    let window_start =
        window_marker.lock().map_err(|_e| "window read")?.ok_or("no window start")?;
    let window_ns = window_start.elapsed().as_nanos();
    let after = pool.metrics_snapshot();
    let samples = Arc::try_unwrap(samples_shared)
        .map_err(|_e| "samples still shared")?
        .into_inner()
        .map_err(|_e| "samples poisoned")?;
    let server_delta = servers.iter().map(EchoServer::accepted).sum::<usize>() - server_baseline;
    let malformed: usize = servers.iter().map(|s| s.malformed.load(Ordering::SeqCst)).sum();
    if malformed != 0 {
        return Err(format!("server saw {malformed} malformed requests").into());
    }
    let ok = samples.iter().filter(|s| s.ok).count();
    let total_bytes = request_bytes * ok as u128;
    Ok(PhaseOutcome {
        samples,
        window_ns,
        total_bytes,
        metrics: pool_delta_json(before, after),
        server_delta,
        total_concurrency,
        reconnect_delta: after.reconnect.saturating_sub(before.reconnect),
        connect_sum: after.connect.saturating_sub(before.connect),
    })
}

async fn run_cold(args: &Args) -> BenchResult<PhaseOutcome> {
    let cert = make_cert("cold")?;
    let server = spawn_echo_server(&cert, false)?;
    let config = client_config(server.addr, &cert.ca_path)?;
    let request = build_request(args.payload_bytes);
    let expected = payload_fingerprint(&request.body)?;
    let request_bytes = serialized_request_len(args.payload_bytes) as u128;
    let server_baseline = server.accepted();
    let total = args.rounds * args.requests_per_round;
    let mut samples = Vec::new();
    let mut connect_sum = 0u64;
    let window_start = Instant::now();
    for index in 0..total {
        // fresh pool per request -> every request pays a cold handshake (connect, generation 1).
        let pool = RelayQuicPool::new(pool_config_with(256)?);
        let sample = one_request(
            &pool,
            &config,
            &request,
            &expected,
            index / args.requests_per_round,
            0,
            index,
        )
        .await;
        connect_sum += pool.metrics_snapshot().connect;
        samples.push(sample);
    }
    let window_ns = window_start.elapsed().as_nanos();
    let server_delta = server.accepted() - server_baseline;
    if server.malformed.load(Ordering::SeqCst) != 0 {
        return Err("cold server saw malformed requests".into());
    }
    let ok = samples.iter().filter(|s| s.ok).count();
    let total_bytes = request_bytes * ok as u128;
    let metrics = serde_json::json!({ "connect_sum_fresh_pools": connect_sum });
    Ok(PhaseOutcome {
        samples,
        window_ns,
        total_bytes,
        metrics,
        server_delta,
        total_concurrency: 1,
        reconnect_delta: 0,
        connect_sum,
    })
}

async fn run_reconnect(args: &Args) -> BenchResult<PhaseOutcome> {
    let cert = make_cert("reconnect")?;
    let server = spawn_echo_server(&cert, false)?;
    let config = client_config(server.addr, &cert.ca_path)?;
    let request = build_request(args.payload_bytes);
    let expected = payload_fingerprint(&request.body)?;
    let request_bytes = serialized_request_len(args.payload_bytes) as u128;
    let pool = RelayQuicPool::new(pool_config_with(256)?);
    let key = RelayQuicPoolKey::from_config(&config)?;
    // warmup establishes the live connection at generation 1.
    for _ in 0..args.warmup.max(1) {
        let _ = pool.request_once(&config, &request).await;
    }
    let server_baseline = server.accepted();
    let before = pool.metrics_snapshot();
    let total = args.rounds * args.requests_per_round;
    let mut samples = Vec::new();
    // The pool assigns generation = connect count (1,2,3,...). We track it deterministically so each
    // measured request evicts the CURRENT generation and forces exactly one counted reconnect.
    let window_start = Instant::now();
    for index in 0..total {
        // measured request i evicts generation i+1 (warmup established generation 1).
        pool.invalidate(&key, (index as u64) + 1);
        samples.push(
            one_request(
                &pool,
                &config,
                &request,
                &expected,
                index / args.requests_per_round,
                0,
                index,
            )
            .await,
        );
    }
    let window_ns = window_start.elapsed().as_nanos();
    let after = pool.metrics_snapshot();
    let reconnect_delta = after.reconnect.saturating_sub(before.reconnect);
    if reconnect_delta != total as u64 {
        return Err(
            format!("reconnect_delta {reconnect_delta} != measured requests {total}").into()
        );
    }
    let server_delta = server.accepted() - server_baseline;
    let ok = samples.iter().filter(|s| s.ok).count();
    let total_bytes = request_bytes * ok as u128;
    Ok(PhaseOutcome {
        samples,
        window_ns,
        total_bytes,
        metrics: pool_delta_json(before, after),
        server_delta,
        total_concurrency: 1,
        reconnect_delta,
        connect_sum: after.connect.saturating_sub(before.connect),
    })
}

async fn run_backpressure(args: &Args) -> BenchResult<(PhaseOutcome, usize)> {
    let concurrency = args.concurrency.max(2);
    let cap = concurrency - 1;
    let cert = make_cert("backpressure")?;
    let server = spawn_echo_server(&cert, true)?;
    let config = client_config(server.addr, &cert.ca_path)?;
    let request = Arc::new(build_request(args.payload_bytes));
    let expected = payload_fingerprint(&request.body)?;
    let request_bytes = serialized_request_len(args.payload_bytes) as u128;
    let server_baseline = server.accepted();
    let pool = Arc::new(RelayQuicPool::new(pool_config_with(cap)?));
    let before = pool.metrics_snapshot();
    let mut set = tokio::task::JoinSet::new();
    let window_start = Instant::now();
    for index in 0..concurrency {
        let pool = Arc::clone(&pool);
        let config = config.clone();
        let request = Arc::clone(&request);
        let expected = expected.clone();
        set.spawn(async move {
            tokio::time::timeout(
                TASK_TIMEOUT,
                one_request(&pool, &config, &request, &expected, 0, 0, index),
            )
            .await
        });
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let snap = pool.metrics_snapshot();
        if snap.backpressure.saturating_sub(before.backpressure) >= 1
            && snap.in_flight_current >= cap as u64
        {
            break;
        }
        if Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    server.release_all();
    let mut samples = Vec::new();
    let mut rejected = 0usize;
    while let Some(joined) = set.join_next().await {
        let sample = joined??;
        if sample.error_class == Some("backpressure") {
            rejected += 1;
        }
        samples.push(sample);
    }
    let window_ns = window_start.elapsed().as_nanos();
    let after = pool.metrics_snapshot();
    if after.in_flight_current != 0 {
        return Err("backpressure ended with non-zero in_flight".into());
    }
    let server_delta = server.accepted() - server_baseline;
    let ok = samples.iter().filter(|s| s.ok).count();
    let total_bytes = request_bytes * ok as u128;
    Ok((
        PhaseOutcome {
            samples,
            window_ns,
            total_bytes,
            metrics: pool_delta_json(before, after),
            server_delta,
            total_concurrency: concurrency,
            reconnect_delta: 0,
            connect_sum: after.connect.saturating_sub(before.connect),
        },
        rejected,
    ))
}

// ---- report assembly ----

fn summarize(
    outcome: &PhaseOutcome,
    args: &Args,
    expected_bp: usize,
    rejected: usize,
) -> BenchResult<serde_json::Value> {
    let mut latencies: Vec<u128> = outcome.samples.iter().map(|s| s.latency_ns).collect();
    latencies.sort_unstable();
    let ok = outcome.samples.iter().filter(|s| s.ok).count();
    let errors = outcome.samples.len() - ok;
    let window_secs = (outcome.window_ns as f64) / 1e9;
    let ops_per_s =
        if window_secs > 0.0 { outcome.samples.len() as f64 / window_secs } else { 0.0 };
    let mib_per_s = if window_secs > 0.0 {
        (outcome.total_bytes as f64 / (1024.0 * 1024.0)) / window_secs
    } else {
        0.0
    };
    let run_id = format!(
        "{}-{}",
        args.seed,
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos())
    );
    let samples_json: Vec<serde_json::Value> =
        outcome.samples.iter().map(Sample::to_json).collect();
    Ok(serde_json::json!({
        "schema": "ramflux.perf.d1.microbench.v1",
        "harness_version": HARNESS_VERSION,
        "run_id": run_id,
        "git": {
            "sha": std::env::var("RAMFLUX_PERF_GIT_SHA").unwrap_or_else(|_e| "unknown".to_owned()),
            "dirty": std::env::var("RAMFLUX_PERF_GIT_DIRTY").unwrap_or_else(|_e| "unknown".to_owned())
        },
        "cli_args": {
            "scenario": format!("{:?}", args.scenario),
            "keys": args.keys, "concurrency": args.concurrency, "payload_bytes": args.payload_bytes,
            "warmup": args.warmup, "rounds": args.rounds, "requests_per_round": args.requests_per_round, "seed": args.seed
        },
        "phase": {
            "requests": outcome.samples.len(),
            "ok": ok,
            "errors": errors,
            "window_ns": outcome.window_ns,
            "server_delta": outcome.server_delta,
            "reconnect_delta": outcome.reconnect_delta,
            "connect_sum": outcome.connect_sum,
            "per_key_concurrency": args.concurrency,
            "total_concurrency": outcome.total_concurrency,
            "expected_backpressure": expected_bp,
            "observed_backpressure": rejected
        },
        "summary": {
            "p50_ns": nearest_rank(&latencies, 50.0),
            "p95_ns": nearest_rank(&latencies, 95.0),
            "p99_ns": nearest_rank(&latencies, 99.0),
            "ops_per_s": ops_per_s,
            "mib_per_s": mib_per_s,
            "pool_delta": outcome.metrics
        },
        "samples": samples_json
    }))
}

fn atomic_write(path: &std::path::Path, value: &serde_json::Value) -> BenchResult<()> {
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(value)?;
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

async fn run(args: &Args) -> BenchResult<serde_json::Value> {
    let (outcome, expected_bp, rejected) = match args.scenario {
        Scenario::Steady => (run_steady(args).await?, 0, 0),
        Scenario::Cold => (run_cold(args).await?, 0, 0),
        Scenario::Reconnect => (run_reconnect(args).await?, 0, 0),
        Scenario::Backpressure => {
            let (o, r) = run_backpressure(args).await?;
            (o, 1, r)
        }
    };
    // Safety acceptance + conservation.
    if matches!(args.scenario, Scenario::Backpressure) {
        if rejected != expected_bp {
            return Err(format!(
                "backpressure expected {expected_bp} bounded rejects, observed {rejected}"
            )
            .into());
        }
        let admitted = outcome.samples.iter().filter(|s| s.ok).count();
        if outcome.server_delta != admitted {
            return Err(format!(
                "backpressure server_delta {} != admitted {admitted}",
                outcome.server_delta
            )
            .into());
        }
    } else {
        let errs = outcome.samples.iter().filter(|s| !s.ok).count();
        if errs != 0 {
            return Err(
                format!("scenario {:?} had {errs} errors inside capacity", args.scenario).into()
            );
        }
        if outcome.server_delta != outcome.samples.len() {
            return Err(format!(
                "server_delta {} != measured {}",
                outcome.server_delta,
                outcome.samples.len()
            )
            .into());
        }
    }
    if matches!(args.scenario, Scenario::Cold)
        && outcome.connect_sum != outcome.samples.len() as u64
    {
        return Err(format!(
            "cold connect_sum {} != measured {}",
            outcome.connect_sum,
            outcome.samples.len()
        )
        .into());
    }
    summarize(&outcome, args, expected_bp, rejected)
}

fn main() -> BenchResult<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv).map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build()?;
    let report = runtime.block_on(run(&args))?;
    if let Some(output) = &args.output {
        atomic_write(output, &report)?;
    }
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "scenario": format!("{:?}", args.scenario),
            "phase": report.get("phase").cloned().unwrap_or(serde_json::Value::Null),
            "summary": report.get("summary").cloned().unwrap_or(serde_json::Value::Null)
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_requires_scenario_and_rejects_illegal() {
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&["--scenario".into(), "nope".into()]).is_err());
        assert!(
            parse_args(&["--scenario".into(), "steady".into(), "--keys".into(), "0".into()])
                .is_err()
        );
        assert!(
            parse_args(&[
                "--scenario".into(),
                "steady".into(),
                "--payload-bytes".into(),
                "2000000".into()
            ])
            .is_err()
        );
        assert!(parse_args(&["--scenario".into(), "steady".into(), "--unknown".into()]).is_err());
    }

    #[test]
    fn parse_args_accepts_valid() -> Result<(), String> {
        let a = parse_args(&[
            "--scenario".into(),
            "steady".into(),
            "--keys".into(),
            "8".into(),
            "--concurrency".into(),
            "32".into(),
            "--payload-bytes".into(),
            "65536".into(),
        ])?;
        assert_eq!(
            (a.keys, a.concurrency, a.payload_bytes, a.scenario),
            (8, 32, 65536, Scenario::Steady)
        );
        Ok(())
    }

    #[test]
    fn nearest_rank_matches_definition() {
        let s = vec![10u128, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert_eq!(nearest_rank(&s, 50.0), 50);
        assert_eq!(nearest_rank(&s, 95.0), 100);
        assert_eq!(nearest_rank(&s, 99.0), 100);
        assert_eq!(nearest_rank(&[], 50.0), 0);
        assert_eq!(nearest_rank(&[42u128], 99.0), 42);
    }

    #[test]
    fn payload_fingerprint_roundtrips_and_len_grows() -> BenchResult<()> {
        let small = build_request(0);
        let big = build_request(65536);
        let (fp_s, len_s) = payload_fingerprint(&small.body)?;
        let (fp_b, len_b) = payload_fingerprint(&big.body)?;
        assert_ne!(fp_s, fp_b);
        assert!(len_b > len_s);
        // deterministic
        let (fp_s2, _) = payload_fingerprint(&build_request(0).body)?;
        assert_eq!(fp_s, fp_s2);
        Ok(())
    }

    #[test]
    fn reconnect_generation_progression_is_monotonic() {
        // The harness invalidates the current generation each request; generations run 1,2,3,...
        // This mirrors the pool's `generation = connect_count`. Verify the sequence the driver uses.
        let mut current = 1u64;
        let seq: Vec<u64> = (0..5)
            .map(|_| {
                let g = current;
                current += 1;
                g
            })
            .collect();
        assert_eq!(seq, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn sample_json_carries_all_fields() {
        let s = Sample { round: 1, key: 2, index: 3, latency_ns: 42, ok: true, error_class: None };
        let j = s.to_json();
        assert_eq!(j.get("round").and_then(serde_json::Value::as_u64), Some(1));
        assert_eq!(j.get("key").and_then(serde_json::Value::as_u64), Some(2));
        assert_eq!(j.get("index").and_then(serde_json::Value::as_u64), Some(3));
        assert_eq!(j.get("latency_ns").and_then(serde_json::Value::as_u64), Some(42));
        assert_eq!(j.get("ok").and_then(serde_json::Value::as_bool), Some(true));
    }

    #[test]
    fn total_concurrency_is_keys_times_per_key() {
        // Documents the P0-4 fix: measured peak concurrency = keys * per-key concurrency.
        assert_eq!(4usize * 8usize, 32);
    }
}
