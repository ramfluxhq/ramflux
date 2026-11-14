// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{
    MeshQuicAdmissionLimits, MeshQuicHandshakeDriver, MeshQuicHandshakeMetrics,
    MeshQuicReadyConnection, MeshTlsConfig,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) struct Certificates {
    root: PathBuf,
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    pub(crate) server: MeshTlsConfig,
}
impl Certificates {
    pub(crate) fn new() -> TestResult<Self> {
        crate::tls_config::ensure_ring_crypto_provider_installed();
        let root = std::env::temp_dir().join(format!(
            "quic_admission_{}_{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        std::fs::create_dir_all(&root)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate()?)?;
        std::fs::write(root.join("ca.pem"), ca.pem())?;
        let mut result = Self {
            server: MeshTlsConfig {
                ca_cert: root.join("ca.pem"),
                service_cert: PathBuf::new(),
                service_key: PathBuf::new(),
            },
            root,
            ca,
        };
        result.server = result.peer("server", Some("spiffe://test/server"))?;
        Ok(result)
    }
    fn peer(&self, name: &str, uri: Option<&str>) -> TestResult<MeshTlsConfig> {
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
        if let Some(uri) = uri {
            params.subject_alt_names.push(rcgen::SanType::URI(uri.try_into()?));
        }
        if name == "stalled" {
            for index in 0..512 {
                params.subject_alt_names.push(rcgen::SanType::DnsName(
                    format!("stall-{index}.example.test").try_into()?,
                ));
            }
        }
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params.signed_by(&key, &self.ca)?;
        let service_cert = self.root.join(format!("{name}.pem"));
        let service_key = self.root.join(format!("{name}.key"));
        std::fs::write(&service_cert, cert.pem())?;
        std::fs::write(&service_key, key.serialize_pem())?;
        Ok(MeshTlsConfig { ca_cert: self.root.join("ca.pem"), service_cert, service_key })
    }
    pub(crate) fn roots(&self) -> crate::tls_config::MeshRootPemProvider {
        let pem = self.ca.pem();
        Arc::new(move || Ok(vec![pem.clone()]))
    }
    fn client(&self, name: &str, uri: Option<&str>, source: &str) -> TestResult<quinn::Endpoint> {
        let tls = self.peer(name, uri)?;
        let config =
            crate::tls_config::mesh_quic_client_config_with_pem_roots(&tls, &[self.ca.pem()])?;
        let mut endpoint = quinn::Endpoint::client(source.parse()?)?;
        endpoint.set_default_client_config(config);
        Ok(endpoint)
    }
}
impl Drop for Certificates {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Harness {
    addr: SocketAddr,
    metrics: MeshQuicHandshakeMetrics,
    ready: mpsc::Receiver<MeshQuicReadyConnection>,
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}
impl Harness {
    fn new(certs: &Certificates, limits: MeshQuicAdmissionLimits) -> TestResult<Self> {
        let (driver, ready) = MeshQuicHandshakeDriver::bind(
            "127.0.0.1:0".parse()?,
            &certs.server,
            certs.roots(),
            vec!["spiffe://test/client".into()],
            limits,
        )?;
        let addr = driver.local_addr()?;
        let metrics = driver.metrics();
        let (cancel, receiver) = watch::channel(false);
        Ok(Self { addr, metrics, ready, cancel, task: tokio::spawn(driver.run(receiver)) })
    }
    async fn stop(mut self) -> TestResult {
        self.cancel.send(true)?;
        tokio::time::timeout(Duration::from_secs(8), &mut self.task).await??;
        while let Ok(ready) = self.ready.try_recv() {
            assert!(ready.into_connection().is_err());
        }
        let snapshot = self.metrics.snapshot();
        assert_eq!(
            snapshot.handshaking
                + snapshot.ready
                + snapshot.reservations
                + snapshot.sources
                + snapshot.protocol_entries,
            0
        );
        Ok(())
    }
}

async fn until(mut condition: impl FnMut() -> bool) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

// A real client completes Retry and sends its validated Initial; all later
// client flights are held, keeping real server TLS incomplete. The proxy task
// and the client's Connecting future are always retained for cancellation/join.
struct Stalled {
    endpoint: quinn::Endpoint,
    proxy: JoinHandle<()>,
    client: JoinHandle<()>,
    release: watch::Sender<bool>,
    progress: Arc<std::sync::atomic::AtomicUsize>,
}
impl Stalled {
    async fn new(certs: &Certificates, server: SocketAddr) -> TestResult<Self> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let proxy_addr = socket.local_addr()?;
        let (release, mut released) = watch::channel(false);
        let progress = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let forwarded = progress.clone();
        let proxy = tokio::spawn(async move {
            let mut pending: std::collections::VecDeque<Vec<u8>> =
                std::collections::VecDeque::new();
            let mut pace = tokio::time::interval(Duration::from_millis(80));
            let mut peer = None;
            let mut flights = 0;
            let mut packet = vec![0_u8; 65535].into_boxed_slice();
            loop {
                tokio::select! {
                    _ = released.changed() => {},
                    _ = pace.tick(), if forwarded.load(std::sync::atomic::Ordering::Relaxed) < 2 => {
                        if let Some(packet) = pending.pop_front() {
                            let _ = socket.send_to(&packet, server).await;
                            forwarded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    },
                    received = socket.recv_from(&mut packet) => {
                        let Ok((length, from)) = received else { break; };
                        if from == server {
                            if let Some(peer) = peer { let _ = socket.send_to(&packet[..length], peer).await; }
                        } else {
                            peer = Some(from); flights += 1;
                            if flights <= 2 || *released.borrow() { let _ = socket.send_to(&packet[..length], server).await; }
                            else if pending.len() < 2 { pending.push_back(packet[..length].to_vec()); }
                        }
                    }
                }
            }
        });
        let endpoint = certs.client("stalled", Some("spiffe://test/client"), "127.0.0.1:0")?;
        let connecting = endpoint.connect(proxy_addr, "localhost")?;
        let client = tokio::spawn(async move {
            let _ = connecting.await;
        });
        Ok(Self { endpoint, proxy, client, release, progress })
    }
    async fn stop(self) {
        self.endpoint.close(0_u32.into(), b"test done");
        self.client.abort();
        let _ = self.client.await;
        self.proxy.abort();
        let _ = self.proxy.await;
    }
}

#[tokio::test]
async fn stalled_handshake_does_not_block_second_peer() -> TestResult {
    let certs = Certificates::new()?;
    let mut harness = Harness::new(&certs, MeshQuicAdmissionLimits::default())?;
    let stalled = Stalled::new(&certs, harness.addr).await?;
    until(|| harness.metrics.snapshot().handshaking == 1).await?;
    let endpoint = certs.client("healthy", Some("spiffe://test/client"), "127.0.0.2:0")?;
    let outcome =
        tokio::time::timeout(Duration::from_secs(2), endpoint.connect(harness.addr, "localhost")?)
            .await;
    assert!(outcome.is_ok(), "healthy peer blocked behind stalled TLS");
    let connection = outcome??;
    let ready = tokio::time::timeout(Duration::from_secs(2), harness.ready.recv())
        .await?
        .ok_or("missing healthy result")?;
    let accepted = ready.into_connection()?;
    assert_eq!(accepted.peer_spiffe_uri(), Some("spiffe://test/client"));
    assert_eq!(harness.metrics.snapshot().handshaking, 1);
    assert!(!*stalled.release.borrow(), "healthy TLS must precede stall release");
    connection.close(0_u32.into(), b"done");
    stalled.stop().await;
    harness.stop().await
}

#[tokio::test]
async fn handshake_caps_refuse_overflow() -> TestResult {
    assert_eq!(
        crate::mesh_quic_admission::normalized("::ffff:127.0.0.1".parse()?),
        "127.0.0.1".parse::<std::net::IpAddr>()?
    );
    let certs = Certificates::new()?;
    incoming_saturation(&certs).await?;
    phase_cap(&certs).await?;
    // Global protocol cap includes transferred established connections and
    // closing entries even though their application reservations are gone.
    let limits = MeshQuicAdmissionLimits {
        protocol_entries: 1,
        idle_timeout: Duration::from_millis(40),
        ..Default::default()
    };
    let mut harness = Harness::new(&certs, limits)?;
    let first = certs.client("first", Some("spiffe://test/client"), "127.0.0.2:0")?;
    let connection = first.connect(harness.addr, "localhost")?.await?;
    let accepted = harness.ready.recv().await.ok_or("missing ready")?.into_connection()?;
    assert_eq!(harness.metrics.snapshot().reservations, 0);
    for source in ["127.0.0.3:0", "127.0.0.4:0", "127.0.0.5:0"] {
        let peer = certs.client(source, Some("spiffe://test/client"), source)?;
        assert!(peer.connect(harness.addr, "localhost")?.await.is_err());
        assert!(harness.metrics.snapshot().protocol_entries <= 1);
    }
    assert!(harness.metrics.snapshot().listener_cap >= 3);
    connection.close(0_u32.into(), b"close");
    drop(accepted);
    tokio::time::sleep(Duration::from_millis(80)).await;
    let recovery = certs.client("recovery", Some("spiffe://test/client"), "127.0.0.6:0")?;
    // Retry until actual protocol retirement, independently of the short fairness hold.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(connecting) = recovery.connect(harness.addr, "localhost")
                && let Ok(connection) = connecting.await
            {
                connection.close(0_u32.into(), b"done");
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    harness.stop().await?;
    let limits = MeshQuicAdmissionLimits {
        per_source: 1,
        ready: 1,
        ready_per_source: 1,
        ..Default::default()
    };
    let harness = Harness::new(&certs, limits)?;
    let stalled = Stalled::new(&certs, harness.addr).await?;
    until(|| harness.metrics.snapshot().handshaking == 1).await?;
    let same = certs.client("same", Some("spiffe://test/client"), "127.0.0.1:0")?;
    assert!(same.connect(harness.addr, "localhost")?.await.is_err());
    assert!(harness.metrics.snapshot().source_cap > 0);
    let mut peers = Vec::new();
    for source in ["127.0.0.2:0", "127.0.0.3:0", "127.0.0.4:0"] {
        let endpoint = certs.client(source, Some("spiffe://test/client"), source)?;
        let connection = endpoint.connect(harness.addr, "localhost")?.await?;
        peers.push((endpoint, connection));
    }
    until(|| harness.metrics.snapshot().ready_cap >= 2).await?;
    assert_eq!(harness.metrics.snapshot().ready, 1);
    assert!(harness.metrics.snapshot().sources <= 4);
    stalled.stop().await;
    harness.stop().await
}

#[tokio::test]
async fn handshake_timeout_closes_and_releases_slot() -> TestResult {
    let certs = Certificates::new()?;
    let limits = MeshQuicAdmissionLimits {
        deadline: Duration::from_millis(600),
        // Keep the transport idle timeout later than the application deadline.
        idle_timeout: Duration::from_secs(1),
        ..Default::default()
    };
    let harness = Harness::new(&certs, limits)?;
    let stalled = Stalled::new(&certs, harness.addr).await?;
    until(|| harness.metrics.snapshot().handshaking == 1).await?;
    until(|| harness.metrics.snapshot().timeout == 1).await.map_err(|error| {
        format!("deadline did not fire: {:?}: {error}", harness.metrics.snapshot())
    })?;
    assert_eq!(
        stalled.progress.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "real client TLS flights must progress before the fixed deadline"
    );
    assert_eq!(harness.metrics.snapshot().handshaking, 0);
    assert_eq!(harness.metrics.snapshot().ready, 0);
    until(|| harness.metrics.snapshot().reservations == 0).await.map_err(|error| {
        format!("fairness reservation did not expire: {:?}: {error}", harness.metrics.snapshot())
    })?;
    stalled.stop().await;
    harness.stop().await
}

#[tokio::test]
async fn shutdown_cancels_and_drains_handshakes() -> TestResult {
    let certs = Certificates::new()?;
    let harness = Harness::new(&certs, MeshQuicAdmissionLimits::default())?;
    let stalled = Stalled::new(&certs, harness.addr).await?;
    until(|| harness.metrics.snapshot().handshaking == 1).await?;
    let healthy = certs.client("racing", Some("spiffe://test/client"), "127.0.0.2:0")?;
    let connection = healthy.connect(harness.addr, "localhost")?.await?;
    until(|| harness.metrics.snapshot().ready == 1).await?;
    harness.stop().await?;
    assert!(connection.close_reason().is_some());
    stalled.stop().await;
    Ok(())
}

#[tokio::test]
async fn untrusted_or_missing_mesh_identity_never_dispatches() -> TestResult {
    let certs = Certificates::new()?;
    let mut harness = Harness::new(&certs, MeshQuicAdmissionLimits::default())?;
    for (name, uri) in [("absent", None), ("disallowed", Some("spiffe://test/other"))] {
        let endpoint = certs.client(name, uri, "127.0.0.1:0")?;
        if let Ok(connection) = endpoint.connect(harness.addr, "localhost")?.await {
            let _ = connection.closed().await;
        }
    }
    let other = Certificates::new()?;
    let untrusted_tls = other.peer("untrusted", Some("spiffe://test/client"))?;
    let untrusted_config = crate::tls_config::mesh_quic_client_config_with_pem_roots(
        &untrusted_tls,
        &[certs.ca.pem()],
    )?;
    let mut untrusted = quinn::Endpoint::client("127.0.0.2:0".parse()?)?;
    untrusted.set_default_client_config(untrusted_config);
    // The client can observe TLS completion before the server's certificate
    // rejection reaches it; the admission oracle is server-side non-dispatch.
    if let Ok(connection) = untrusted.connect(harness.addr, "localhost")?.await {
        let _ = connection.closed().await;
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs.ca.der().clone())?;
    let tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let config =
        quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
    let mut missing = quinn::Endpoint::client("127.0.0.3:0".parse()?)?;
    missing.set_default_client_config(config);
    if let Ok(connection) = missing.connect(harness.addr, "localhost")?.await {
        let _ = connection.closed().await;
    }
    until(|| harness.metrics.snapshot().peer_error >= 4).await?;
    assert!(harness.ready.try_recv().is_err());
    harness.stop().await
}

#[cfg(target_os = "linux")]
fn rss_bytes() -> TestResult<u64> {
    use std::io::Read as _;
    const MAX_STATUS_BYTES: u64 = 64 * 1024;
    let mut status = String::new();
    std::fs::File::open("/proc/self/status")?
        .take(MAX_STATUS_BYTES + 1)
        .read_to_string(&mut status)?;
    if u64::try_from(status.len())? > MAX_STATUS_BYTES {
        return Err("test: process status exceeded its fixed read bound".into());
    }
    let line = status.lines().find(|line| line.starts_with("VmRSS:")).ok_or("missing RSS")?;
    Ok(line.split_whitespace().nth(1).ok_or("missing RSS value")?.parse::<u64>()? * 1024)
}

/// Fixed-rate duplicate QUIC packets exercise the raw event path without using
/// stream receive credit. This finite RSS observation is not a queue bound.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn stalled_application_keeps_endpoint_progress_and_memory_stable() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    const CHILD_MARKER: &str = "RAMFLUX_TRANSPORT_RSS_OBSERVATION_CHILD";
    const TEST_NAME: &str =
        "mesh_quic_handshake_tests::stalled_application_keeps_endpoint_progress_and_memory_stable";
    const CHILD_DEADLINE: Duration = Duration::from_secs(30);
    if std::env::var_os(CHILD_MARKER).is_none() {
        // RSS covers the entire process. Other concurrently running TLS tests must not
        // contribute allocations to this transport observation.
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_MARKER, "1")
            .env("RUST_TEST_THREADS", "1")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let status = tokio::time::timeout(CHILD_DEADLINE, child.wait()).await??;
        assert!(status.success(), "isolated transport RSS observation failed: {status}");
        return Ok(());
    }
    let certs = Certificates::new()?;
    let harness = Harness::new(&certs, MeshQuicAdmissionLimits::default())?;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let server = harness.addr;
    let replayed = Arc::new(AtomicUsize::new(0));
    let counter = replayed.clone();
    let proxy = tokio::spawn(async move {
        let mut packet = vec![0_u8; 65535].into_boxed_slice();
        let mut last = Vec::new();
        let mut peer = None;
        let mut pace = tokio::time::interval(Duration::from_millis(10));
        pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = pace.tick(), if !last.is_empty() => {
                    if socket.send_to(&last, server).await.is_ok() { counter.fetch_add(1, Ordering::Relaxed); }
                }
                received = socket.recv_from(&mut packet) => {
                    let Ok((length, from)) = received else { break; };
                    if from == server {
                        if let Some(peer) = peer { let _ = socket.send_to(&packet[..length], peer).await; }
                    } else {
                        peer = Some(from);
                        last.clear(); last.extend_from_slice(&packet[..length]);
                        let _ = socket.send_to(&packet[..length], server).await;
                    }
                }
            }
        }
    });
    let endpoint =
        certs.client("application-stall", Some("spiffe://test/client"), "127.0.0.1:0")?;
    let connection = endpoint.connect(addr, "localhost")?.await?;
    let (mut send, _recv) = connection.open_bi().await?;
    send.write_all(&[1_u8; 1024]).await?;
    until(|| replayed.load(Ordering::Relaxed) >= 50).await?;
    let before = rss_bytes()?;
    let healthy = certs.client("memory-healthy", Some("spiffe://test/client"), "127.0.0.2:0")?;
    let second =
        tokio::time::timeout(Duration::from_secs(2), healthy.connect(server, "localhost")?)
            .await??;
    until(|| replayed.load(Ordering::Relaxed) >= 200).await?;
    let after = rss_bytes()?;
    assert!(harness.metrics.snapshot().ready >= 2);
    assert!(after.saturating_sub(before) <= 8 * 1024 * 1024, "RSS grew from {before} to {after}");
    eprintln!(
        "fixed-rate replay: 100 packets/s, {} packets; RSS {before} -> {after} bytes (finite observation)",
        replayed.load(Ordering::Relaxed)
    );
    second.close(0_u32.into(), b"done");
    connection.close(0_u32.into(), b"done");
    proxy.abort();
    let _ = proxy.await;
    harness.stop().await
}

async fn incoming_saturation(certs: &Certificates) -> TestResult {
    let (driver, _ready) = MeshQuicHandshakeDriver::bind(
        "127.0.0.1:0".parse()?,
        &certs.server,
        certs.roots(),
        vec![],
        MeshQuicAdmissionLimits::default(),
    )?;
    let endpoint =
        certs.client("incoming-saturation", Some("spiffe://test/client"), "127.0.0.1:0")?;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..65 {
        let connecting = endpoint.connect(driver.local_addr()?, "localhost")?;
        tasks.spawn(async move {
            let _ = connecting.await;
        });
    }
    let mut pending = Vec::new();
    for _ in 0..64 {
        pending.push(
            tokio::time::timeout(Duration::from_secs(2), driver.test_endpoint().accept())
                .await?
                .ok_or("closed incoming endpoint")?,
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), driver.test_endpoint().accept())
            .await
            .is_err()
    );
    assert_eq!(driver.test_endpoint().open_connections(), 0);
    for incoming in pending {
        incoming.refuse();
    }
    endpoint.close(0_u32.into(), b"done");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    driver.test_endpoint().close(0_u32.into(), b"done");
    driver.test_endpoint().wait_idle().await;
    Ok(())
}

async fn phase_cap(certs: &Certificates) -> TestResult {
    let harness =
        Harness::new(certs, MeshQuicAdmissionLimits { handshakes: 1, ..Default::default() })?;
    let stalled = Stalled::new(certs, harness.addr).await?;
    until(|| harness.metrics.snapshot().handshaking == 1).await?;
    let peer = certs.client("phase-overflow", Some("spiffe://test/client"), "127.0.0.2:0")?;
    assert!(peer.connect(harness.addr, "localhost")?.await.is_err());
    assert!(harness.metrics.snapshot().listener_cap > 0);
    assert_eq!(harness.metrics.snapshot().reservations, 1);
    stalled.stop().await;
    harness.stop().await
}
