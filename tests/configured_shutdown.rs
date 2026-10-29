// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn configured_shutdown_is_clean(
    binary: &str,
    service: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(service)?;
    if let Ok(mode) = std::env::var("RAMFLUX_SHUTDOWN_TEST_ONLY") {
        run_case(binary, service, &fixture, &mode)?;
        return assert_clean_reopen(&fixture.database);
    }
    run_case(binary, service, &fixture, "idle")?;
    assert_clean_reopen(&fixture.database)?;
    let modes: &[&str] =
        if matches!(service, "ramflux-router" | "ramflux-retention" | "ramflux-federation") {
            &["pooled", "handshake", "raw"]
        } else {
            &["probe"]
        };
    for mode in modes {
        run_case(binary, service, &fixture, mode)?;
        assert_clean_reopen(&fixture.database)?;
    }
    #[cfg(feature = "itest-http")]
    if matches!(service, "ramflux-router" | "ramflux-retention" | "ramflux-federation") {
        run_case(binary, service, &fixture, "request")?;
        assert_clean_reopen(&fixture.database)?;
        assert_committed_request(service, &fixture)?;
    }
    #[cfg(feature = "itest-http")]
    if service == "ramflux-router" {
        run_case(binary, service, &fixture, "churn")?;
    }
    assert_clean_reopen(&fixture.database)?;
    #[cfg(feature = "itest-http")]
    if service == "ramflux-router" {
        std::fs::remove_file(fixture.root.join("admitted"))?;
        run_case(binary, service, &fixture, "second")?;
    }
    Ok(())
}

struct Fixture {
    root: PathBuf,
    config: PathBuf,
    database: PathBuf,
    probe_addr: String,
    probe_udp: bool,
    route_key: PathBuf,
    signing_seed: PathBuf,
    voice_udp: String,
    voice_control: String,
    async_addr: String,
}

impl Fixture {
    fn new(service: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir()
            .join(format!("ramflux-{service}-shutdown-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(root.join("state"))?;
        create_tls_material(&root, service)?;
        let key = root.join("service.key");
        let cert = root.join("service.pem");
        let mesh_addr = free_tcp_addr()?;
        let gateway_addr = free_tcp_addr()?;
        let signaling_addr = free_udp_addr()?;
        let notify_addr = free_udp_addr()?;
        let voice_udp = free_udp_addr()?;
        let voice_control = free_tcp_addr()?;
        let (probe_addr, probe_udp) = match service {
            "ramflux-gateway" => (gateway_addr.clone(), false),
            "ramflux-notify" => (notify_addr.clone(), true),
            "ramflux-relay" => (voice_udp.clone(), true),
            "ramflux-signaling" => (signaling_addr.clone(), true),
            _ => (mesh_addr.clone(), false),
        };
        let database = root.join("state").join(format!("{service}.redb"));
        let config = root.join("service.toml");
        std::fs::write(
            &config,
            format!(
                r#"node_id = "localhost"
service_id = "{service}"
redb_path = "{}"
node_service_signing_seed_b64url = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio"

[mesh]
listen_addr = "{mesh_addr}"
ca_cert = "{}"
service_cert = "{}"
service_key = "{}"
allowed_service_ids = ["{service}", "ramflux-gateway", "ramflux-relay", "ramflux-router", "ramflux-retention"]

[mesh.endpoints]
gateway = "{mesh_addr}"
router = "{mesh_addr}"
notify = "{mesh_addr}"
federation = "{mesh_addr}"
relay = "{mesh_addr}"
signaling = "{mesh_addr}"
retention = "{mesh_addr}"

[gateway]
public_listen_addr = "{gateway_addr}"

[signaling]
turn_udp_addr = "{signaling_addr}"
turn_tcp_addr = "127.0.0.1:0"
"#,
                database.display(),
                root.join("ca.pem").display(),
                cert.display(),
                key.display(),
            ),
        )?;
        let route_key = root.join("notify-route.key");
        std::fs::write(&route_key, b"ERERERERERERERERERERERERERERERERERERERERERE")?;
        let signing_seed = root.join("node-signing.key");
        std::fs::write(&signing_seed, b"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&route_key, std::fs::Permissions::from_mode(0o600))?;
            std::fs::set_permissions(&signing_seed, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            root,
            config,
            database,
            probe_addr,
            probe_udp,
            route_key,
            signing_seed,
            voice_udp,
            voice_control,
            async_addr: free_udp_addr()?,
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn run_case(
    binary: &str,
    service: &str,
    fixture: &Fixture,
    mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "itest-http")]
    if service == "ramflux-federation" && mode == "request" {
        seed_federation_sweep(fixture)?;
    }
    let mut child = ChildGuard(configured_command(binary, service, fixture, mode)?.spawn()?);
    let stdout = child.0.stdout.take().ok_or("missing stdout")?;
    let (log_sender, log_receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut logs = String::new();
        for line in std::io::BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    logs.push_str(&line);
                    logs.push('\n');
                    let _ = log_sender.send(line);
                }
                Err(_) => break,
            }
        }
        logs
    });
    if let Err(error) = wait_for_ready(&log_receiver, service, Duration::from_secs(10)) {
        let _ = child.0.kill();
        let _ = child.0.wait();
        let mut logs = reader.join().map_err(|_| "stdout reader panicked")?;
        if let Some(mut stderr) = child.0.stderr.take() {
            stderr.read_to_string(&mut logs)?;
        }
        return Err(format!("{service} startup failed ({error}): {logs}").into());
    }
    let probe = if mode == "probe" {
        Some(start_request_probe(&fixture.probe_addr, fixture.probe_udp)?)
    } else {
        None
    };
    let mut peer =
        if matches!(mode, "pooled" | "handshake" | "raw" | "request" | "churn" | "second") {
            Some(start_mesh_peer(
                fixture,
                service,
                if mode == "second" { "request" } else { mode },
                child.0.id(),
            )?)
        } else {
            None
        };
    if matches!(mode, "request" | "second") {
        wait_for_file(&fixture.root.join("admitted"))?;
    }
    let (status, elapsed) = signal_and_wait(&mut child.0, service, mode)?;
    if let Some(peer) = peer.as_mut()
        && mode == "request"
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = peer.0.try_wait()? {
                assert!(status.success(), "request peer failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                return Err("request peer exceeded timeout".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if let Some(probe) = probe {
        probe.join().map_err(|_| "request probe panicked")??;
    }
    let mut logs = reader.join().map_err(|_| "stdout reader panicked")?;
    if let Some(mut stderr) = child.0.stderr.take() {
        stderr.read_to_string(&mut logs)?;
    }
    if mode == "second" {
        assert_eq!(status.code(), Some(1), "{logs}");
        assert!(elapsed < Duration::from_secs(1), "second signal did not force exit");
        assert_eq!(logs.matches("shutdown interrupted by second signal").count(), 1, "{logs}");
        assert!(!logs.contains("graceful shutdown complete"), "{logs}");
        return Ok(());
    }
    if !status.success() {
        return Err(format!("{service} exited with {status}: {logs}").into());
    }
    if logs.matches("graceful shutdown complete").count() != 1 {
        return Err(format!("missing unique shutdown completion for {service}: {logs}").into());
    }
    Ok(())
}

fn wait_for_ready(
    receiver: &mpsc::Receiver<String>,
    service: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let marker = match service {
        "ramflux-gateway" => "gateway QUIC session surface listening",
        "ramflux-router" => "router mesh mTLS surface listening",
        "ramflux-notify" => "notify mesh QUIC surface listening",
        "ramflux-federation" => "federation production admin HTTP surface listening",
        "ramflux-relay" => "relay voice surfaces listening",
        "ramflux-signaling" => "signaling itest STUN/TURN UDP surface listening",
        "ramflux-retention" => "retention mesh mTLS surface listening",
        _ => return Err(format!("unknown shutdown-test service {service}").into()),
    };
    let extra: &[&str] = match service {
        "ramflux-router" => &["router async QUIC ingress listening"],
        "ramflux-retention" => &["retention async QUIC ingress listening"],
        "ramflux-federation" => {
            &["federation mesh mTLS surface listening", "federation mesh QUIC surface listening"]
        }
        _ => &[],
    };
    let mut pending = vec![marker];
    pending.extend_from_slice(extra);
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("service startup exceeded test timeout".into());
        }
        let line = receiver.recv_timeout(remaining)?;
        pending.retain(|marker| !line.contains(marker));
        if pending.is_empty() {
            return Ok(());
        }
    }
}

fn start_request_probe(
    addr: &str,
    udp: bool,
) -> Result<std::thread::JoinHandle<Result<(), std::io::Error>>, std::io::Error> {
    if udp {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(addr)?;
        return Ok(std::thread::spawn(move || {
            let _ = socket.send(b"shutdown-race")?;
            Ok(())
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut stream = loop {
        match TcpStream::connect(addr) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    };
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    Ok(std::thread::spawn(move || {
        stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")?;
        Ok(())
    }))
}

fn assert_clean_reopen(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let repaired = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&repaired);
    let mut builder = redb::Builder::new();
    builder.set_repair_callback(move |_| {
        observed.store(true, Ordering::SeqCst);
    });
    let database = builder.open(path)?;
    drop(database);
    if repaired.load(Ordering::SeqCst) {
        return Err(format!("{} required redb repair after shutdown", path.display()).into());
    }
    Ok(())
}

fn free_tcp_addr() -> Result<String, std::io::Error> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.to_string())
}

fn free_udp_addr() -> Result<String, std::io::Error> {
    Ok(UdpSocket::bind("127.0.0.1:0")?.local_addr()?.to_string())
}

fn openssl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("openssl").args(args).output()?;
    if !output.status.success() {
        return Err(format!("openssl failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(())
}

fn issue_certificate(
    root: &Path,
    name: &str,
    service: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = root.join(format!("{name}.key"));
    let csr = root.join(format!("{name}.csr"));
    let cert = root.join(format!("{name}.pem"));
    let extensions = root.join(format!("{name}.ext"));
    std::fs::write(
        &extensions,
        format!(
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,URI:spiffe://localhost/{service}\n"
        ),
    )?;
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-keyout",
        key.to_str().ok_or("key path")?,
        "-out",
        csr.to_str().ok_or("csr path")?,
    ])?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        csr.to_str().ok_or("csr path")?,
        "-CA",
        root.join("ca.pem").to_str().ok_or("CA path")?,
        "-CAkey",
        root.join("ca.key").to_str().ok_or("CA key path")?,
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        extensions.to_str().ok_or("extension path")?,
        "-out",
        cert.to_str().ok_or("cert path")?,
    ])
}

fn start_mesh_peer(
    fixture: &Fixture,
    service: &str,
    mode: &str,
    pid: u32,
) -> Result<ChildGuard, Box<dyn std::error::Error>> {
    let mut child = ChildGuard(
        Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/shutdown_peer.py"))
            .args([
                fixture.root.to_str().ok_or("fixture path")?,
                &fixture.probe_addr,
                mode,
                service,
                &pid.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    if mode != "request" {
        let stdout = child.0.stdout.take().ok_or("peer stdout")?;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(std::io::BufReader::new(stdout).lines().next());
        });
        let line =
            receiver.recv_timeout(Duration::from_secs(if mode == "churn" { 300 } else { 10 }))?;
        assert!(
            line.transpose()?
                .is_some_and(|line| matches!(line.as_str(), "peer-ready" | "churn-complete")),
            "mesh peer failed before ready"
        );
    }
    Ok(child)
}

fn wait_for_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err("request did not reach test rendezvous".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn assert_committed_request(
    service: &str,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let response: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.root.join("response.json"))?)?;
    let committed = response["status"] == 200;
    match service {
        "ramflux-router" => {
            let store = ramflux_node_core::RouterRedbStore::open(&fixture.database)?;
            let router = store.load_router()?.ok_or("missing router state")?;
            let session = router.session("shutdown-target");
            assert_eq!(session.is_some(), committed);
            if let Some(session) = session {
                assert_eq!(session.session_id, "shutdown-session");
                assert_eq!(session.device_id, "shutdown-device");
                assert_eq!(session.gateway_id, "shutdown-gateway");
                assert_eq!(session.device_epoch, 1);
                assert_eq!(session.session_seq, 1);
            }
        }
        "ramflux-retention" => {
            let store = ramflux_node_core::RetentionRedbStore::open(&fixture.database)?;
            let state = store.load_state()?.unwrap_or_default();
            let record = state.metadata_record("shutdown-record");
            assert_eq!(record.is_some(), committed);
            if let Some(record) = record {
                assert_eq!(record.subject_hash, "shutdown-subject");
                assert_eq!(record.metadata_hash, "shutdown-hash");
                assert_eq!(record.expires_at, 4_102_444_800);
                assert!(!record.legal_hold);
            }
        }
        "ramflux-federation" => {
            let store = ramflux_node_core::FederationRedbStore::open(&fixture.database)?;
            assert_eq!(
                store.list_pending_for_peer("shutdown-peer", 10)?.len(),
                if committed { 0 } else { 2 }
            );
            if committed {
                let body: serde_json::Value =
                    serde_json::from_str(response["body"].as_str().ok_or("response body")?)?;
                assert_eq!(body["deleted_count"], 2);
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn seed_federation_sweep(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let store = ramflux_node_core::FederationRedbStore::open(&fixture.database)?;
    for index in 0..2 {
        let forward = serde_json::from_value(serde_json::json!({
            "source_node_id": "localhost", "target_node_id": "shutdown-peer",
            "signing_key_id": "fixture", "signature_alg": "ed25519", "signature": "fixture",
            "delivery_class": "opaque_event", "required_capability": "opaque_delivery",
            "envelope": {
                "schema": "ramflux.envelope.v1", "version": 1, "domain": "ramflux.envelope.v1",
                "signing_key_id": "fixture", "signature_alg": "ed25519", "signature": "fixture",
                "envelope_id": format!("shutdown-envelope-{index}"),
                "source_principal_id": "shutdown-source", "source_device_id": "shutdown-device",
                "target_delivery_id": "shutdown-target", "routing_set_id": null,
                "delivery_class": "opaque_event", "priority": "normal", "ttl": 1,
                "created_at": 100, "encrypted_payload": "ciphertext", "payload_hash": "fixture"
            }
        }))?;
        store.spool_outbound_forward("shutdown-peer", &forward, 100, 1)?;
    }
    assert_eq!(store.list_pending_for_peer("shutdown-peer", 10)?.len(), 2);
    Ok(())
}

fn create_tls_material(root: &Path, service: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = root.join("service.key");
    let cert = root.join("service.pem");
    std::fs::write(
        root.join("ca.cnf"),
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=ShutdownTestCA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",
    )?;
    openssl(&[
        "req",
        "-x509",
        "-config",
        root.join("ca.cnf").to_str().ok_or("CA config path")?,
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=ShutdownTestCA",
        "-days",
        "1",
        "-keyout",
        key.to_str().ok_or("non-UTF-8 key path")?,
        "-out",
        cert.to_str().ok_or("non-UTF-8 certificate path")?,
    ])?;
    std::fs::rename(&cert, root.join("ca.pem"))?;
    std::fs::rename(&key, root.join("ca.key"))?;
    issue_certificate(root, "service", service)?;
    let peer_id = if service == "ramflux-retention" {
        "ramflux-relay"
    } else if service == "ramflux-federation" {
        "ramflux-retention"
    } else {
        "ramflux-gateway"
    };
    issue_certificate(root, "peer", peer_id)?;
    Ok(())
}

fn configured_command(
    binary: &str,
    service: &str,
    fixture: &Fixture,
    mode: &str,
) -> Result<Command, Box<dyn std::error::Error>> {
    let mut child = Command::new(binary);
    child
        .args(["--config", fixture.config.to_str().ok_or("non-UTF-8 config path")?])
        .env("RAMFLUX_SHUTDOWN_GRACE_SECONDS", "3")
        .env("RAMFLUX_NODE_STATE_DIR", fixture.root.join("state"))
        .env("RAMFLUX_NOTIFY_ROUTE_KEY_FILE", &fixture.route_key)
        .env("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE", &fixture.signing_seed)
        .env("RAMFLUX_ROUTER_ASYNC_INGRESS", "1")
        .env("RAMFLUX_ROUTER_ASYNC_LISTEN_ADDR", &fixture.async_addr)
        .env("RAMFLUX_NOTIFY_MESH_LISTEN_ADDR", &fixture.probe_addr)
        .env("RAMFLUX_RETENTION_ASYNC_LISTEN_ADDR", &fixture.async_addr)
        .env("RAMFLUX_FEDERATION_SPOOL_RETRY_INTERVAL_SECS", "3600")
        .env("RAMFLUX_FEDERATION_PUBLIC_ADDR", "127.0.0.1:0")
        .env("RAMFLUX_FEDERATION_ADMIN_ADDR", "127.0.0.1:0")
        .env("RAMFLUX_RELAY_VOICE_UDP_ADDR", &fixture.voice_udp)
        .env("RAMFLUX_RELAY_VOICE_CONTROL_ADDR", &fixture.voice_control)
        .env("RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT", &fixture.voice_udp)
        .env_remove("RAMFLUX_RELAY_CLIENT_QUIC_ADDR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if service == "ramflux-gateway" {
        child.env(
            "RAMFLUX_RELAY_SERVICE_KEY_REF",
            "literal:shutdown-test-relay-service-key-material",
        );
    }
    if matches!(mode, "request" | "second") {
        child.env("RAMFLUX_ITEST_SHUTDOWN_REQUEST_MARKER", fixture.root.join("admitted"));
    }
    Ok(child)
}

fn signal_and_wait(
    child: &mut Child,
    service: &str,
    mode: &str,
) -> Result<(std::process::ExitStatus, Duration), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let sent = Command::new("kill").args(["-TERM", &child.id().to_string()]).status()?;
    if !sent.success() {
        return Err(format!("kill failed for {service}: {sent}").into());
    }
    if mode == "second" {
        std::thread::sleep(Duration::from_millis(30));
        let second = Command::new("kill").args(["-INT", &child.id().to_string()]).status()?;
        assert!(second.success());
    }
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(4) {
            return Err(format!("{service} exceeded shutdown bound").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Ok((status, started.elapsed()))
}
