// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type RegistrationSeed = fn(&Path) -> Result<(), Box<dyn std::error::Error>>;
type ShutdownProbe = std::thread::JoinHandle<Result<(), std::io::Error>>;
pub type GatewayTlsProbe =
    fn(&str, &Path, Arc<AtomicBool>, Arc<AtomicBool>) -> Result<ShutdownProbe, std::io::Error>;

#[allow(dead_code)] // Shared by several integration-test binaries.
pub fn configured_shutdown_is_clean(
    binary: &str,
    service: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    configured_shutdown_with_registration(binary, service, None)
}

#[allow(dead_code)] // The router supplies a real registration; other services use the wrapper.
pub fn configured_shutdown_with_registration(
    binary: &str,
    service: &str,
    registration_seed: Option<RegistrationSeed>,
) -> Result<(), Box<dyn std::error::Error>> {
    configured_shutdown_with_probes(binary, service, registration_seed, None)
}

#[allow(dead_code)]
pub fn configured_gateway_shutdown_is_clean(
    binary: &str,
    service: &str,
    gateway_tls_probe: GatewayTlsProbe,
) -> Result<(), Box<dyn std::error::Error>> {
    configured_shutdown_with_probes(binary, service, None, Some(gateway_tls_probe))
}

fn configured_shutdown_with_probes(
    binary: &str,
    service: &str,
    registration_seed: Option<RegistrationSeed>,
    gateway_tls_probe: Option<GatewayTlsProbe>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(service)?;
    fixture.registration_seed = registration_seed;
    fixture.gateway_tls_probe = gateway_tls_probe;
    if let Ok(mode) = std::env::var("RAMFLUX_SHUTDOWN_TEST_ONLY") {
        run_case(binary, service, &fixture, &mode)?;
        #[cfg(feature = "itest-http")]
        if mode == "request" {
            assert_committed_request(service, &fixture)?;
        }
        return assert_clean_reopen(&fixture.database);
    }
    run_case(binary, service, &fixture, "idle")?;
    assert_clean_reopen(&fixture.database)?;
    let modes: &[&str] =
        if matches!(service, "ramflux-router" | "ramflux-retention" | "ramflux-federation") {
            &["pooled", "handshake", "raw", "probe"]
        } else {
            &["probe"]
        };
    for mode in modes {
        run_case(binary, service, &fixture, mode)?;
        assert_clean_reopen(&fixture.database)?;
    }
    #[cfg(feature = "itest-http")]
    if matches!(service, "ramflux-router" | "ramflux-retention" | "ramflux-federation") {
        for stage in ["clone", "spawn"] {
            run_case(binary, service, &fixture, &format!("failure-{stage}"))?;
            assert_clean_reopen(&fixture.database)?;
        }
        run_case(binary, service, &fixture, "request")?;
        assert_clean_reopen(&fixture.database)?;
        assert_committed_request(service, &fixture)?;
    }
    #[cfg(feature = "itest-http")]
    if service == "ramflux-router" {
        run_case(binary, service, &fixture, "descriptors")?;
        assert_clean_reopen(&fixture.database)?;
        run_case(binary, service, &fixture, "churn")?;
    }
    assert_clean_reopen(&fixture.database)?;
    #[cfg(feature = "itest-http")]
    if service == "ramflux-federation" {
        for surface in ["admin", "public"] {
            for state in ["idle", "request"] {
                let _ = std::fs::remove_file(fixture.root.join("admitted"));
                run_case(binary, service, &fixture, &format!("http-{surface}-{state}"))?;
                assert_clean_reopen(&fixture.database)?;
            }
        }
    }
    #[cfg(feature = "itest-http")]
    if service == "ramflux-router" {
        std::fs::remove_file(fixture.root.join("admitted"))?;
        run_case(binary, service, &fixture, "second")?;
    }
    Ok(())
}

#[allow(dead_code)]
pub fn configured_notify_runtime_shutdown_is_clean(
    binary: &str,
    runtime: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new("ramflux-notify")?;
    fixture.notify_runtime = Some(runtime.to_owned());
    for mode in ["idle", "probe"] {
        run_case(binary, "ramflux-notify", &fixture, mode)?;
        assert_clean_reopen(&fixture.database)?;
    }
    Ok(())
}

struct Fixture {
    registration_seed: Option<RegistrationSeed>,
    gateway_tls_probe: Option<GatewayTlsProbe>,
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
    notify_runtime: Option<String>,
    public_addr: String,
    admin_addr: String,
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
            notify_runtime: None,
            registration_seed: None,
            gateway_tls_probe: None,
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
            public_addr: free_tcp_addr()?,
            admin_addr: free_tcp_addr()?,
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

struct ShutdownLogReader {
    receiver: mpsc::Receiver<String>,
    thread: std::thread::JoinHandle<String>,
}

fn spawn_shutdown_log_reader(stdout: std::process::ChildStdout) -> ShutdownLogReader {
    let (sender, receiver) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut logs = String::new();
        for line in std::io::BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    logs.push_str(&line);
                    logs.push('\n');
                    let _ = sender.send(line);
                }
                Err(_) => break,
            }
        }
        logs
    });
    ShutdownLogReader { receiver, thread }
}

#[cfg(feature = "itest-http")]
fn seed_request_case(
    service: &str,
    fixture: &Fixture,
    mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if service == "ramflux-federation" && mode == "request" {
        seed_federation_sweep(fixture)?;
    }
    if service == "ramflux-router"
        && mode == "request"
        && let Some(seed) = fixture.registration_seed
    {
        seed(&fixture.database)?;
    }
    Ok(())
}

fn run_case(
    binary: &str,
    service: &str,
    fixture: &Fixture,
    mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "itest-http")]
    seed_request_case(service, fixture, mode)?;
    let mut command = configured_command(binary, service, fixture, mode)?;
    if mode.starts_with("failure-") {
        let directory = fixture.root.join("connection-failures");
        std::fs::create_dir_all(&directory)?;
        command.env("RAMFLUX_ITEST_CONNECTION_FAILURE_DIR", directory);
    }
    let mut child = ChildGuard(command.spawn()?);
    let stdout = child.0.stdout.take().ok_or("missing stdout")?;
    let log_reader = spawn_shutdown_log_reader(stdout);
    if let Err(error) = wait_for_ready(&log_reader.receiver, service, Duration::from_secs(10)) {
        let _ = child.0.kill();
        let _ = child.0.wait();
        let mut logs = log_reader.thread.join().map_err(|_| "stdout reader panicked")?;
        if let Some(mut stderr) = child.0.stderr.take() {
            stderr.read_to_string(&mut logs)?;
        }
        return Err(format!("{service} startup failed ({error}): {logs}").into());
    }
    if let Some(stage) = mode.strip_prefix("failure-") {
        std::fs::write(fixture.root.join("connection-failures").join(stage), b"fail once")?;
    }
    let shutdown_started = Arc::new(AtomicBool::new(false));
    let probe_closed = Arc::new(AtomicBool::new(false));
    let probe = start_configured_probe(service, mode, fixture, &shutdown_started, &probe_closed)?;
    let mut peer = if matches!(
        mode,
        "pooled" | "handshake" | "raw" | "request" | "churn" | "descriptors" | "second"
    ) || mode.starts_with("failure-")
        || mode.starts_with("http-")
    {
        Some(start_mesh_peer(
            fixture,
            service,
            if mode == "second" { "request" } else { mode },
            child.0.id(),
        )?)
    } else {
        None
    };
    if matches!(mode, "request" | "second") || mode.ends_with("-request") {
        wait_for_file(&fixture.root.join("admitted"))?;
    }
    let (status, elapsed) = signal_and_wait(
        &mut child.0,
        service,
        mode,
        shutdown_bound(service)?,
        (mode == "probe").then_some(&shutdown_started),
    )?;
    wait_for_request_peer(peer.as_mut(), mode)?;
    finish_shutdown_probe(
        probe,
        probe_closed.as_ref(),
        service == "ramflux-gateway" && mode == "probe",
    )?;
    let mut logs = log_reader.thread.join().map_err(|_| "stdout reader panicked")?;
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
    if let Some(stage) = mode.strip_prefix("failure-") {
        assert!(
            !fixture.root.join("connection-failures").join(stage).exists(),
            "failure was not injected"
        );
        assert_eq!(
            logs.matches(&format!("injected connection {stage} failure")).count(),
            1,
            "{logs}"
        );
    }
    if logs.matches("graceful shutdown complete").count() != 1 {
        return Err(format!("missing unique shutdown completion for {service}: {logs}").into());
    }
    Ok(())
}

fn start_configured_probe(
    service: &str,
    mode: &str,
    fixture: &Fixture,
    shutdown_started: &Arc<AtomicBool>,
    probe_closed: &Arc<AtomicBool>,
) -> Result<Option<ShutdownProbe>, Box<dyn std::error::Error>> {
    if mode != "probe" {
        return Ok(None);
    }
    if service == "ramflux-gateway" {
        let start_probe = fixture.gateway_tls_probe.ok_or("gateway TLS probe not configured")?;
        Ok(Some(start_probe(
            &fixture.probe_addr,
            &fixture.root.join("ca.pem"),
            Arc::clone(shutdown_started),
            Arc::clone(probe_closed),
        )?))
    } else {
        Ok(Some(start_request_probe(
            &fixture.probe_addr,
            fixture.probe_udp,
            Arc::clone(shutdown_started),
            shutdown_bound(service)?,
        )?))
    }
}

fn finish_shutdown_probe(
    probe: Option<ShutdownProbe>,
    probe_closed: &AtomicBool,
    require_closed_at_exit: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(probe) = probe {
        probe.join().map_err(|_| "request probe panicked")??;
    }
    if require_closed_at_exit && !probe_closed.load(Ordering::SeqCst) {
        return Err("gateway TLS connection remained open when the process exited".into());
    }
    Ok(())
}

fn wait_for_request_peer(
    peer: Option<&mut ChildGuard>,
    mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(peer) = peer
        && (mode == "request" || mode.ends_with("-request"))
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
    shutdown_started: Arc<AtomicBool>,
    close_bound: Duration,
) -> Result<std::thread::JoinHandle<Result<(), std::io::Error>>, std::io::Error> {
    if udp {
        return start_udp_close_probe(addr, shutdown_started, close_bound);
    }
    start_tcp_http_close_probe(addr, shutdown_started, close_bound)
}

fn start_udp_close_probe(
    addr: &str,
    shutdown_started: Arc<AtomicBool>,
    close_bound: Duration,
) -> Result<std::thread::JoinHandle<Result<(), std::io::Error>>, std::io::Error> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.connect(addr)?;
    socket.send(b"shutdown-race")?;
    Ok(std::thread::spawn(move || {
        wait_for_probe_shutdown_start(&shutdown_started)?;
        read_udp_probe_to_close(&socket, close_bound)
    }))
}

fn start_tcp_http_close_probe(
    addr: &str,
    shutdown_started: Arc<AtomicBool>,
    close_bound: Duration,
) -> Result<std::thread::JoinHandle<Result<(), std::io::Error>>, std::io::Error> {
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
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")?;
    let admitted = Instant::now() + Duration::from_millis(80);
    while Instant::now() < admitted {
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(std::thread::spawn(move || {
        wait_for_probe_shutdown_start(&shutdown_started)?;
        read_http_probe_to_close(&mut stream, close_bound)
    }))
}

fn wait_for_probe_shutdown_start(shutdown_started: &AtomicBool) -> Result<(), std::io::Error> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !shutdown_started.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "shutdown signal exceeded 10-second hang guard",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn read_http_probe_to_close(
    stream: &mut TcpStream,
    close_bound: Duration,
) -> Result<(), std::io::Error> {
    let deadline = Instant::now() + close_bound;
    let mut chunk = [0; 1024];
    let mut response = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "socket did not close within the shutdown hang guard",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error),
        }
    }
    reject_malformed_http_close(&response)
}

fn read_udp_probe_to_close(
    socket: &UdpSocket,
    close_bound: Duration,
) -> Result<(), std::io::Error> {
    let deadline = Instant::now() + close_bound;
    let mut chunk = [0; 1024];
    let mut response = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        socket.set_read_timeout(Some(remaining))?;
        match socket.recv(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                break;
            }
            Err(error) => return Err(error),
        }
    }
    reject_malformed_http_close(&response)
}

fn reject_malformed_http_close(response: &[u8]) -> Result<(), std::io::Error> {
    if response.is_empty()
        || is_well_formed_http_error_response(response)
        || is_well_formed_tls_alert(response)
    {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "probe received neither EOF/reset nor a well-formed HTTP error response: {response:?}"
        ),
    ))
}

fn is_well_formed_tls_alert(response: &[u8]) -> bool {
    if response.is_empty() {
        return false;
    }
    let mut rest = response;
    while !rest.is_empty() {
        if rest.len() < 7 || rest[0] != 0x15 || rest[1] != 0x03 || !matches!(rest[2], 0x01..=0x03) {
            return false;
        }
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if len != 2 || rest.len() < 5 + len {
            return false;
        }
        if !matches!(rest[5], 1 | 2) {
            return false;
        }
        rest = &rest[5 + len..];
    }
    true
}

fn is_well_formed_http_error_response(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let mut lines = response[..header_end].split(|byte| *byte == b'\n');
    let Some(status_line) = lines.next().and_then(|line| line.strip_suffix(b"\r")) else {
        return false;
    };
    let Ok(status_line) = std::str::from_utf8(status_line) else {
        return false;
    };
    let mut status_parts = status_line.splitn(3, ' ');
    let (Some(version), Some(status), Some(reason)) =
        (status_parts.next(), status_parts.next(), status_parts.next())
    else {
        return false;
    };
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || status.len() != 3
        || !status.bytes().all(|byte| byte.is_ascii_digit())
        || !status.parse::<u16>().is_ok_and(|code| (400..=599).contains(&code))
        || reason.bytes().any(|byte| byte < b' ' || byte == 0x7f)
    {
        return false;
    }
    lines.all(|line| {
        let Some(line) = line.strip_suffix(b"\r") else {
            return false;
        };
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return false;
        };
        let name = &line[..colon];
        let value = &line[colon + 1..];
        !name.is_empty()
            && name.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
            && value.iter().all(|byte| *byte == b'\t' || (*byte >= b' ' && *byte != 0x7f))
    })
}

fn shutdown_bound(service: &str) -> Result<Duration, Box<dyn std::error::Error>> {
    match service {
        "ramflux-gateway" => Ok(Duration::from_secs(10)),
        "ramflux-router" | "ramflux-notify" | "ramflux-federation" | "ramflux-relay"
        | "ramflux-signaling" | "ramflux-retention" => Ok(Duration::from_secs(4)),
        _ => Err(format!("unknown shutdown-test service {service}").into()),
    }
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
    let spiffe_service =
        if service == "ramflux-gateway" { "ramflux-gateway/ramflux-gateway" } else { service };
    std::fs::write(
        &extensions,
        format!(
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,URI:spiffe://localhost/{spiffe_service}\n"
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
                if mode.starts_with("http-admin-") {
                    &fixture.admin_addr
                } else if mode.starts_with("http-public-") {
                    &fixture.public_addr
                } else {
                    &fixture.probe_addr
                },
                mode,
                service,
                &pid.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    if mode != "request" && !mode.ends_with("-request") {
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
            assert_eq!(
                store.pending_identity_admission_count()?,
                0,
                "SIGTERM must drain the identity journal"
            );
            let router = store.load_router()?.ok_or("missing router state")?;
            let session = router.session("shutdown-target");
            assert_eq!(session.is_some(), committed);
            if let Some(session) = session {
                assert_eq!(session.session_id, "shutdown-session");
                assert_eq!(session.device_id, "shutdown-device");
                assert_eq!(session.gateway_id, "ramflux-gateway");
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
        .env("RAMFLUX_FEDERATION_PUBLIC_ADDR", &fixture.public_addr)
        .env("RAMFLUX_FEDERATION_ADMIN_ADDR", &fixture.admin_addr)
        .env("RAMFLUX_RELAY_VOICE_UDP_ADDR", &fixture.voice_udp)
        .env("RAMFLUX_RELAY_VOICE_CONTROL_ADDR", &fixture.voice_control)
        .env("RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT", &fixture.voice_udp)
        .env_remove("RAMFLUX_RELAY_CLIENT_QUIC_ADDR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(runtime) = &fixture.notify_runtime {
        child
            .env("RAMFLUX_NOTIFY_RUNTIME", runtime)
            .env("RAMFLUX_NOTIFY_TOKIO_CONCURRENT_WORKERS", "2")
            .env("RAMFLUX_NOTIFY_TOKIO_CONCURRENT_PROVIDER_WORKERS", "2")
            .env("RAMFLUX_NOTIFY_COMPIO_SHARDS", "2")
            .env("RAMFLUX_NOTIFY_COMPIO_FANOUT_WORKERS", "2")
            .env("RAMFLUX_NOTIFY_COMPIO_PROVIDER_WORKERS", "2");
    }
    if service == "ramflux-gateway" {
        child.env(
            "RAMFLUX_RELAY_SERVICE_KEY_REF",
            "literal:shutdown-test-relay-service-key-material",
        );
    }
    if matches!(mode, "request" | "second") || mode.ends_with("-request") {
        child.env("RAMFLUX_ITEST_SHUTDOWN_REQUEST_MARKER", fixture.root.join("admitted"));
    }
    Ok(child)
}

fn signal_and_wait(
    child: &mut Child,
    service: &str,
    mode: &str,
    shutdown_bound: Duration,
    shutdown_started: Option<&AtomicBool>,
) -> Result<(std::process::ExitStatus, Duration), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let sent = Command::new("kill").args(["-TERM", &child.id().to_string()]).status()?;
    if !sent.success() {
        return Err(format!("kill failed for {service}: {sent}").into());
    }
    if let Some(shutdown_started) = shutdown_started {
        shutdown_started.store(true, Ordering::SeqCst);
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
        assert!(
            started.elapsed() < shutdown_bound,
            "{service} exceeded {shutdown_bound:?} shutdown hang guard"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    Ok((status, started.elapsed()))
}
