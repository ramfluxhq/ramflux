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
    run_case(binary, service, &fixture, false)?;
    assert_clean_reopen(&fixture.database)?;
    run_case(binary, service, &fixture, true)?;
    assert_clean_reopen(&fixture.database)?;
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
}

impl Fixture {
    fn new(service: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir()
            .join(format!("ramflux-{service}-shutdown-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(root.join("state"))?;
        let key = root.join("service.key");
        let cert = root.join("service.pem");
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-days",
            "1",
            "-keyout",
            key.to_str().ok_or("non-UTF-8 key path")?,
            "-out",
            cert.to_str().ok_or("non-UTF-8 certificate path")?,
        ])?;
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
allowed_service_ids = ["{service}"]

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
                cert.display(),
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
    race_request: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new(binary);
    child
        .args(["--config", fixture.config.to_str().ok_or("non-UTF-8 config path")?])
        .env("RAMFLUX_SHUTDOWN_GRACE_SECONDS", "3")
        .env("RAMFLUX_NODE_STATE_DIR", fixture.root.join("state"))
        .env("RAMFLUX_NOTIFY_ROUTE_KEY_FILE", &fixture.route_key)
        .env("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE", &fixture.signing_seed)
        .env("RAMFLUX_ROUTER_ASYNC_INGRESS", "0")
        .env("RAMFLUX_NOTIFY_MESH_LISTEN_ADDR", &fixture.probe_addr)
        .env("RAMFLUX_RETENTION_ASYNC_LISTEN_ADDR", "")
        .env("RAMFLUX_FEDERATION_PUBLIC_ADDR", "127.0.0.1:0")
        .env("RAMFLUX_FEDERATION_ADMIN_ADDR", "127.0.0.1:0")
        .env("RAMFLUX_RELAY_VOICE_UDP_ADDR", &fixture.voice_udp)
        .env("RAMFLUX_RELAY_VOICE_CONTROL_ADDR", &fixture.voice_control)
        .env("RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT", &fixture.voice_udp)
        .env_remove("RAMFLUX_RELAY_CLIENT_QUIC_ADDR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = ChildGuard(child.spawn()?);
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
    wait_for_ready(&log_receiver, service, Duration::from_secs(10))?;
    let probe = if race_request {
        Some(start_request_probe(&fixture.probe_addr, fixture.probe_udp)?)
    } else {
        None
    };
    let started = Instant::now();
    let sent = Command::new("kill").args(["-TERM", &child.0.id().to_string()]).status()?;
    if !sent.success() {
        return Err(format!("kill failed for {service}: {sent}").into());
    }
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(5) {
            return Err(format!("{service} exceeded shutdown bound").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if let Some(probe) = probe {
        probe.join().map_err(|_| "request probe panicked")??;
    }
    let mut logs = reader.join().map_err(|_| "stdout reader panicked")?;
    if let Some(mut stderr) = child.0.stderr.take() {
        stderr.read_to_string(&mut logs)?;
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
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("service startup exceeded test timeout".into());
        }
        let line = receiver.recv_timeout(remaining)?;
        if line.contains(marker) {
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
