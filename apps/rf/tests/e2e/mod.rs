// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared boot for CLI e2e: mesh certs, four node processes, rf daemons, PTY create.
#![allow(dead_code)]

mod proc;

use serde::Deserialize as _;
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Write as _},
    net::{TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PASSPHRASE: &str = "cli-e2e-passphrase-ok";
const NODE_ID: &str = "localhost";
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);
const CEREMONY_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_TIMEOUT: Duration = Duration::from_secs(90);
const CLI_TIMEOUT: Duration = Duration::from_secs(15);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const BOOT_ATTEMPTS: u32 = 5;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct ChildGuard {
    group: proc::ProcessGroup,
    name: String,
    log_path: PathBuf,
}

impl ChildGuard {
    fn spawn(name: String, mut command: Command, log_path: PathBuf) -> Result<Self> {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log = File::create(&log_path)
            .map_err(|error| format!("create log {}: {error}", log_path.display()))?;
        let log_err = log
            .try_clone()
            .map_err(|error| format!("clone log {}: {error}", log_path.display()))?;
        command.stdout(Stdio::from(log)).stderr(Stdio::from(log_err));
        let group = proc::ProcessGroup::spawn(&mut command)
            .map_err(|error| format!("spawn {name}: {error}"))?;
        Ok(Self { group, name, log_path })
    }

    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        Ok(self.group.try_wait()?)
    }

    fn exited(&mut self) -> Result<bool> {
        Ok(self.try_wait()?.is_some())
    }

    fn pid(&self) -> u32 {
        self.group.id()
    }
}

pub struct Stack {
    pub root: PathBuf,
    pub discovery_url: String,
    pub gateway_public: String,
    pub router_mesh: String,
    _servers: Vec<ChildGuard>,
}

pub struct Daemon {
    pub socket: PathBuf,
    pub data_root: PathBuf,
    child: ChildGuard,
}

pub struct Account {
    pub id: String,
    pub display_name: String,
    pub principal_id: String,
    pub principal_commitment: String,
    pub device_id: String,
    pub target_delivery_id: String,
}

impl Drop for Stack {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct RootGuard {
    path: PathBuf,
    keep: bool,
}

impl Drop for RootGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        stop_daemon_process(&self.socket, &mut self.child);
    }
}

fn stop_daemon_process(socket: &Path, child: &mut ChildGuard) {
    let _ = rf_output_timeout(socket, &["daemon", "stop"], STOP_TIMEOUT);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.group.kill_group();
    let _ = child.group.wait();
}

pub fn boot_stack() -> Result<Stack> {
    let mut last = None;
    for attempt in 1..=BOOT_ATTEMPTS {
        match boot_stack_once() {
            Ok(stack) => return Ok(stack),
            Err(error) if attempt < BOOT_ATTEMPTS && is_addr_in_use(&error) => {
                last = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| "boot stack retries exhausted".into()))
}

fn is_addr_in_use(error: &impl std::fmt::Display) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("address already in use")
        || text.contains("eaddrinuse")
        || text.contains("addrinuse")
}

fn boot_stack_once() -> Result<Stack> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("rf-cli-e2e-{}-{nonce}", std::process::id()));
    let mut guard = RootGuard { path: root.clone(), keep: false };
    std::fs::create_dir_all(root.join("secrets"))?;
    std::fs::create_dir_all(root.join("state"))?;
    std::fs::create_dir_all(root.join("certs"))?;
    create_ca(&root)?;
    let services = ["ramflux-federation", "ramflux-router", "ramflux-retention", "ramflux-gateway"];
    for service in services {
        issue_service_cert(&root, service)?;
    }
    let mesh: Vec<String> =
        services.iter().map(|_| free_tcp_addr()).collect::<std::io::Result<_>>()?;
    let gateway_quic = free_udp_addr()?;
    let gateway_tcp = free_tcp_addr()?;
    let public_addr = free_tcp_addr()?;
    let admin_addr = free_tcp_addr()?;
    let signing_seed = root.join("secrets").join("node-signing.key");
    write_seed_file(&signing_seed, &[0xA1; 32])?;
    let route_key = root.join("secrets").join("notify-route.key");
    write_seed_file(&route_key, &[0x11; 32])?;
    let custody = init_custody(&root, &signing_seed)?;
    let router_async = free_udp_addr()?;
    for (service, mesh_addr) in services.iter().zip(mesh.iter()) {
        write_service_toml(&root, service, mesh_addr, &mesh, &gateway_tcp)?;
    }
    let mut servers = Vec::new();
    let order = [
        ("ramflux-federation", federation_ready()),
        (
            "ramflux-router",
            &["router mesh mTLS surface listening", "router async QUIC ingress listening"][..],
        ),
        ("ramflux-retention", &["retention mesh mTLS surface listening"][..]),
        (
            "ramflux-gateway",
            &[
                "gateway QUIC session surface listening",
                "gateway TCP-TLS session surface listening",
            ][..],
        ),
    ];
    let ca_pem = root.join("certs").join("ca.pem");
    for (service, markers) in order {
        let mut command = Command::new(sibling_bin(service)?);
        command
            .arg("--config")
            .arg(root.join("certs").join(format!("{service}.toml")))
            .env("RAMFLUX_SHUTDOWN_GRACE_SECONDS", "3")
            .env("RAMFLUX_NODE_STATE_DIR", root.join("state"))
            .env("RAMFLUX_NOTIFY_ROUTE_KEY_FILE", &route_key)
            .env("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE", &signing_seed)
            .env("RAMFLUX_FEDERATION_PUBLIC_ADDR", &public_addr)
            .env("RAMFLUX_FEDERATION_ADMIN_ADDR", &admin_addr)
            .env("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR", &gateway_quic)
            .env("RAMFLUX_ITEST_GATEWAY_TCP_ADDR", &gateway_tcp)
            .env("RAMFLUX_CLIENT_GATEWAY_QUIC_ADDR", &gateway_quic)
            .env("RAMFLUX_CLIENT_GATEWAY_TCP_ADDR", &gateway_tcp)
            .env("RAMFLUX_CLIENT_GATEWAY_SERVER_NAME", "localhost")
            .env("RAMFLUX_FEDERATION_NODE_ID", NODE_ID)
            .env("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", &custody.node_public_key)
            .env("RAMFLUX_CUSTODY_NODE_RECORD_FILE", &custody.node_record_file)
            .env("RAMFLUX_CUSTODY_PROXY_SIGNING_SEED", &custody.proxy_signing_seed)
            .env("RAMFLUX_ROUTER_ASYNC_INGRESS", "1")
            .env("RAMFLUX_ROUTER_ASYNC_LISTEN_ADDR", &router_async)
            .env("RAMFLUX_ROUTER_ASYNC_ENDPOINT", &router_async)
            .env("RAMFLUX_ROUTER_ASYNC_SERVER_NAME", "ramflux-router")
            .env("RAMFLUX_ROUTER_ASYNC_PEER_CA_PEM_FILE", &ca_pem)
            .env("RUST_LOG", "info")
            .env_remove("RAMFLUX_RELAY_CLIENT_QUIC_ADDR");
        let log_path = root.join("logs").join(format!("{service}.log"));
        let mut child = ChildGuard::spawn(service.to_owned(), command, log_path.clone())?;
        if let Err(error) = wait_for_log_markers(&log_path, markers, READY_TIMEOUT) {
            let logs = std::fs::read_to_string(&log_path).unwrap_or_default();
            return Err(format!("{service} startup failed ({error}): {logs}").into());
        }
        if child.exited()? {
            let logs = std::fs::read_to_string(&log_path).unwrap_or_default();
            return Err(format!("{service} exited after ready: {logs}").into());
        }
        servers.push(child);
    }
    let discovery_url = format!("http://{public_addr}");
    let record = fetch_client_discovery(&discovery_url)?;
    assert_discovery_addr(&record, "gateway_quic_addr", &gateway_quic)?;
    assert_discovery_addr(&record, "gateway_tcp_addr", &gateway_tcp)?;
    let advertised_name = record
        .get("gateway_server_name")
        .and_then(Value::as_str)
        .ok_or("discovery record missing gateway_server_name")?;
    if advertised_name != "localhost" {
        return Err(format!("discovery gateway_server_name {advertised_name} != localhost").into());
    }
    probe_gateway_tls(&root.join("certs").join("ca.pem"), &gateway_tcp)?;
    let router_mesh = mesh.get(1).cloned().ok_or("router mesh address")?;
    guard.keep = true;
    Ok(Stack { root, discovery_url, gateway_public: gateway_tcp, router_mesh, _servers: servers })
}

fn fetch_client_discovery(origin: &str) -> Result<Value> {
    let addr = origin.trim_start_matches("http://");
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(
        b"GET /.well-known/ramflux/client HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    let mut body = String::new();
    stream.read_to_string(&mut body)?;
    parse_json_object(&body).map_err(|error| {
        format!("federation discovery at {origin}/.well-known/ramflux/client: {error}; body={body}")
            .into()
    })
}

struct CustodyEnv {
    node_public_key: String,
    node_record_file: String,
    proxy_signing_seed: String,
}

fn init_custody(root: &Path, signing_seed: &Path) -> Result<CustodyEnv> {
    let output_dir = root.join("custody");
    let public = ramflux_crypto::public_key_base64url_from_seed([0xA1; 32]);
    let mut command = Command::new(rf_bin());
    command
        .args([
            "--socket",
            "/nonexistent/cli-e2e-custody.sock",
            "node",
            "custody-init",
            "--node-id",
            NODE_ID,
            "--node-signing-seed",
        ])
        .arg(signing_seed)
        .args(["--expected-public-key", &public, "--output-dir"])
        .arg(&output_dir);
    let output = proc::run_group_output(&mut command, CLI_TIMEOUT)?;
    if !output.status.success() {
        return Err(format!(
            "rf node custody-init failed ({}): stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    parse_custody_env(&output_dir.join("custody.env"))
}

fn parse_custody_env(path: &Path) -> Result<CustodyEnv> {
    let text = std::fs::read_to_string(path)?;
    let mut node_public_key = None;
    let mut node_record_file = None;
    let mut proxy_signing_seed = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = unquote(value);
        match key {
            "RAMFLUX_CUSTODY_NODE_PUBLIC_KEY" => node_public_key = Some(value),
            "RAMFLUX_CUSTODY_NODE_RECORD_FILE" => node_record_file = Some(value),
            "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED" => proxy_signing_seed = Some(value),
            _ => {}
        }
    }
    Ok(CustodyEnv {
        node_public_key: node_public_key.ok_or("custody.env missing NODE_PUBLIC_KEY")?,
        node_record_file: node_record_file.ok_or("custody.env missing NODE_RECORD_FILE")?,
        proxy_signing_seed: proxy_signing_seed.ok_or("custody.env missing PROXY_SIGNING_SEED")?,
    })
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(inner) = trimmed.strip_prefix('\'').and_then(|rest| rest.strip_suffix('\'')) {
        inner.replace("'\\''", "'")
    } else if let Some(inner) = trimmed.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) {
        inner.to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn federation_ready() -> &'static [&'static str] {
    &[
        "federation production admin HTTP surface listening",
        "federation mesh mTLS surface listening",
    ]
}

pub fn start_daemon(stack: &Stack, name: &str) -> Result<Daemon> {
    let data_root = stack.root.join(format!("daemon-{name}"));
    let socket = stack.root.join(format!("{name}.sock"));
    std::fs::create_dir_all(&data_root)?;
    spawn_daemon(socket, data_root)
}

pub fn shutdown_daemon(daemon: Daemon) -> Result<(PathBuf, PathBuf)> {
    let socket = daemon.socket.clone();
    let data_root = daemon.data_root.clone();
    drop(daemon);
    let deadline = Instant::now() + Duration::from_secs(5);
    while socket.exists() {
        if Instant::now() >= deadline {
            return Err("daemon stop did not remove the socket".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok((socket, data_root))
}

pub fn start_daemon_at(socket: PathBuf, data_root: PathBuf) -> Result<Daemon> {
    spawn_daemon(socket, data_root)
}

pub fn restart_daemon(daemon: Daemon) -> Result<Daemon> {
    let (socket, data_root) = shutdown_daemon(daemon)?;
    spawn_daemon(socket, data_root)
}

fn spawn_daemon(socket: PathBuf, data_root: PathBuf) -> Result<Daemon> {
    std::fs::create_dir_all(&data_root)?;
    let mut command = Command::new(rf_bin());
    command
        .arg("--socket")
        .arg(&socket)
        .args(["daemon", "start", "--data-root"])
        .arg(&data_root)
        .arg("--itest-memory-vault")
        .env("RUST_LOG", "info");
    let log_path = data_root.join("daemon.log");
    let mut child = ChildGuard::spawn(format!("rf-{}", socket.display()), command, log_path)?;
    let deadline = Instant::now() + SOCKET_TIMEOUT;
    while !socket.exists() {
        if child.exited()? {
            return Err("daemon exited before binding its socket".into());
        }
        if Instant::now() >= deadline {
            return Err("daemon did not bind its socket".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(Daemon { socket, data_root, child })
}

pub fn configure_node(daemon: &Daemon, discovery_url: &str) -> Result<String> {
    let added = rf_json(&daemon.socket, &["node", "add", discovery_url])?;
    let node_id = added["node"]["node_id"]
        .as_str()
        .or_else(|| added["node_id"].as_str())
        .unwrap_or(NODE_ID)
        .to_owned();
    rf_json(&daemon.socket, &["node", "confirm", &node_id])?;
    rf_json(&daemon.socket, &["node", "set-default", &node_id])?;
    Ok(node_id)
}

pub fn create_account(daemon: &Daemon, display_name: &str) -> Result<Account> {
    let created = pty_account_create(&daemon.socket, display_name, PASSPHRASE)?;
    let id = required_str(&created, "account_id")?;
    wait_networking_live(daemon, &id)?;
    let status = rf_json(&daemon.socket, &["account", "status", "--account", &id])?;
    Ok(Account {
        id,
        display_name: display_name.to_owned(),
        principal_id: required_str(&status, "principal_id")?,
        principal_commitment: required_str(&status, "principal_commitment")?,
        device_id: required_str(&status, "device_id")?,
        target_delivery_id: required_str(&status, "target_delivery_id")?,
    })
}

pub fn unlock_account(daemon: &Daemon, account: &Account) -> Result<Value> {
    let unlocked = rf_json_env(
        &daemon.socket,
        &[
            "account",
            "unlock",
            "--account",
            &account.id,
            "--passphrase-env",
            "RAMFLUX_ACCOUNT_PASSPHRASE",
        ],
        &[("RAMFLUX_ACCOUNT_PASSPHRASE", PASSPHRASE)],
    )?;
    wait_networking_live(daemon, &account.id)?;
    Ok(unlocked)
}

pub fn exchange_contacts(a: &Daemon, alice: &Account, b: &Daemon, bob: &Account) -> Result<()> {
    let alice_card = rf_json(&a.socket, &["contact", "card", "--account", &alice.id])?;
    let bob_card = rf_json(&b.socket, &["contact", "card", "--account", &bob.id])?;
    let alice_text = required_str(&alice_card, "card")?;
    let bob_text = required_str(&bob_card, "card")?;
    rf_json(&b.socket, &["contact", "add", "--account", &bob.id, "--card", &alice_text])?;
    rf_json(&a.socket, &["contact", "add", "--account", &alice.id, "--card", &bob_text])?;
    wait_contact(a, alice, bob)?;
    wait_contact(b, bob, alice)?;
    Ok(())
}

fn wait_contact(daemon: &Daemon, owner: &Account, peer: &Account) -> Result<Value> {
    poll_json(daemon, &["contact", "list", "--account", &owner.id], POLL_TIMEOUT, |value| {
        contact_list_has_peer(value, peer)
    })
}

fn contact_list_has_peer(value: &Value, peer: &Account) -> bool {
    let Some(contacts) = value.get("contacts").and_then(Value::as_array) else {
        return false;
    };
    contacts.iter().any(|row| {
        row.get("principal_id").and_then(Value::as_str) == Some(peer.principal_id.as_str())
            || row.get("root_commitment").and_then(Value::as_str)
                == Some(peer.principal_commitment.as_str())
            || row.get("target_id").and_then(Value::as_str) == Some(peer.principal_id.as_str())
            || row.get("requester_id").and_then(Value::as_str) == Some(peer.principal_id.as_str())
    })
}

pub fn dm_send(
    daemon: &Daemon,
    sender: &Account,
    recipient: &Account,
    conversation: &str,
    message: &str,
    body: &str,
) -> Result<Value> {
    let args = [
        "dm",
        "send",
        "--account",
        sender.id.as_str(),
        "--conversation",
        conversation,
        "--message",
        message,
        "--envelope",
        message,
        "--source-principal",
        sender.principal_id.as_str(),
        "--sender",
        sender.device_id.as_str(),
        "--recipient-device",
        recipient.device_id.as_str(),
        "--recipient-principal-commitment",
        recipient.principal_commitment.as_str(),
        "--target",
        recipient.target_delivery_id.as_str(),
        "--body",
        body,
    ];
    poll_json(daemon, &args, POLL_TIMEOUT, |_| true).map_err(|error| {
        let log = std::fs::read_to_string(daemon.data_root.join("daemon.log")).unwrap_or_default();
        format!("{error}; daemon_log={log}").into()
    })
}

pub fn wait_dm_texts(
    daemon: &Daemon,
    account: &Account,
    conversation: &str,
    expected: &[&str],
) -> Result<Value> {
    poll_json(
        daemon,
        &["dm", "read", "--account", &account.id, "--conversation", conversation],
        POLL_TIMEOUT,
        |value| contains_all_texts(value, expected),
    )
    .map_err(|error| {
        let log = std::fs::read_to_string(daemon.data_root.join("daemon.log")).unwrap_or_default();
        format!("{error}; daemon_log={log}").into()
    })
}

pub fn wait_dm_receipt(
    daemon: &Daemon,
    owner: &Account,
    conversation: &str,
    message_id: &str,
    peer: &Account,
) -> Result<Value> {
    poll_json(
        daemon,
        &["dm", "read", "--account", &owner.id, "--conversation", conversation],
        POLL_TIMEOUT,
        |value| message_has_peer_receipt(value, message_id, peer),
    )
    .map_err(|error| {
        let log = std::fs::read_to_string(daemon.data_root.join("daemon.log")).unwrap_or_default();
        format!("Alice receipt JSON missing B's qualified receipt: {error}; daemon_log={log}")
            .into()
    })
}

pub fn message_has_peer_receipt(value: &Value, message_id: &str, peer: &Account) -> bool {
    for key in ["decrypted_messages", "messages"] {
        let Some(rows) = value.get(key).and_then(Value::as_array) else {
            continue;
        };
        for row in rows {
            if row.get("message_id").and_then(Value::as_str) != Some(message_id)
                && row.get("id").and_then(Value::as_str) != Some(message_id)
            {
                continue;
            }
            let Some(receipts) = row.get("receipts").and_then(Value::as_array) else {
                continue;
            };
            if receipts.iter().any(|receipt| receipt_matches_peer(receipt, peer)) {
                return true;
            }
        }
    }
    false
}

fn receipt_matches_peer(receipt: &Value, peer: &Account) -> bool {
    let device = receipt.get("device_id").and_then(Value::as_str);
    let root = receipt.get("principal_commitment").and_then(Value::as_str);
    let state = receipt.get("state").and_then(Value::as_str);
    let delivered = receipt.get("delivered_at").and_then(Value::as_i64);
    let read = receipt.get("read_at").and_then(Value::as_i64);
    device == Some(peer.device_id.as_str())
        && root == Some(peer.principal_commitment.as_str())
        && matches!(state, Some("delivered" | "read"))
        && (delivered.is_some_and(|ts| ts > 0) || read.is_some_and(|ts| ts > 0))
}

pub fn wait_node_observed_ack(
    stack: &Stack,
    account: &Account,
    envelope_id: &str,
) -> Result<Value> {
    let deadline = Instant::now() + POLL_TIMEOUT;
    let mut last = Value::Null;
    loop {
        match mesh_cursor(stack, &account.target_delivery_id) {
            Ok(cursor) if cursor_has_ack(&cursor, envelope_id) => return Ok(cursor),
            Ok(cursor) => last = cursor,
            Err(error) if Instant::now() >= deadline => {
                return Err(format!(
                    "node ACK for envelope {envelope_id} not observed: {error}; last={last}"
                )
                .into());
            }
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "node ACK for envelope {envelope_id} not observed; last cursor={last}"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn cursor_has_ack(cursor: &Value, envelope_id: &str) -> bool {
    if cursor.get("last_envelope_id").and_then(Value::as_str) == Some(envelope_id) {
        return true;
    }
    cursor
        .get("acked_envelope_ids")
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(envelope_id)))
}

fn mesh_cursor(stack: &Stack, target: &str) -> Result<Value> {
    let certs = stack.root.join("certs");
    let ca = certs.join("ca.pem");
    let cert = certs.join("ramflux-gateway.pem");
    let key = certs.join("ramflux-gateway.key");
    let path = format!("/mvp0/cursor/{target}");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        stack.router_mesh
    );
    let mut command = Command::new("openssl");
    command.args([
        "s_client",
        "-connect",
        &stack.router_mesh,
        "-servername",
        "ramflux-router",
        "-CAfile",
        ca.to_str().ok_or("ca path")?,
        "-cert",
        cert.to_str().ok_or("cert path")?,
        "-key",
        key.to_str().ok_or("key path")?,
        "-quiet",
    ]);
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut group = proc::ProcessGroup::spawn(&mut command)?;
    let child = group.child_mut().ok_or("mesh openssl child")?;
    let mut stdin = child.stdin.take().ok_or("mesh openssl stdin")?;
    let stdout = child.stdout.take().ok_or("mesh openssl stdout")?;
    let stderr = child.stderr.take().ok_or("mesh openssl stderr")?;
    stdin.write_all(request.as_bytes())?;
    drop(stdin);
    let sink = Arc::new(Mutex::new(String::new()));
    let readers =
        [proc::drain_pipe(stdout, Arc::clone(&sink)), proc::drain_pipe(stderr, Arc::clone(&sink))];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = String::new();
    let parsed = loop {
        last.clone_from(&sink.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        if let Some(value) = parse_mesh_cursor_body(&last) {
            break Some(value);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    group.kill_group();
    let _ = group.wait();
    for reader in readers {
        let _ = reader.join();
    }
    parsed.ok_or_else(|| {
        format!("mesh GET {path} on {} produced no JSON: {last}", stack.router_mesh).into()
    })
}

fn parse_mesh_cursor_body(text: &str) -> Option<Value> {
    if let Ok(value) = parse_json_object(text) {
        return Some(value);
    }
    let body = http_body(text);
    (body == "null").then_some(Value::Null)
}

fn http_body(text: &str) -> &str {
    if let Some((_, rest)) = text.split_once("\r\n\r\n") {
        return rest.trim();
    }
    if let Some((_, rest)) = text.split_once("\n\n") {
        return rest.trim();
    }
    text.trim()
}

pub fn dm_ack(
    daemon: &Daemon,
    account: &Account,
    conversation: &str,
    message: &str,
    inbox_seq: Option<u64>,
) -> Result<Value> {
    let seq_text = inbox_seq.map(|seq| seq.to_string());
    let mut args = vec![
        "dm",
        "ack",
        "--account",
        account.id.as_str(),
        "--conversation",
        conversation,
        "--message",
        message,
        "--envelope",
        message,
        "--receiver-device",
        account.device_id.as_str(),
    ];
    if let Some(seq) = seq_text.as_deref() {
        args.push("--inbox-seq");
        args.push(seq);
    }
    rf_json(&daemon.socket, &args).map_err(|error| {
        let log = std::fs::read_to_string(daemon.data_root.join("daemon.log")).unwrap_or_default();
        format!("{error}; daemon_log={log}").into()
    })
}

pub fn envelope_id_from_read(value: &Value) -> Option<String> {
    for key in ["decrypted_messages", "gateway_entries", "messages", "envelope"] {
        if let Some(id) = nested_envelope_id(value.get(key).unwrap_or(&Value::Null)) {
            return Some(id);
        }
    }
    nested_envelope_id(value)
}

pub fn inbox_seq_from_read(value: &Value, envelope_id: &str) -> Option<u64> {
    nested_inbox_seq(value, envelope_id)
}

fn nested_inbox_seq(value: &Value, envelope_id: &str) -> Option<u64> {
    match value {
        Value::Object(map) => {
            let id_match = map.get("envelope_id").and_then(Value::as_str) == Some(envelope_id)
                || map
                    .get("envelope")
                    .and_then(|envelope| envelope.get("envelope_id"))
                    .and_then(Value::as_str)
                    == Some(envelope_id);
            if id_match
                && let Some(seq) =
                    map.get("inbox_seq").and_then(Value::as_u64).filter(|seq| *seq > 0)
            {
                return Some(seq);
            }
            map.values().find_map(|child| nested_inbox_seq(child, envelope_id))
        }
        Value::Array(rows) => rows.iter().find_map(|row| nested_inbox_seq(row, envelope_id)),
        _ => None,
    }
}

fn nested_envelope_id(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(id) =
                map.get("envelope_id").and_then(Value::as_str).filter(|id| !id.is_empty())
            {
                return Some(id.to_owned());
            }
            map.values().find_map(nested_envelope_id)
        }
        Value::Array(rows) => rows.iter().find_map(nested_envelope_id),
        _ => None,
    }
}

pub fn dump_logs(stack: &Stack, daemons: &[&Daemon]) -> String {
    let mut out = String::new();
    if let Ok(entries) = std::fs::read_dir(stack.root.join("logs")) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("log");
            let body = std::fs::read_to_string(&path).unwrap_or_default();
            out.push_str("\n===== ");
            out.push_str(name);
            out.push_str(" (tail) =====\n");
            out.push_str(&tail_lines(&body, 80));
        }
    }
    for daemon in daemons {
        let name = daemon.data_root.file_name().and_then(|n| n.to_str()).unwrap_or("daemon");
        let body = std::fs::read_to_string(daemon.data_root.join("daemon.log")).unwrap_or_default();
        out.push_str("\n===== ");
        out.push_str(name);
        out.push_str(" (tail) =====\n");
        out.push_str(&tail_lines(&body, 40));
    }
    out
}

fn tail_lines(body: &str, n: usize) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

pub fn dm_receipt_delivered(
    daemon: &Daemon,
    account: &Account,
    conversation: &str,
    message: &str,
) -> Result<Value> {
    rf_json(
        &daemon.socket,
        &[
            "dm",
            "receipt",
            "delivered",
            "--account",
            &account.id,
            "--conversation",
            conversation,
            "--message",
            message,
            "--receiver-device",
            &account.device_id,
        ],
    )
}

pub fn group_create(
    daemon: &Daemon,
    creator: &Account,
    group: &str,
    members: &[&Account],
) -> Result<Value> {
    let mut last = rf_json(
        &daemon.socket,
        &[
            "group",
            "create",
            "--account",
            &creator.id,
            "--group",
            group,
            "--creator",
            &creator.device_id,
        ],
    )?;
    for member in members {
        last = group_member_add(daemon, creator, group, member)?;
    }
    Ok(last)
}

fn group_member_add(
    daemon: &Daemon,
    creator: &Account,
    group: &str,
    member: &Account,
) -> Result<Value> {
    let args = [
        "group",
        "member",
        "add",
        "--account",
        creator.id.as_str(),
        "--group",
        group,
        "--member-device",
        member.device_id.as_str(),
        "--member-principal-commitment",
        member.principal_commitment.as_str(),
        "--target-delivery",
        member.target_delivery_id.as_str(),
    ];
    poll_json(daemon, &args, POLL_TIMEOUT, |_| true).map_err(|error| {
        let log = std::fs::read_to_string(daemon.data_root.join("daemon.log")).unwrap_or_default();
        format!("{error}; daemon_log={log}").into()
    })
}

pub fn group_send(
    daemon: &Daemon,
    sender: &Account,
    group: &str,
    conversation: &str,
    message: &str,
    body: &str,
) -> Result<Value> {
    rf_json(
        &daemon.socket,
        &[
            "group",
            "send",
            "--account",
            &sender.id,
            "--group",
            group,
            "--conversation",
            conversation,
            "--message",
            message,
            "--sender",
            &sender.device_id,
            "--body",
            body,
        ],
    )
}

pub fn wait_group_texts(
    daemon: &Daemon,
    account: &Account,
    group: &str,
    conversation: &str,
    expected: &[&str],
) -> Result<Value> {
    poll_json(
        daemon,
        &[
            "group",
            "read",
            "--account",
            &account.id,
            "--group",
            group,
            "--conversation",
            conversation,
        ],
        POLL_TIMEOUT,
        |value| contains_all_texts(value, expected),
    )
}

pub fn unique(prefix: &str) -> String {
    let nanos =
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
    format!("{prefix}-{}-{nanos}", std::process::id())
}

pub fn message_texts(value: &Value) -> Vec<String> {
    let mut texts = Vec::new();
    for key in ["decrypted_messages", "messages"] {
        let Some(rows) = value.get(key).and_then(Value::as_array) else {
            continue;
        };
        for row in rows {
            if let Some(text) = row.get("body_utf8").and_then(Value::as_str) {
                texts.push(text.to_owned());
            }
        }
    }
    texts
}

pub fn contains_all_texts(value: &Value, expected: &[&str]) -> bool {
    let texts = message_texts(value);
    expected.iter().all(|body| texts.iter().any(|got| got == body))
}

pub fn assert_texts_once_in_order(value: &Value, expected: &[&str]) -> Result<()> {
    let texts = message_texts(value);
    let filtered: Vec<&str> =
        texts.iter().map(String::as_str).filter(|text| expected.contains(text)).collect();
    if filtered != expected {
        return Err(format!("expected {expected:?} once in order, got {texts:?}").into());
    }
    Ok(())
}

fn poll_json(
    daemon: &Daemon,
    args: &[&str],
    timeout: Duration,
    ready: impl Fn(&Value) -> bool,
) -> Result<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        match rf_json(&daemon.socket, args) {
            Ok(value) if ready(&value) => return Ok(value),
            Ok(value) if Instant::now() >= deadline => {
                return Err(format!("timed out waiting for CLI JSON; last={value}").into());
            }
            Err(error) if Instant::now() >= deadline => {
                return Err(format!("timed out waiting for CLI JSON; last={error}").into());
            }
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_networking_live(daemon: &Daemon, account_id: &str) -> Result<()> {
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        let status =
            rf_json(daemon.socket.as_path(), &["account", "status", "--account", account_id])?;
        if status.get("networking").and_then(Value::as_str) == Some("live") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let daemon_log =
                std::fs::read_to_string(daemon.data_root.join("daemon.log")).unwrap_or_default();
            let gateway_log = daemon
                .data_root
                .parent()
                .map(|root| root.join("logs").join("ramflux-gateway.log"))
                .and_then(|path| std::fs::read_to_string(path).ok())
                .unwrap_or_default();
            return Err(format!(
                "account {account_id} networking did not become live: {status}; daemon_log={daemon_log}; gateway_log={gateway_log}"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn rf_json(socket: &Path, args: &[&str]) -> Result<Value> {
    rf_json_env(socket, args, &[])
}

fn rf_json_env(socket: &Path, args: &[&str], extra: &[(&str, &str)]) -> Result<Value> {
    let output = rf_output_env(socket, args, extra)?;
    if !output.status.success() {
        return Err(format!(
            "rf {args:?} failed ({}): stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    parse_json_object(&stdout)
        .map_err(|error| format!("rf {args:?} produced non-JSON stdout ({error}): {stdout}").into())
}

fn rf_output(socket: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    rf_output_env(socket, args, &[])
}

fn rf_output_timeout(
    socket: &Path,
    args: &[&str],
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    rf_output_env_timeout(socket, args, &[], timeout)
}

fn rf_output_env(
    socket: &Path,
    args: &[&str],
    extra: &[(&str, &str)],
) -> std::io::Result<std::process::Output> {
    rf_output_env_timeout(socket, args, extra, CLI_TIMEOUT)
}

fn rf_output_env_timeout(
    socket: &Path,
    args: &[&str],
    extra: &[(&str, &str)],
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let mut command = Command::new(rf_bin());
    command.arg("--socket").arg(socket).args(args);
    for (key, value) in extra {
        command.env(key, value);
    }
    proc::run_group_output(&mut command, timeout)
        .map_err(|error| std::io::Error::other(error.to_string()))
}

fn pty_account_create(socket: &Path, display_name: &str, passphrase: &str) -> Result<Value> {
    let rf = rf_bin();
    let socket_text = socket.to_str().ok_or("socket path")?;
    let inner = [
        rf.to_str().ok_or("rf path")?,
        "--socket",
        socket_text,
        "account",
        "create",
        "--display-name",
        display_name,
    ];
    let mut command = Command::new("script");
    if cfg!(target_os = "linux") {
        command.args(["-q", "-e", "-f", "-c", &shell_join(&inner), "/dev/null"]);
    } else {
        command.arg("-q").arg("/dev/null").args(inner);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("TERM", "xterm");
    let mut session = PtySession::spawn(&mut command)?;
    session.drive_account_create(passphrase, CEREMONY_TIMEOUT)
}

struct PtySession {
    group: proc::ProcessGroup,
    stdin: Option<std::process::ChildStdin>,
    output: Arc<Mutex<String>>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

impl PtySession {
    fn spawn(command: &mut Command) -> Result<Self> {
        let mut group = proc::ProcessGroup::spawn(command)?;
        let child = group.child_mut().ok_or("pty child")?;
        let stdin = child.stdin.take().ok_or("pty stdin")?;
        let stdout = child.stdout.take().ok_or("pty stdout")?;
        let stderr = child.stderr.take().ok_or("pty stderr")?;
        let output = Arc::new(Mutex::new(String::new()));
        let readers = vec![
            proc::drain_pipe(stdout, Arc::clone(&output)),
            proc::drain_pipe(stderr, Arc::clone(&output)),
        ];
        Ok(Self { group, stdin: Some(stdin), output, readers })
    }

    fn drive_account_create(&mut self, passphrase: &str, budget: Duration) -> Result<Value> {
        let deadline = Instant::now() + budget;
        let mut cursor = 0;
        cursor = wait_buffer_until(
            &self.output,
            "Press Enter after saving the words to hide them:",
            cursor,
            deadline,
        )?;
        let phrase = recovery_phrase(&lock_buf(&self.output))?;
        self.write_line("")?;
        for _ in 0..3 {
            cursor = wait_buffer_until(&self.output, "Recovery word ", cursor, deadline)?;
            let prompt =
                lock_buf(&self.output)[cursor.saturating_sub("Recovery word ".len())..].to_owned();
            let position = recovery_position(&prompt)?;
            let word = phrase.get(position.wrapping_sub(1)).ok_or("challenge position")?;
            self.write_line(word)?;
        }
        cursor = wait_buffer_until(
            &self.output,
            "New local data passphrase (hidden):",
            cursor,
            deadline,
        )?;
        self.write_line(passphrase)?;
        cursor = wait_buffer_until(
            &self.output,
            "Repeat local data passphrase (hidden):",
            cursor,
            deadline,
        )?;
        self.write_line(passphrase)?;
        let _ = wait_buffer_until(&self.output, "\"account_id\"", cursor, deadline)?;
        drop(self.stdin.take());
        let status = self.wait_exit(deadline)?;
        let buffer = lock_buf(&self.output).clone();
        if !status.success() {
            return Err(format!("account create exited {status}: {buffer}").into());
        }
        parse_json_object(&buffer)
    }

    fn write_line(&mut self, line: &str) -> Result<()> {
        let stdin = self.stdin.as_mut().ok_or("pty stdin closed")?;
        stdin.write_all(line.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        Ok(())
    }

    fn wait_exit(&mut self, deadline: Instant) -> Result<std::process::ExitStatus> {
        loop {
            self.group.track_descendants();
            if let Some(status) = self.group.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.group.kill_group();
                let _ = self.group.wait();
                return Err("pty session exceeded its budget".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        drop(self.stdin.take());
        self.group.kill_group();
        let _ = self.group.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn lock_buf(output: &Arc<Mutex<String>>) -> std::sync::MutexGuard<'_, String> {
    output.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn wait_buffer(output: &Arc<Mutex<String>>, needle: &str, from: usize) -> Result<usize> {
    wait_buffer_until(output, needle, from, Instant::now() + CEREMONY_TIMEOUT)
}

fn wait_buffer_until(
    output: &Arc<Mutex<String>>,
    needle: &str,
    from: usize,
    deadline: Instant,
) -> Result<usize> {
    loop {
        {
            let buffer = lock_buf(output);
            if let Some(index) = buffer.get(from..).and_then(|slice| slice.find(needle)) {
                return Ok(from + index + needle.len());
            }
        }
        if Instant::now() >= deadline {
            let buffer = lock_buf(output);
            return Err(
                format!("timeout waiting for {needle:?} in ceremony output: {buffer}").into()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn recovery_phrase(buffer: &str) -> Result<Vec<String>> {
    const MARK: &str = "Write down these 24 recovery words and keep them private.";
    let rest = buffer.split(MARK).nth(1).ok_or("ceremony did not show the recovery phrase")?;
    for line in rest.lines() {
        let cleaned = strip_ansi(line);
        let words: Vec<String> =
            cleaned.split_whitespace().map(str::to_owned).filter(|word| !word.is_empty()).collect();
        if words.len() == 24
            && words.iter().all(|word| word.chars().all(|ch| ch.is_ascii_lowercase()))
        {
            return Ok(words);
        }
    }
    Err("could not parse the 24-word recovery phrase from the PTY".into())
}

fn recovery_position(prompt: &str) -> Result<usize> {
    let cleaned = strip_ansi(prompt);
    let digits: String = cleaned
        .trim_start_matches("Recovery word ")
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let position: usize = digits.parse()?;
    if (1..=24).contains(&position) {
        Ok(position)
    } else {
        Err(format!("invalid recovery word position {position}").into())
    }
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if ch != '\r' {
            out.push(ch);
        }
    }
    out
}

fn parse_json_object(buffer: &str) -> Result<Value> {
    let idx = buffer.find('{').ok_or("no JSON object in CLI output")?;
    let mut deserializer = serde_json::Deserializer::from_str(&buffer[idx..]);
    Value::deserialize(&mut deserializer).map_err(|error| format!("JSON parse: {error}").into())
}

fn required_str(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing {key} in {value}").into())
}

fn shell_join(args: &[&str]) -> String {
    args.iter()
        .map(|arg| {
            if arg.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'=')
            }) {
                (*arg).to_owned()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn rf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rf"))
}

fn sibling_bin(name: &str) -> Result<PathBuf> {
    let path = rf_bin().parent().ok_or("rf parent")?.join(name);
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "missing {name} next to {}; cargo build -p {name} into this target dir first",
            rf_bin().display()
        )
        .into())
    }
}

fn free_tcp_addr() -> std::io::Result<String> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.to_string())
}

fn free_udp_addr() -> std::io::Result<String> {
    Ok(UdpSocket::bind("127.0.0.1:0")?.local_addr()?.to_string())
}

fn assert_discovery_addr(record: &Value, key: &str, expected: &str) -> Result<()> {
    let advertised = record
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("discovery missing {key}"))?;
    if advertised == expected {
        Ok(())
    } else {
        Err(format!("discovery {key} {advertised} != {expected}").into())
    }
}

fn probe_gateway_tls(ca: &Path, addr: &str) -> Result<()> {
    let ca = ca.to_str().ok_or("ca path")?;
    let mut command = Command::new("openssl");
    command.args([
        "s_client",
        "-connect",
        addr,
        "-servername",
        "localhost",
        "-CAfile",
        ca,
        "-brief",
    ]);
    let output = proc::run_group_output(&mut command, Duration::from_secs(5))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let verified = text.contains("Verify return code: 0")
        || text.contains("Verification: OK")
        || text.contains("Verify return code: 0 (ok)");
    if verified {
        Ok(())
    } else {
        Err(format!("openssl s_client {addr} did not verify: {text}").into())
    }
}

fn write_seed_file(path: &Path, seed: &[u8; 32]) -> Result<()> {
    std::fs::write(path, ramflux_protocol::encode_base64url(seed))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn openssl(args: &[&str]) -> Result<()> {
    let mut command = Command::new("openssl");
    command.args(args);
    let output = proc::run_group_output(&mut command, CLI_TIMEOUT)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("openssl failed: {}", String::from_utf8_lossy(&output.stderr)).into())
    }
}

fn create_ca(root: &Path) -> Result<()> {
    let certs = root.join("certs");
    std::fs::write(
        certs.join("ca.cnf"),
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=CliE2eCA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",
    )?;
    openssl(&[
        "req",
        "-x509",
        "-config",
        certs.join("ca.cnf").to_str().ok_or("ca cnf")?,
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-subj",
        "/CN=CliE2eCA",
        "-days",
        "1",
        "-keyout",
        certs.join("ca.key").to_str().ok_or("ca key")?,
        "-out",
        certs.join("ca.pem").to_str().ok_or("ca pem")?,
    ])
}

fn issue_service_cert(root: &Path, service: &str) -> Result<()> {
    let certs = root.join("certs");
    let key = certs.join(format!("{service}.key"));
    let csr = certs.join(format!("{service}.csr"));
    let cert = certs.join(format!("{service}.pem"));
    let ext = certs.join(format!("{service}.ext"));
    let spiffe =
        if service == "ramflux-gateway" { "ramflux-gateway/ramflux-gateway" } else { service };
    std::fs::write(
        &ext,
        format!(
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{service},DNS:localhost,IP:127.0.0.1,URI:spiffe://localhost/{spiffe}\n"
        ),
    )?;
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        &format!("/CN={service}"),
        "-keyout",
        key.to_str().ok_or("key")?,
        "-out",
        csr.to_str().ok_or("csr")?,
    ])?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        csr.to_str().ok_or("csr")?,
        "-CA",
        certs.join("ca.pem").to_str().ok_or("ca")?,
        "-CAkey",
        certs.join("ca.key").to_str().ok_or("ca key")?,
        "-CAcreateserial",
        "-sha256",
        "-days",
        "1",
        "-extfile",
        ext.to_str().ok_or("ext")?,
        "-out",
        cert.to_str().ok_or("cert")?,
    ])
}

fn write_service_toml(
    root: &Path,
    service: &str,
    listen: &str,
    mesh: &[String],
    gateway_public: &str,
) -> Result<()> {
    let certs = root.join("certs");
    let database = root.join("state").join(service).join(format!("{service}.redb"));
    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let endpoints = format!(
        "gateway = \"{}\"\nrouter = \"{}\"\nnotify = \"{}\"\nfederation = \"{}\"\nrelay = \"{}\"\nsignaling = \"{}\"\nretention = \"{}\"",
        mesh[3], mesh[1], mesh[1], mesh[0], mesh[1], mesh[1], mesh[2]
    );
    std::fs::write(
        certs.join(format!("{service}.toml")),
        format!(
            r#"node_id = "{NODE_ID}"
service_id = "{service}"
redb_path = "{}"
node_service_signing_seed_b64url = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio"

[mesh]
listen_addr = "{listen}"
ca_cert = "{}"
service_cert = "{}"
service_key = "{}"
allowed_service_ids = ["ramflux-gateway", "ramflux-relay", "ramflux-router", "ramflux-retention", "ramflux-federation", "ramflux-notify", "ramflux-signaling"]

[mesh.endpoints]
{endpoints}

[gateway]
public_listen_addr = "{gateway_public}"

[signaling]
turn_udp_addr = "127.0.0.1:0"
turn_tcp_addr = "127.0.0.1:0"
"#,
            database.display(),
            certs.join("ca.pem").display(),
            certs.join(format!("{service}.pem")).display(),
            certs.join(format!("{service}.key")).display(),
        ),
    )?;
    Ok(())
}

fn wait_for_log_markers(path: &Path, markers: &[&str], timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if markers.iter().all(|marker| text.contains(marker)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                format!("startup exceeded timeout; still waiting for {markers:?}: {text}").into()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Harness proof: a hung CLI child is killed and reaped inside `budget`.
pub fn prove_hung_command_reaped_within(budget: Duration) -> Result<()> {
    let mut command = Command::new("sleep");
    command.arg("60");
    let started = Instant::now();
    match proc::run_group_output(&mut command, Duration::from_millis(300)) {
        Err(error) if error.to_string().contains("timed out") => {}
        Ok(output) => {
            return Err(format!("hung command exited {}", output.status).into());
        }
        Err(error) => return Err(error),
    }
    if started.elapsed() > budget {
        return Err("hung command cleanup exceeded budget".into());
    }
    Ok(())
}

/// Harness proof: a PTY ceremony that never answers returns inside `budget` with no leftovers.
///
/// Linux `script -c` puts the command in a new session. Cleanup must reap that
/// descendant, including a child that ignores SIGHUP.
pub fn prove_failed_ceremony_reaped_within(budget: Duration) -> Result<()> {
    let inner = r#"trap "" HUP; sleep 60"#;
    let mut command = Command::new("script");
    if cfg!(target_os = "linux") {
        command.args(["-q", "-e", "-f", "-c", inner, "/dev/null"]);
    } else {
        command.arg("-q").arg("/dev/null").arg("sh").arg("-c").arg(inner);
    }
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut session = PtySession::spawn(&mut command)?;
    let pid = session.group.id();
    let started = Instant::now();
    let descendants_deadline = Instant::now() + Duration::from_millis(800);
    while session.group.tracked_pids().is_empty() && Instant::now() < descendants_deadline {
        session.group.track_descendants();
        std::thread::sleep(Duration::from_millis(20));
    }
    let timed_out = wait_buffer_until(
        &session.output,
        "this prompt never appears",
        0,
        Instant::now() + Duration::from_millis(400),
    )
    .is_err();
    session.group.track_descendants();
    let descendants: Vec<u32> = session.group.tracked_pids().to_vec();
    if cfg!(target_os = "linux") && descendants.is_empty() {
        drop(session);
        return Err("PTY command produced no descendants to reap".into());
    }
    drop(session);
    proc::wait_process_group_gone(pid, budget)?;
    for descendant in descendants {
        proc::wait_process_gone(descendant, budget)?;
    }
    if !timed_out {
        return Err("failed ceremony produced a prompt".into());
    }
    if started.elapsed() > budget {
        return Err("failed ceremony cleanup exceeded budget".into());
    }
    Ok(())
}

/// Harness proof: Drop still kills remaining group members after the leader exits.
pub fn prove_orphaned_group_members_reaped_within(budget: Duration) -> Result<()> {
    let mut command = Command::new("sh");
    command.args(["-c", r#"trap "" HUP; sleep 60"#]);
    let mut group = proc::ProcessGroup::spawn(&mut command)?;
    let leader = group.id();
    let started = Instant::now();
    let descendants_deadline = Instant::now() + Duration::from_millis(800);
    while group.tracked_pids().is_empty() && Instant::now() < descendants_deadline {
        group.track_descendants();
        std::thread::sleep(Duration::from_millis(20));
    }
    let descendants: Vec<u32> = group.tracked_pids().to_vec();
    if descendants.is_empty() {
        drop(group);
        return Err("orphaned-member fixture produced no descendants".into());
    }
    if let Some(pid) = rustix::process::Pid::from_raw(leader.cast_signed()) {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    }
    let leader_deadline = Instant::now() + budget;
    loop {
        if group.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= leader_deadline {
            drop(group);
            return Err("orphaned-member leader did not exit".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(group);
    for descendant in descendants {
        proc::wait_process_gone(descendant, budget)?;
    }
    if started.elapsed() > budget {
        return Err("orphaned group member cleanup exceeded budget".into());
    }
    Ok(())
}

/// Harness proof: Drop of an unresponsive daemon returns inside `budget` with no leftovers.
pub fn prove_unresponsive_daemon_drop_within(budget: Duration) -> Result<()> {
    let root = std::env::temp_dir().join(format!(
        "rf-cli-e2e-hung-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&root)?;
    let socket = root.join("hung.sock");
    let data_root = root.join("data");
    std::fs::create_dir_all(&data_root)?;
    let mut command = Command::new("sleep");
    command.arg("60");
    let child = ChildGuard::spawn("hung-daemon".into(), command, data_root.join("daemon.log"))?;
    let pid = child.pid();
    let daemon = Daemon { socket, data_root, child };
    let started = Instant::now();
    drop(daemon);
    let gone = proc::wait_process_group_gone(pid, budget);
    let _ = std::fs::remove_dir_all(&root);
    gone?;
    if started.elapsed() > budget {
        return Err("unresponsive daemon drop exceeded budget".into());
    }
    Ok(())
}
