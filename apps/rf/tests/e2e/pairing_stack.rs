// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A stack whose node serves device pairing over HTTPS, and two real `rf` daemons paired into one
//! account through the command line only (AGENT-CLI-E2E-01). Pairing is HTTPS-only, so a small TLS
//! front terminates the stack's own test CA in front of the node's public HTTP surface, the way a
//! reverse proxy does on a deployed node; the daemons trust that CA through the integration-build
//! seam `RAMFLUX_ITEST_PAIRING_CA_FILE`. Everything after that is the shipped `rf pairing` surface.
#![cfg(unix)]

use super::{
    Account, Daemon, PASSPHRASE, PtySession, Result, Stack, boot_pairing_stack, lock_buf,
    parse_json_object, rf_bin, rf_json, rf_json_timeout, shell_join, spawn_daemon_with_env,
    unlock_account, wait_networking_live,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const PAIR_CALL: Duration = Duration::from_secs(30);
const PAIR_POLL: Duration = Duration::from_secs(90);
/// Largest request and reply the front relays; the pairing exchanges stay far below it.
const FRONT_CAP: usize = 512 * 1024;
const HEADER_CAP: usize = 16 * 1024;

/// The stack plus the TLS front in front of its pairing surface.
pub struct PairingStack {
    pub stack: Stack,
    _front: TlsFront,
}

struct TlsFront {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for TlsFront {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Boots the ordinary stack with pairing on and a TLS front for its public origin.
/// # Errors
/// Returns configuration, certificate or child-process failures.
pub fn boot_agent_stack() -> Result<PairingStack> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let origin = format!("https://localhost:{}", listener.local_addr()?.port());
    let stack = boot_pairing_stack(&[
        ("RAMFLUX_DEVICE_PAIRING_ENABLED", "1"),
        ("RAMFLUX_FEDERATION_TRUSTED_PROXIES", "127.0.0.1"),
        ("RAMFLUX_FEDERATION_PUBLIC_ORIGIN", origin.as_str()),
    ])?;
    let backend: SocketAddr = stack
        .discovery_url
        .strip_prefix("http://")
        .ok_or("the federation public surface is plain HTTP behind the front")?
        .parse()?;
    let config = server_config(
        &stack.root.join("certs/ramflux-federation.pem"),
        &stack.root.join("certs/ramflux-federation.key"),
    )?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || serve(&listener, backend, &config, &worker_stop));
    let ready = PairingStack { stack, _front: TlsFront { stop, thread: Some(thread) } };
    probe_front(&ready, &origin)?;
    Ok(ready)
}

/// The front must serve the node's health route over HTTPS to a client that trusts only the stack's
/// test CA, as the daemons do. A failure here names the front, not the pairing ceremony.
fn probe_front(stack: &PairingStack, origin: &str) -> Result<()> {
    let host = origin.strip_prefix("https://").ok_or("origin")?;
    let ca = stack.stack.root.join("certs/ca.pem");
    let mut command = Command::new("openssl");
    command
        .args(["s_client", "-connect", host, "-servername", "localhost", "-CAfile"])
        .arg(&ca)
        .args(["-verify_return_error", "-verify_hostname", "localhost", "-quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .ok_or("openssl stdin")?
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let output = child.wait_with_output()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    if !text.contains("HTTP/1.1 200") {
        return Err(format!("the TLS front does not serve /healthz at {origin}: {text}").into());
    }
    Ok(())
}

fn server_config(cert: &Path, key: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let mut cert_pem = std::io::BufReader::new(std::fs::File::open(cert)?);
    let mut key_pem = std::io::BufReader::new(std::fs::File::open(key)?);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = rustls_pemfile::certs(&mut cert_pem).collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem)?.ok_or("the federation key is missing")?;
    Ok(Arc::new(
        rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?,
    ))
}

fn serve(
    listener: &TcpListener,
    backend: SocketAddr,
    config: &Arc<rustls::ServerConfig>,
    stop: &AtomicBool,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((tcp, peer)) => {
                let config = Arc::clone(config);
                // One short-lived thread per request: the two daemons poll at the same time.
                std::thread::spawn(move || {
                    if let Err(error) = relay_one(tcp, peer, backend, &config) {
                        eprintln!("test: TLS front request refused: {error}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn relay_one(
    mut tcp: TcpStream,
    peer: SocketAddr,
    backend: SocketAddr,
    config: &Arc<rustls::ServerConfig>,
) -> Result<()> {
    tcp.set_nonblocking(false)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut connection = rustls::ServerConnection::new(Arc::clone(config))?;
    let mut tls = rustls::Stream::new(&mut connection, &mut tcp);
    let (head, body) = read_request(&mut tls)?;
    let mut upstream = TcpStream::connect_timeout(&backend, Duration::from_secs(5))?;
    upstream.set_read_timeout(Some(Duration::from_secs(10)))?;
    upstream.set_write_timeout(Some(Duration::from_secs(10)))?;
    upstream.write_all(&forwarded(&head, &body, peer)?)?;
    let mut reply = Vec::new();
    upstream.take(FRONT_CAP as u64 + 1).read_to_end(&mut reply)?;
    if reply.len() > FRONT_CAP {
        return Err("the upstream reply exceeds the front cap".into());
    }
    tls.write_all(&reply)?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

/// The request head and body as read from the TLS side, bounded.
fn read_request(tls: &mut impl Read) -> Result<(String, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 1024];
    let split = loop {
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break at;
        }
        let read = tls.read(&mut buffer)?;
        if read == 0 || raw.len() > HEADER_CAP {
            return Err("the request head is incomplete or too large".into());
        }
        raw.extend_from_slice(buffer.get(..read).ok_or("read bound")?);
    };
    let head = String::from_utf8(raw.get(..split).ok_or("head bound")?.to_vec())?;
    let length: usize = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse())
        .transpose()?
        .unwrap_or(0);
    if length > FRONT_CAP {
        return Err("the request body exceeds the front cap".into());
    }
    let mut body = raw.get(split + 4..).ok_or("body bound")?.to_vec();
    while body.len() < length {
        let read = tls.read(&mut buffer)?;
        if read == 0 {
            return Err("the request body is short".into());
        }
        body.extend_from_slice(buffer.get(..read).ok_or("read bound")?);
    }
    body.truncate(length);
    Ok((head, body))
}

/// The request as the trusted proxy sends it upstream: the request line, the headers the pairing
/// routes use, the forwarded scheme and client address, and the body.
fn forwarded(head: &str, body: &[u8], peer: SocketAddr) -> Result<Vec<u8>> {
    let mut lines = head.lines();
    let request_line = lines.next().ok_or("the request line is missing")?;
    let mut out = format!(
        "{request_line}\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: {}\r\n",
        body.len(),
        peer.ip()
    )
    .into_bytes();
    for line in lines {
        if let Some((name, _)) = line.split_once(':')
            && ["authorization", "content-type", "x-ramflux-pairing-arm"]
                .iter()
                .any(|allowed| name.eq_ignore_ascii_case(allowed))
        {
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Ok(out)
}

/// Starts a daemon that trusts the stack's test CA for pairing (integration builds only).
/// # Errors
/// Returns the spawn failure.
pub fn start_pairing_daemon(stack: &PairingStack, name: &str) -> Result<Daemon> {
    let data_root = stack.stack.root.join(format!("daemon-{name}"));
    // The pairing file registry lives beside the socket and is keyed by operation: each daemon gets
    // its own directory, as two machines would have (a shared one makes the second role collide).
    let socket_dir = stack.stack.root.join(format!("sock-{name}"));
    std::fs::create_dir_all(&socket_dir)?;
    let socket = socket_dir.join("rf.sock");
    let ca = stack.stack.root.join("certs/ca.pem");
    let ca = ca.to_str().ok_or("ca path")?.to_owned();
    spawn_daemon_with_env(
        socket,
        data_root,
        &[("RAMFLUX_ITEST_PAIRING_CA_FILE", ca.as_str()), ("RUST_LOG", "info,ramflux_sdk=debug")],
    )
}

/// The primary and the paired desktop of one human account, after a real pairing ceremony.
pub struct Pair {
    pub primary: Daemon,
    pub desktop: Daemon,
    pub account: Account,
}

fn text(value: &Value, pointer: &str) -> Result<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing {pointer} in {value}").into())
}

/// `value.outcome.value` when present (pairing status and join replies nest it), else `value`.
fn nested(value: &Value) -> &Value {
    value.pointer("/outcome/value").unwrap_or(value)
}

/// Pairs a second daemon into the account of `primary` with the `rf pairing` commands only: begin,
/// join (a pseudo-terminal, for the new local passphrase), the seven-name check on both sides,
/// confirm on both, approve on the primary, completion on both, and the joiner's unlock.
/// # Errors
/// Returns the first failing step with the command output.
pub fn pair_devices(
    stack: &PairingStack,
    primary: Daemon,
    account: &Account,
    desktop_name: &str,
) -> Result<Pair> {
    match pair_inner(stack, &primary, account, desktop_name) {
        Ok((desktop, joined)) => Ok(Pair { primary, desktop, account: joined }),
        Err(error) => {
            Err(format!("{error}; logs={}", super::dump_logs(&stack.stack, &[&primary])).into())
        }
    }
}

fn pair_inner(
    stack: &PairingStack,
    primary: &Daemon,
    account: &Account,
    desktop_name: &str,
) -> Result<(Daemon, Account)> {
    let desktop = start_pairing_daemon(stack, desktop_name)?;
    super::configure_node(&desktop, &stack.stack.discovery_url)?;
    match pair_steps(stack, primary, &desktop, account, desktop_name) {
        Ok(joined) => Ok((desktop, joined)),
        Err(error) => {
            Err(format!("{error}; desktop log={}", super::dump_logs(&stack.stack, &[&desktop]))
                .into())
        }
    }
}

/// `rf pairing begin` on the primary, once its layer declaration is fresh; a refused proof is
/// retried a bounded number of times (see `wait_layer_declaration_fresh`).
fn begin_invitation(primary: &Daemon, id: &str, invitation: &Path) -> Result<Value> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let (now_text, until_text) = (now.to_string(), (now + 3600).to_string());
    wait_layer_declaration_fresh(primary, id)?;
    let begin_args = [
        "pairing",
        "--account",
        id,
        "begin",
        "--display-name",
        "agent-e2e-pairing",
        "--lease-not-before",
        &now_text,
        "--lease-expires-at",
        &until_text,
        "--invitation-out",
        invitation.to_str().ok_or("invitation path")?,
    ];
    // A brand-new account's directory head can still be changing when the first proof is made; the
    // node then refuses that one proof (BindingRefused) and a fresh attempt passes. Bound the retries.
    let mut attempt = 0;
    let begun = loop {
        match rf_json_timeout(&primary.socket, &begin_args, PAIR_CALL) {
            Ok(reply) => break reply,
            Err(error) if attempt < 5 && error.to_string().contains("BindingRefused") => {
                attempt += 1;
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(error) => return Err(format!("pairing begin on the primary: {error}").into()),
        }
    };
    Ok(begun)
}

/// `rf pairing approve` on the primary. The proposal can be reported a moment before the
/// coordinator accepts the approval; a refusal before it is ready is a plain `NotFound`, so that one
/// case is retried a bounded number of times.
fn approve_when_ready(primary: &Daemon, approve_args: &[&str]) -> Result<()> {
    let mut tries = 0;
    loop {
        match rf_json_timeout(&primary.socket, approve_args, PAIR_CALL) {
            Ok(_) => return Ok(()),
            Err(error) if tries < 8 && error.to_string().contains("ValidationFailed") => {
                tries += 1;
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(error) => return Err(format!("pairing approve: {error}").into()),
        }
    }
}

/// `rf pairing confirm` of one side, with the other side's code file as the attended peer proof.
fn confirm_pairing(
    daemon: &Daemon,
    id: &str,
    (op, generation, transcript): (&str, &str, &str),
    peer: &Path,
) -> Result<()> {
    rf_json_timeout(
        &daemon.socket,
        &[
            "pairing",
            "--account",
            id,
            "confirm",
            "--operation-id",
            op,
            "--generation",
            generation,
            "--transcript-hash",
            transcript,
            "--matches",
            "true",
            "--peer-sas-file",
            peer.to_str().ok_or("peer path")?,
            "--peer-sas-attended",
        ],
        PAIR_CALL,
    )
    .map_err(|error| format!("pairing confirm: {error}"))?;
    Ok(())
}

fn pair_steps(
    stack: &PairingStack,
    primary: &Daemon,
    desktop: &Daemon,
    account: &Account,
    desktop_name: &str,
) -> Result<Account> {
    let dir = stack.stack.root.join(format!("pair-{desktop_name}"));
    std::fs::create_dir_all(&dir)?;
    let invitation = dir.join("invitation.json");
    let id = account.id.as_str();
    let begun = begin_invitation(primary, id, &invitation)?;
    let op_primary = text(nested(&begun), "/operation_id")?;
    let generation_primary = nested(&begun)
        .pointer("/generation")
        .map(Value::to_string)
        .ok_or("begin reply has no generation")?;
    let joined = pty_pairing_join(&desktop.socket, id, &invitation, &dir.join("join-sas.json"))?;
    let op_desktop = text(nested(&joined), "/operation_id")?;
    let generation_desktop = nested(&joined)
        .pointer("/generation")
        .map(Value::to_string)
        .ok_or("join reply has no generation")?;

    let sas_primary = dir.join("sas-primary.json");
    let sas_desktop = dir.join("sas-desktop.json");
    poll_sas(primary, id, &op_primary, &generation_primary, &sas_primary)?;
    poll_sas(desktop, id, &op_desktop, &generation_desktop, &sas_desktop)?;
    let names = |path: &Path| -> Result<(Value, String)> {
        let value = parse_json_object(&std::fs::read_to_string(path)?)?;
        let transcript = text(&value, "/transcript_hash")?;
        Ok((value.get("names").cloned().unwrap_or(Value::Null), transcript))
    };
    let (names_primary, transcript_primary) = names(&sas_primary)?;
    let (names_desktop, transcript_desktop) = names(&sas_desktop)?;
    if names_primary != names_desktop || transcript_primary != transcript_desktop {
        return Err("the two devices do not show the same seven names and transcript".into());
    }
    let peer_for_primary = dir.join("peer-for-primary.json");
    let peer_for_desktop = dir.join("peer-for-desktop.json");
    std::fs::copy(&sas_desktop, &peer_for_primary)?;
    std::fs::copy(&sas_primary, &peer_for_desktop)?;
    for (daemon, op, generation, transcript, peer) in [
        (primary, &op_primary, &generation_primary, &transcript_primary, &peer_for_primary),
        (desktop, &op_desktop, &generation_desktop, &transcript_desktop, &peer_for_desktop),
    ] {
        confirm_pairing(daemon, id, (op, generation, transcript), peer)?;
    }
    let proposal = poll_status(primary, id, &op_primary, &generation_primary, |value| {
        nested(value)
            .get("proposal_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| !hash.is_empty())
    })?;
    let proposal_hash = text(nested(&proposal), "/proposal_hash")?;
    let approve_args = [
        "pairing",
        "--account",
        id,
        "approve",
        "--operation-id",
        &op_primary,
        "--generation",
        &generation_primary,
        "--transcript-hash",
        &transcript_primary,
        "--proposal-hash",
        &proposal_hash,
        "--approved",
        "true",
    ];
    approve_when_ready(primary, &approve_args)?;
    for (daemon, op, generation) in
        [(primary, &op_primary, &generation_primary), (desktop, &op_desktop, &generation_desktop)]
    {
        poll_status(daemon, id, op, generation, |value| {
            nested(value).get("phase").and_then(Value::as_str) == Some("completed")
        })?;
    }
    // The joiner holds the same account id as the primary; it unlocks with its own passphrase.
    let joined_account = Account {
        id: account.id.clone(),
        display_name: account.display_name.clone(),
        principal_id: account.principal_id.clone(),
        principal_commitment: account.principal_commitment.clone(),
        device_id: String::new(),
        target_delivery_id: String::new(),
    };
    unlock_account(desktop, &joined_account)?;
    wait_networking_live(desktop, &account.id)?;
    Ok(joined_account)
}

fn poll_sas(daemon: &Daemon, id: &str, op: &str, generation: &str, out: &Path) -> Result<()> {
    let deadline = Instant::now() + PAIR_POLL;
    let mut attempt = 0_u32;
    while Instant::now() < deadline {
        attempt += 1;
        let candidate = daemon.data_root.join(format!("names-{op}-{attempt}.sas.json"));
        let candidate_text = candidate.to_str().ok_or("sas path")?;
        let _ = rf_json_timeout(
            &daemon.socket,
            &[
                "pairing",
                "--account",
                id,
                "--sas-out",
                candidate_text,
                "status",
                "--operation-id",
                op,
                "--generation",
                generation,
            ],
            PAIR_CALL,
        );
        if std::fs::metadata(&candidate).is_ok_and(|meta| meta.len() > 0) {
            std::fs::copy(&candidate, out)?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!("the seven names never appeared for {}", daemon.socket.display()).into())
}

fn poll_status(
    daemon: &Daemon,
    id: &str,
    op: &str,
    generation: &str,
    ready: impl Fn(&Value) -> bool,
) -> Result<Value> {
    let deadline = Instant::now() + PAIR_POLL;
    let mut last = String::new();
    let mut attempt = 0_u32;
    while Instant::now() < deadline {
        // `status` always names a SAS output path (a new file each call; the file stays empty
        // unless the names are available).
        attempt += 1;
        let sas = daemon.data_root.join(format!("status-{op}-{attempt}.sas.json"));
        let sas_text = sas.to_str().ok_or("sas path")?;
        match rf_json_timeout(
            &daemon.socket,
            &[
                "pairing",
                "--account",
                id,
                "--sas-out",
                sas_text,
                "status",
                "--operation-id",
                op,
                "--generation",
                generation,
            ],
            PAIR_CALL,
        ) {
            Ok(value) if ready(&value) => return Ok(value),
            Ok(value) => last = value.to_string(),
            Err(error) => last = error.to_string(),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "pairing status on {} never reached the awaited state; last={last}",
        daemon.socket.display()
    )
    .into())
}

/// `rf pairing join` needs a terminal: it asks twice for the new local data passphrase.
fn pty_pairing_join(socket: &Path, id: &str, invitation: &Path, sas_out: &Path) -> Result<Value> {
    let rf = rf_bin();
    let socket_text = socket.to_str().ok_or("socket path")?;
    let inner = [
        rf.to_str().ok_or("rf path")?,
        "--socket",
        socket_text,
        "pairing",
        "--account",
        id,
        "--sas-out",
        sas_out.to_str().ok_or("sas path")?,
        "join",
        "--display-name",
        "agent-e2e-desktop",
        "--invitation-file",
        invitation.to_str().ok_or("invitation path")?,
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
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut cursor = session.wait_until("New local data passphrase (hidden):", 0, deadline)?;
    session.write_line(PASSPHRASE)?;
    cursor = session.wait_until("Repeat local data passphrase (hidden):", cursor, deadline)?;
    session.write_line(PASSPHRASE)?;
    drop(session.stdin.take());
    let status = session.wait_exit(deadline)?;
    let output = lock_buf(&session.output).clone();
    let _ = cursor;
    if !status.success() {
        return Err(format!("pairing join exited {status}: {output}").into());
    }
    // The transcript holds the two prompts, then one JSON reply.
    let start = output.find('{').ok_or("the join printed no reply")?;
    parse_json_object(output.get(start..).ok_or("join reply bound")?)
}

/// One bounded `GET` of the node's public HTTP surface, body as text.
/// # Errors
/// Returns connection, status or size failures.
pub fn node_get(stack: &Stack, path: &str) -> Result<String> {
    let host = stack.discovery_url.strip_prefix("http://").ok_or("discovery url")?;
    let mut stream = TcpStream::connect(host)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )?;
    let mut reply = Vec::new();
    stream.take(FRONT_CAP as u64 + 1).read_to_end(&mut reply)?;
    let text = String::from_utf8(reply)?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("malformed reply")?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!("GET {path} answered {}", head.lines().next().unwrap_or("")).into());
    }
    Ok(body.to_owned())
}

/// A new account republishes its directory head when its message-layer declaration lands. A
/// custody proof made against the earlier head is refused (`BindingRefused`), which is what a
/// daemon with one fresh account hits when it pairs at once. Pair once the declaration is fresh.
fn wait_layer_declaration_fresh(daemon: &Daemon, account_id: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = rf_json(&daemon.socket, &["account", "status", "--account", account_id])?;
        if status.pointer("/layer_declaration/state").and_then(Value::as_str) == Some("fresh") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("the layer declaration never became fresh: {status}").into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
