// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared boot for CLI e2e: mesh certs, four node processes, rf daemons, PTY create.
#![allow(dead_code)]

use serde::Deserialize as _;
use serde_json::Value;
use std::{
    io::{BufRead as _, Read, Write as _},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PASSPHRASE: &str = "cli-e2e-passphrase-ok";
const NODE_ID: &str = "localhost";
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);
const CEREMONY_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_TIMEOUT: Duration = Duration::from_secs(20);

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct ChildGuard {
    child: Child,
    name: String,
}

impl ChildGuard {
    fn spawn(name: String, mut command: Command) -> Result<Self> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = command.spawn().map_err(|error| format!("spawn {name}: {error}"))?;
        Ok(Self { child, name })
    }

    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        Ok(self.child.try_wait()?)
    }

    fn exited(&mut self) -> Result<bool> {
        Ok(self.try_wait()?.is_some())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub struct Stack {
    pub root: PathBuf,
    pub discovery_url: String,
    pub gateway_public: String,
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
    pub device_id: String,
    pub target_delivery_id: String,
}

impl Drop for Stack {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = rf_output(&self.socket, &["daemon", "stop"]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

pub fn boot_stack() -> Result<Stack> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("rf-cli-e2e-{}-{nonce}", std::process::id()));
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
    let gateway_public = free_tcp_addr()?;
    let public_addr = free_tcp_addr()?;
    let admin_addr = free_tcp_addr()?;
    let signing_seed = root.join("secrets").join("node-signing.key");
    write_seed_file(&signing_seed, &[0xA1; 32])?;
    let route_key = root.join("secrets").join("notify-route.key");
    write_seed_file(&route_key, &[0x11; 32])?;
    for (service, mesh_addr) in services.iter().zip(mesh.iter()) {
        write_service_toml(&root, service, mesh_addr, &mesh, &gateway_public)?;
    }
    let mut servers = Vec::new();
    let order = [
        ("ramflux-federation", federation_ready()),
        ("ramflux-router", &["router mesh mTLS surface listening"][..]),
        ("ramflux-retention", &["retention mesh mTLS surface listening"][..]),
        ("ramflux-gateway", &["gateway QUIC session surface listening"][..]),
    ];
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
            .env("RAMFLUX_CLIENT_GATEWAY_QUIC_ADDR", &gateway_public)
            .env("RAMFLUX_CLIENT_GATEWAY_TCP_ADDR", &gateway_public)
            .env("RAMFLUX_CLIENT_GATEWAY_SERVER_NAME", "ramflux-gateway")
            .env("RAMFLUX_FEDERATION_NODE_ID", NODE_ID)
            .env_remove("RAMFLUX_RELAY_CLIENT_QUIC_ADDR");
        let mut child = ChildGuard::spawn(service.to_owned(), command)?;
        let stdout = child.child.stdout.take().ok_or("missing stdout")?;
        let stderr_slot = child.child.stderr.take();
        if let Err(error) = wait_for_markers(stdout, markers, READY_TIMEOUT) {
            let mut logs = String::new();
            if let Some(mut stderr) = stderr_slot {
                let _ = stderr.read_to_string(&mut logs);
            }
            return Err(format!("{service} startup failed ({error}): {logs}").into());
        }
        servers.push(child);
    }
    Ok(Stack {
        root,
        discovery_url: format!("http://{public_addr}"),
        gateway_public,
        _servers: servers,
    })
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
    let mut command = Command::new(rf_bin());
    command
        .arg("--socket")
        .arg(&socket)
        .args(["daemon", "start", "--data-root"])
        .arg(&data_root)
        .arg("--itest-memory-vault")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = ChildGuard::spawn(format!("rf-{}", socket.display()), command)?;
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
        device_id: required_str(&status, "device_id")?,
        target_delivery_id: required_str(&status, "target_delivery_id")?,
    })
}

pub fn unlock_account(daemon: &Daemon, account: &Account) -> Result<Value> {
    rf_json_env(
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
    )
}

pub fn exchange_contacts(a: &Daemon, alice: &Account, b: &Daemon, bob: &Account) -> Result<()> {
    let alice_card = rf_json(&a.socket, &["contact", "card", "--account", &alice.id])?;
    let bob_card = rf_json(&b.socket, &["contact", "card", "--account", &bob.id])?;
    let alice_text = required_str(&alice_card, "card")?;
    let bob_text = required_str(&bob_card, "card")?;
    rf_json(&b.socket, &["contact", "add", "--account", &bob.id, "--card", &alice_text])?;
    rf_json(&a.socket, &["contact", "add", "--account", &alice.id, "--card", &bob_text])?;
    Ok(())
}

pub fn dm_send(
    daemon: &Daemon,
    sender: &Account,
    recipient: &Account,
    conversation: &str,
    message: &str,
    body: &str,
) -> Result<Value> {
    rf_json(
        &daemon.socket,
        &[
            "dm",
            "send",
            "--account",
            &sender.id,
            "--conversation",
            conversation,
            "--message",
            message,
            "--envelope",
            message,
            "--source-principal",
            &sender.principal_id,
            "--sender",
            &sender.device_id,
            "--target",
            &recipient.target_delivery_id,
            "--body",
            body,
        ],
    )
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
}

pub fn dm_ack(
    daemon: &Daemon,
    account: &Account,
    conversation: &str,
    message: &str,
) -> Result<Value> {
    rf_json(
        &daemon.socket,
        &[
            "dm",
            "ack",
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
    let mut args = vec![
        "group".to_owned(),
        "create".to_owned(),
        "--account".to_owned(),
        creator.id.clone(),
        "--group".to_owned(),
        group.to_owned(),
        "--creator".to_owned(),
        creator.device_id.clone(),
    ];
    for member in members {
        args.push("--member".to_owned());
        args.push(member.device_id.clone());
    }
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    rf_json(&daemon.socket, &borrowed)
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
            return Err(
                format!("account {account_id} networking did not become live: {status}").into()
            );
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

fn rf_output_env(
    socket: &Path,
    args: &[&str],
    extra: &[(&str, &str)],
) -> std::io::Result<std::process::Output> {
    let mut command = Command::new(rf_bin());
    command.arg("--socket").arg(socket).args(args);
    for (key, value) in extra {
        command.env(key, value);
    }
    command.output()
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
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or("pty stdin")?;
    let stdout = child.stdout.take().ok_or("pty stdout")?;
    let output = Arc::new(Mutex::new(String::new()));
    let reader_out = Arc::clone(&output);
    let reader = std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut buf = [0_u8; 1024];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            if let Ok(chunk) = std::str::from_utf8(&buf[..n]) {
                lock_buf(&reader_out).push_str(chunk);
            }
        }
    });
    wait_buffer(&output, "Press Enter after saving the words to hide them:", CEREMONY_TIMEOUT)?;
    let phrase = recovery_phrase(&lock_buf(&output))?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    for _ in 0..3 {
        let prompt = wait_buffer(&output, "Recovery word ", CEREMONY_TIMEOUT)?;
        let position = recovery_position(&prompt)?;
        let word = phrase.get(position.wrapping_sub(1)).ok_or("challenge position")?;
        stdin.write_all(word.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
    }
    wait_buffer(&output, "New local data passphrase (hidden):", CEREMONY_TIMEOUT)?;
    stdin.write_all(passphrase.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    wait_buffer(&output, "Repeat local data passphrase (hidden):", CEREMONY_TIMEOUT)?;
    stdin.write_all(passphrase.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    wait_buffer(&output, "\"account_id\"", CEREMONY_TIMEOUT)?;
    drop(stdin);
    let status = child.wait()?;
    let _ = reader.join();
    let buffer = lock_buf(&output).clone();
    if !status.success() {
        return Err(format!("account create exited {status}: {buffer}").into());
    }
    parse_json_object(&buffer)
}

fn lock_buf(output: &Arc<Mutex<String>>) -> std::sync::MutexGuard<'_, String> {
    output.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn wait_buffer(output: &Arc<Mutex<String>>, needle: &str, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        {
            let buffer = lock_buf(output);
            if let Some(index) = buffer.find(needle) {
                return Ok(buffer[index..].to_owned());
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
    let idx = buffer.rfind('{').ok_or("no JSON object in CLI output")?;
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
    let output = Command::new("openssl").args(args).output()?;
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

fn wait_for_markers(
    stdout: impl Read + Send + 'static,
    markers: &[&str],
    timeout: Duration,
) -> Result<()> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let mut pending: Vec<&str> = markers.to_vec();
    let deadline = Instant::now() + timeout;
    while !pending.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!("startup exceeded timeout; still waiting for {pending:?}").into());
        }
        let line = receiver.recv_timeout(remaining)?;
        pending.retain(|marker| !line.contains(marker));
    }
    Ok(())
}
