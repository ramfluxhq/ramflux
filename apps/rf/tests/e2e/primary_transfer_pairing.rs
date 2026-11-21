// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attended CLI pairing on the existing node process stack and shared TLS front.
use super::{
    Account, CEREMONY_TIMEOUT, Daemon, PASSPHRASE, PtySession, Result, Stack, boot_pairing_stack,
    configure_node, pairing_tls, rf_bin, rf_json, shell_join, wait_json,
};
use serde_json::Value;
use std::{
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub struct Network {
    pub stack: Stack,
    _front: pairing_tls::TlsFront,
}

/// Each simulated device owns its CLI registry as well as its database and vault.
pub fn start_device(stack: &Stack, name: &str) -> Result<Daemon> {
    let root = stack.root.join(format!("daemon-{name}"));
    std::fs::create_dir_all(&root)?;
    super::spawn_daemon(root.join("cli.sock"), root)
}

impl Network {
    pub fn open() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let origin = format!("https://localhost:{}", listener.local_addr()?.port());
        let stack = boot_pairing_stack(&[
            ("RAMFLUX_DEVICE_PAIRING_ENABLED", "1"),
            ("RAMFLUX_FEDERATION_TRUSTED_PROXIES", "127.0.0.1"),
            ("RAMFLUX_FEDERATION_PUBLIC_ORIGIN", &origin),
        ])?;
        let config = pairing_tls::rustls_server_config(
            &stack.root.join("certs/ramflux-federation.pem"),
            &stack.root.join("certs/ramflux-federation.key"),
        )?;
        let backend = stack
            .discovery_url
            .strip_prefix("http://")
            .ok_or("federation HTTP backend")?
            .parse()?;
        let front = pairing_tls::spawn_tls_front(listener, backend, config)?;
        Ok(Self { stack, _front: front })
    }
}

/// Keep stdin attached until exit; the shared process group owns and reaps descendants.
pub fn attended(socket: &Path, args: &[&str], answers: &[(&str, &str)]) -> Result<Value> {
    let mut session = spawn_cli(socket, args)?;
    let deadline = Instant::now() + CEREMONY_TIMEOUT;
    let mut cursor = 0;
    for (prompt, answer) in answers {
        cursor = session.wait_until(prompt, cursor, deadline)?;
        session.write_line(answer)?;
    }
    if !session.wait_exit(deadline)?.success() {
        return Err("attended pairing CLI refused; no credential transcript is printed".into());
    }
    super::parse_json_object(&super::lock_buf(&session.output))
}

fn spawn_cli(socket: &Path, args: &[&str]) -> Result<PtySession> {
    let binary = rf_bin();
    let mut inner =
        vec![binary.to_str().ok_or("rf path")?, "--socket", socket.to_str().ok_or("socket path")?];
    inner.extend_from_slice(args);
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
    PtySession::spawn(&mut command)
}

/// Retain only this test-owned account's attended recovery phrase for B's later Prepare.
pub fn create_source(daemon: &Daemon) -> Result<(Account, zeroize::Zeroizing<String>)> {
    let mut session =
        spawn_cli(&daemon.socket, &["account", "create", "--display-name", "Transfer source"])?;
    let created = session.drive_account_create(PASSPHRASE, CEREMONY_TIMEOUT)?;
    let phrase = zeroize::Zeroizing::new(
        super::recovery_phrase(&super::lock_buf(&session.output))?.join(" "),
    );
    let id = super::required_str(&created, "account_id")?;
    super::wait_networking_live(daemon, &id)?;
    let status = rf_json(&daemon.socket, &["account", "status", "--account", &id])?;
    let account = Account {
        id,
        display_name: "Transfer source".into(),
        principal_id: super::required_str(&status, "principal_id")?,
        principal_commitment: super::required_str(&status, "principal_commitment")?,
        device_id: super::required_str(&status, "device_id")?,
        target_delivery_id: super::required_str(&status, "target_delivery_id")?,
    };
    Ok((account, phrase))
}

pub fn enroll(stack: &Stack, source: &Daemon, account: &Account) -> Result<(Daemon, Account)> {
    let target = start_device(stack, "transfer-target")?;
    configure_node(&target, &stack.discovery_url)?;
    let invitation = stack.root.join("enrollment.invitation");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let begin = rf_json(
        &source.socket,
        &[
            "pairing",
            "--account",
            &account.id,
            "begin",
            "--display-name",
            "Target phone",
            "--lease-not-before",
            &now.to_string(),
            "--lease-expires-at",
            &(now + 604_800).to_string(),
            "--invitation-out",
            invitation.to_str().ok_or("invitation path")?,
        ],
    )?;
    let operation = begin.get("operation_id").and_then(Value::as_str).ok_or("begin operation")?;
    let generation =
        begin.get("generation").and_then(Value::as_u64).ok_or("begin generation")?.to_string();
    let target_id = "transferred-account";
    eprintln!("native transfer seed: joining recipient");
    attended(
        &target.socket,
        &[
            "pairing",
            "--account",
            target_id,
            "join",
            "--display-name",
            "Target phone",
            "--invitation-file",
            invitation.to_str().ok_or("invitation path")?,
        ],
        &[
            ("New local data passphrase (hidden):", PASSPHRASE),
            ("Repeat local data passphrase (hidden):", PASSPHRASE),
        ],
    )
    .map_err(|error| format!("{error}; {}", super::dump_logs(stack, &[source, &target])))?;
    for (daemon, id) in [(source, account.id.as_str()), (&target, target_id)] {
        eprintln!("native transfer seed: confirming {id}");
        let ready = status(daemon, id, operation, &generation, |value| {
            value.pointer("/outcome/value/phase").and_then(Value::as_str) == Some("sas_pending")
        })?;
        let transcript = field(&ready, "transcript_hash")?;
        attended(
            &daemon.socket,
            &[
                "pairing",
                "--account",
                id,
                "confirm",
                "--operation-id",
                operation,
                "--generation",
                &generation,
                "--transcript-hash",
                transcript,
                "--matches",
                "true",
            ],
            &[("Type match or mismatch:", "match")],
        )?;
    }
    let proposal = status(source, &account.id, operation, &generation, |value| {
        value.pointer("/outcome/value/proposal_hash").and_then(Value::as_str).is_some()
    })?;
    rf_json(
        &source.socket,
        &[
            "pairing",
            "--account",
            &account.id,
            "approve",
            "--operation-id",
            operation,
            "--generation",
            &generation,
            "--transcript-hash",
            field(&proposal, "transcript_hash")?,
            "--proposal-hash",
            field(&proposal, "proposal_hash")?,
            "--approved",
            "true",
        ],
    )?;
    for (daemon, id) in [(source, account.id.as_str()), (&target, target_id)] {
        status(daemon, id, operation, &generation, |value| {
            value.pointer("/outcome/value/phase").and_then(Value::as_str) == Some("completed")
        })?;
    }
    let enrolled = unlock_enrolled(&target, target_id)?;
    Ok((target, enrolled))
}

fn unlock_enrolled(target: &Daemon, target_id: &str) -> Result<Account> {
    // Enrollment installs a locked account; opening it is a separate ordinary user action.
    super::rf_json_env(
        &target.socket,
        &[
            "account",
            "unlock",
            "--account",
            target_id,
            "--passphrase-env",
            "RAMFLUX_ACCOUNT_PASSPHRASE",
        ],
        &[("RAMFLUX_ACCOUNT_PASSPHRASE", PASSPHRASE)],
    )?;
    super::wait_networking_live(target, target_id)?;
    let value = wait_json(target, &["account", "status", "--account", target_id], |value| {
        value.get("target_delivery_id").and_then(Value::as_str).is_some()
    })?;
    let text = |name: &str| -> Result<String> {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("target account status lacks {name}").into())
    };
    Ok(Account {
        id: target_id.into(),
        display_name: "Target phone".into(),
        principal_id: text("principal_id")?,
        principal_commitment: text("principal_commitment")?,
        device_id: text("device_id")?,
        target_delivery_id: text("target_delivery_id")?,
    })
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get("outcome")
        .and_then(|v| v.get("value"))
        .and_then(|v| v.get(name))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("pairing response lacks {name}").into())
}

fn status(
    daemon: &Daemon,
    account: &str,
    operation: &str,
    generation: &str,
    ready: impl Fn(&Value) -> bool,
) -> Result<Value> {
    let last = std::cell::RefCell::new(None::<String>);
    super::poll_value(
        "attended pairing status",
        super::POLL_TIMEOUT,
        || {
            attended(
                &daemon.socket,
                &[
                    "pairing",
                    "--account",
                    account,
                    "status",
                    "--operation-id",
                    operation,
                    "--generation",
                    generation,
                ],
                &[],
            )
        },
        |value| {
            let phase = value.pointer("/outcome/value/phase").and_then(Value::as_str);
            if last.borrow().as_deref() != phase {
                eprintln!("native transfer seed: {account} phase {phase:?}");
                *last.borrow_mut() = phase.map(str::to_owned);
            }
            ready(value)
        },
    )
}
