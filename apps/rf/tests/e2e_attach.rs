// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! ATTACH-SEND-01 r2 (review M1): real accounts, real daemons, the real gateway and the real
//! relay. A file is sent in a DM and in a group of three, received, imported by every
//! recipient and by the sender, revoked, and then refused. No seeded rows, no test plane.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use e2e::{
    Account, Daemon, boot_stack_with_relay, configure_node, create_account, dm_conversation,
    dump_logs, exchange_contacts, group_create, rf_json_timeout, rf_output_with_timeout,
    start_daemon, unique, wait_dm_texts, wait_group_texts, wait_json,
};
use serde_json::Value;

/// Generous per-call budget: one send streams the file through the gateway and the relay.
const CALL: Duration = Duration::from_secs(120);
/// Total time a step may keep retrying a refusal that is expected to clear.
const STEP: Duration = Duration::from_secs(150);

fn file_bytes(length: usize, seed: u8) -> Vec<u8> {
    (0..length).map(|index| u8::try_from(index % 241).unwrap_or(0).wrapping_add(seed)).collect()
}

/// Runs a CLI call until it succeeds, for refusals that clear once the session is live or the
/// peer's layer declaration is published.
fn until_ok(daemon: &Daemon, args: &[&str]) -> e2e::Result<Value> {
    let deadline = Instant::now() + STEP;
    let mut first = None;
    loop {
        match rf_json_timeout(&daemon.socket, args, CALL) {
            Ok(value) => return Ok(value),
            Err(error) if Instant::now() >= deadline => {
                let log = std::fs::read_to_string(daemon.data_root.join("daemon.log"))
                    .unwrap_or_default();
                let tail: String =
                    log.chars().rev().take(6000).collect::<Vec<_>>().into_iter().rev().collect();
                return Err(format!(
                    "{args:?} never succeeded: {error}; first refusal: {first:?}; daemon_log_tail={tail}"
                )
                .into());
            }
            Err(error) => {
                first.get_or_insert_with(|| error.to_string());
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

/// Sends with a fresh operation id per attempt: a refused send leaves its operation pending
/// by design, so a retry of the same id is a reconciliation, not a resend.
fn send_fresh(
    daemon: &Daemon,
    prefix: &str,
    build: impl Fn(&str) -> Vec<String>,
) -> e2e::Result<Value> {
    let deadline = Instant::now() + STEP;
    let mut refusals = Vec::new();
    loop {
        let message = unique(prefix);
        let owned = build(&message);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        match rf_json_timeout(&daemon.socket, &args, CALL) {
            Ok(value) => return Ok(value),
            Err(error) if Instant::now() >= deadline => {
                refusals.push(error.to_string());
                let all: Vec<String> = refusals
                    .iter()
                    .map(|text| {
                        text.chars().rev().take(300).collect::<Vec<_>>().into_iter().rev().collect()
                    })
                    .collect();
                let log = std::fs::read_to_string(daemon.data_root.join("daemon.log"))
                    .unwrap_or_default();
                let tail: String =
                    log.chars().rev().take(4000).collect::<Vec<_>>().into_iter().rev().collect();
                return Err(format!(
                    "send never succeeded; refusals: {all:#?}; daemon_log_tail={tail}"
                )
                .into());
            }
            Err(error) => {
                refusals.push(error.to_string());
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn declared(daemon: &Daemon, account: &Account) -> e2e::Result<()> {
    wait_json(daemon, &["account", "status", "--account", &account.id], |value| {
        value["layer_declaration"]["state"] == "fresh"
    })?;
    Ok(())
}

fn enable(daemon: &Daemon, account: &Account) -> e2e::Result<()> {
    let value =
        until_ok(daemon, &["attachment", "enable", "--account", &account.id, "--from-node"])?;
    assert_eq!(value["enabled"], true, "the pin is stored: {value}");
    Ok(())
}

fn import(
    daemon: &Daemon,
    account: &Account,
    message: &str,
    output: &Path,
) -> std::io::Result<std::process::Output> {
    let output_text = output.to_string_lossy().into_owned();
    rf_output_with_timeout(
        &daemon.socket,
        &[
            "attachment",
            "import",
            "--account",
            &account.id,
            "--message",
            message,
            "--index",
            "0",
            "--output",
            &output_text,
        ],
        CALL,
    )
}

/// Imports until it succeeds: the message may still be settling on the receiving daemon.
fn import_ok(
    daemon: &Daemon,
    account: &Account,
    message: &str,
    output: &Path,
) -> e2e::Result<Vec<u8>> {
    let deadline = Instant::now() + STEP;
    loop {
        let result = import(daemon, account, message, output)?;
        if result.status.success() {
            return Ok(std::fs::read(output)?);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "import of {message} never succeeded: {}",
                String::from_utf8_lossy(&result.stderr)
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn message_id(view: &Value, text: &str) -> e2e::Result<String> {
    view["messages"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["text"] == text))
        .and_then(|row| row["id"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("no message with text {text:?} in {view}").into())
}

fn scratch(daemon: &Daemon, name: &str) -> e2e::Result<PathBuf> {
    let dir = daemon.data_root.join("attach-e2e");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(name))
}

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn a_file_is_sent_received_imported_revoked_and_then_refused() -> e2e::Result<()> {
    let stack = boot_stack_with_relay()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = dm_conversation(&alice, &bob)?;
    let logs = || dump_logs(&stack, &[&alice_d, &bob_d]);
    enable(&alice_d, &alice).map_err(|error| format!("{error}; logs={}", logs()))?;
    enable(&bob_d, &bob).map_err(|error| format!("{error}; logs={}", logs()))?;

    // Five MiB: two segments and ten network chunks through the gateway and the relay.
    let source = scratch(&alice_d, "source.bin")?;
    let original = file_bytes(5 * 1024 * 1024, 7);
    std::fs::write(&source, &original)?;
    let source_text = source.to_string_lossy().into_owned();
    declared(&alice_d, &alice)?;
    declared(&bob_d, &bob)?;
    let caption = "a real file over the real wire";
    let sent = send_fresh(&alice_d, "attach", |message| {
        [
            "dm",
            "send",
            "--account",
            &alice.id,
            "--conversation",
            &conversation,
            "--message",
            message,
            "--envelope",
            message,
            "--source-principal",
            &alice.principal_id,
            "--sender",
            &alice.device_id,
            "--recipient-device",
            &bob.device_id,
            "--recipient-principal-commitment",
            &bob.principal_commitment,
            "--target",
            &bob.target_delivery_id,
            "--body",
            caption,
            "--attach",
            &source_text,
        ]
        .map(str::to_owned)
        .to_vec()
    })
    .map_err(|error| format!("{error}; logs={}", logs()))?;
    assert_eq!(sent["delivery_state"], "submitted", "the send reached every device: {sent}");
    let sent_id = sent["message_id"].as_str().ok_or("sent message id")?.to_owned();

    let received = wait_dm_texts(&bob_d, &bob, &conversation, &[caption])?;
    let received_id = message_id(&received, caption)?;
    assert_eq!(received_id, sent_id, "sender and receiver name the message the same way");

    let bob_out = scratch(&bob_d, "received.bin")?;
    let bob_bytes = import_ok(&bob_d, &bob, &received_id, &bob_out)
        .map_err(|error| format!("{error}; logs={}", logs()))?;
    assert_eq!(bob_bytes, original, "the recipient imports the exact bytes");

    let alice_out = scratch(&alice_d, "own-copy.bin")?;
    let alice_bytes = import_ok(&alice_d, &alice, &sent_id, &alice_out)
        .map_err(|error| format!("{error}; logs={}", logs()))?;
    assert_eq!(alice_bytes, original, "the sender imports its own file");

    // Revoke at the sender, then every later import is refused and a failed import keeps
    // the earlier output untouched.
    let deadline = Instant::now() + STEP;
    let erased = loop {
        let state = rf_json_timeout(
            &alice_d.socket,
            &["object", "revoke", "--account", &alice.id, "--message", &sent_id],
            CALL,
        )?;
        if state["state"] == "relay_erased" || Instant::now() >= deadline {
            break state;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    assert_eq!(erased["state"], "relay_erased", "the relay confirmed the cleanup: {erased}");

    let refused = import(&bob_d, &bob, &received_id, &bob_out)?;
    assert!(!refused.status.success(), "a revoked file must not import again");
    let reason = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(
        reason.contains("attachment_deleted"),
        "the recipient is refused with the stable code, got {reason:?}"
    );
    assert_eq!(std::fs::read(&bob_out)?, original, "a failed import never touches its output");
    let own = import(&alice_d, &alice, &sent_id, &alice_out)?;
    assert!(!own.status.success(), "the sender is refused as well");
    assert_eq!(std::fs::read(&alice_out)?, original, "the sender's earlier output stays");
    Ok(())
}

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn a_file_in_a_group_of_three_reaches_both_members() -> e2e::Result<()> {
    let stack = boot_stack_with_relay()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    let carol_d = start_daemon(&stack, "carol")?;
    for daemon in [&alice_d, &bob_d, &carol_d] {
        configure_node(daemon, &stack.discovery_url)?;
    }
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    let carol = create_account(&carol_d, "Carol")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    exchange_contacts(&alice_d, &alice, &carol_d, &carol)?;
    exchange_contacts(&bob_d, &bob, &carol_d, &carol)?;
    let logs = || dump_logs(&stack, &[&alice_d, &bob_d, &carol_d]);
    for (daemon, account) in [(&alice_d, &alice), (&bob_d, &bob), (&carol_d, &carol)] {
        enable(daemon, account).map_err(|error| format!("{error}; logs={}", logs()))?;
    }
    let group = unique("e2e-attach-group");
    group_create(&alice_d, &alice, &group, &[&bob, &carol])?;

    let source = scratch(&alice_d, "group-source.bin")?;
    let original = file_bytes(1_200_000, 31);
    std::fs::write(&source, &original)?;
    let source_text = source.to_string_lossy().into_owned();
    for (daemon, account) in [(&alice_d, &alice), (&bob_d, &bob), (&carol_d, &carol)] {
        declared(daemon, account)?;
    }
    let caption = "a file for the whole group";
    let sent = send_fresh(&alice_d, "group-attach", |message| {
        [
            "group",
            "send",
            "--account",
            &alice.id,
            "--group",
            &group,
            "--conversation",
            &group,
            "--message",
            message,
            "--sender",
            &alice.device_id,
            "--body",
            caption,
            "--attach",
            &source_text,
        ]
        .map(str::to_owned)
        .to_vec()
    })
    .map_err(|error| format!("{error}; logs={}", logs()))?;
    assert_eq!(sent["delivery_state"], "submitted", "the group send was admitted: {sent}");

    for (daemon, account, name) in [(&bob_d, &bob, "bob"), (&carol_d, &carol, "carol")] {
        let view = wait_group_texts(daemon, account, &group, &group, &[caption])
            .map_err(|error| format!("{error}; logs={}", logs()))?;
        let id = message_id(&view, caption)?;
        let out = scratch(daemon, &format!("group-{name}.bin"))?;
        let bytes = import_ok(daemon, account, &id, &out)
            .map_err(|error| format!("{error}; logs={}", logs()))?;
        assert_eq!(bytes, original, "{name} imports the exact bytes from its own entry");
    }
    Ok(())
}
