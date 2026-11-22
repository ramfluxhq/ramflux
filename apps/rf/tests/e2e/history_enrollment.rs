// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! HISTORY-COURIER-IDENTITY-01: a device added to an account receives the account's earlier direct
//! messages, own and peer, in order, without the one erased for everyone, with real `rf` daemons
//! driven only through the command line (the pairing ceremony included) and every courier running by
//! itself. Real: the four node services, three daemons (owner phone, peer, paired desktop), the pairing
//! ceremony over HTTPS, the enrollment history job, the authored-copy courier, the node. Fixture: the
//! stack's test CA and the memory vault.
#![cfg(unix)]

use crate::e2e::{
    Result, assert_texts_once_in_order, boot_agent_stack, configure_node, create_account,
    dm_conversation, exchange_contacts, message_texts, pair_devices, rf_json, start_pairing_daemon,
    unique, wait_dm_texts_with_timeout, wait_json,
};
use std::time::Duration;

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn an_added_device_receives_the_earlier_history_of_both_sides() -> Result<()> {
    let stack = boot_agent_stack()?;
    let phone = start_pairing_daemon(&stack, "phone")?;
    let peer_d = start_pairing_daemon(&stack, "peer")?;
    configure_node(&phone, &stack.stack.discovery_url)?;
    configure_node(&peer_d, &stack.stack.discovery_url)?;
    let owner = create_account(&phone, "Owner")?;
    let peer = create_account(&peer_d, "Peer")?;
    exchange_contacts(&phone, &owner, &peer_d, &peer)?;
    for (daemon, account) in [(&phone, &owner), (&peer_d, &peer)] {
        wait_json(daemon, &["contact", "list", "--account", &account.id], |value| {
            value.pointer("/contacts/0/request_state").and_then(serde_json::Value::as_str)
                == Some("accepted")
        })?;
    }
    let conversation = dm_conversation(&owner, &peer)?;

    // History before the second device exists: both sides write, one message is erased for everyone.
    let (own_1, peer_1, own_2, erased) = ("own-1", "peer-1", "own-2", "erased-1");
    let budget = Duration::from_secs(90);
    send(&phone, &owner, &conversation, own_1)?;
    wait_dm_texts_with_timeout(&peer_d, &peer, &conversation, &[own_1], budget)?;
    send(&peer_d, &peer, &conversation, peer_1)?;
    wait_dm_texts_with_timeout(&phone, &owner, &conversation, &[peer_1], budget)?;
    send(&phone, &owner, &conversation, own_2)?;
    let erased_id = send(&phone, &owner, &conversation, erased)?;
    wait_dm_texts_with_timeout(&peer_d, &peer, &conversation, &[own_2, erased], budget)?;
    rf_json(
        &phone.socket,
        &[
            "conversation",
            "delete",
            "--account",
            &owner.id,
            "--conversation",
            &conversation,
            "--message",
            &erased_id,
            "--scope",
            "everyone",
            "--operation-id",
            &unique("erase-op"),
        ],
    )?;
    wait_json(
        &peer_d,
        &["dm", "read", "--account", &peer.id, "--conversation", &conversation],
        |value| !message_texts(value).iter().any(|text| text == erased),
    )?;

    // The second device is added by the CLI ceremony; nothing else is done for it.
    let pair = pair_devices(&stack, phone, &owner, "desktop")?;
    let history = wait_dm_texts_with_timeout(
        &pair.desktop,
        &owner,
        &conversation,
        &[own_1, peer_1, own_2],
        Duration::from_secs(150),
    )
    .map_err(|error| {
        let short: String = error.to_string().chars().take(400).collect();
        format!(
            "the added device never showed the earlier history: {short}; {}",
            history_log_lines(&[&pair.primary, &pair.desktop])
        )
    })?;
    // The courier and refusal lines are printed on success too: the report names which must be absent.
    eprintln!("history log lines: {}", history_log_lines(&[&pair.primary, &pair.desktop]));
    assert_texts_once_in_order(&history, &[own_1, peer_1, own_2])?;
    assert!(
        !message_texts(&history).iter().any(|text| text == erased),
        "the message erased for everyone must not appear on the added device: {history}"
    );
    Ok(())
}

/// `rf conversation send`, retried while the account is not yet connected; returns the message id.
fn send(
    daemon: &crate::e2e::Daemon,
    account: &crate::e2e::Account,
    conversation: &str,
    text: &str,
) -> Result<String> {
    let op = unique("send-op");
    let sent = wait_json(
        daemon,
        &[
            "conversation",
            "send",
            "--account",
            &account.id,
            "--conversation",
            conversation,
            "--text",
            text,
            "--operation-id",
            &op,
        ],
        |value| {
            value.pointer("/body/delivery_state").and_then(serde_json::Value::as_str)
                == Some("submitted")
                || (value.get("ok").and_then(serde_json::Value::as_bool) == Some(false)
                    && !matches!(
                        value.pointer("/error/code").and_then(serde_json::Value::as_str),
                        Some("not_connected" | "NetworkingPending" | "ephemeral_unavailable")
                    ))
        },
    )?;
    sent.pointer("/body/message_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("the send was not submitted: {sent}").into())
}

/// The history, courier and refusal lines of each daemon log, counted, for a failure message.
fn history_log_lines(daemons: &[&crate::e2e::Daemon]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for daemon in daemons {
        let text = std::fs::read_to_string(daemon.data_root.join("daemon.log")).unwrap_or_default();
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for line in text.lines().filter(|line| {
            ["courier", "history", "source_authority", "pairing", "own-device", "WARN"]
                .iter()
                .any(|key| line.contains(key))
        }) {
            // Drop the timestamp so repeats of one line count together.
            let key: String =
                line.split_once(' ').map_or(line, |(_, rest)| rest).chars().take(260).collect();
            *counts.entry(key).or_default() += 1;
        }
        let _ = writeln!(out, "\n== {} ==", daemon.data_root.display());
        for (line, count) in counts {
            let _ = writeln!(out, "{count} x {line}");
        }
    }
    out
}
