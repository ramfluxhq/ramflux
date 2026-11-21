// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! AGENT-CLI-E2E-01: the whole agent lifecycle through the `rf` command line, with real service
//! processes and two real `rf` daemons (the primary and a desktop paired into the same account by
//! `rf pairing`). Nothing is built by hand: every request and answer is a command a person types.
//! Real: the four node services, both daemons, the pairing ceremony over HTTPS, own-device delivery
//! of the plan and the decision through the node, the AgentPublish admission on the node, background
//! commit and publication on the desktop. Fixture: the primary's user presence (the integration
//! hook `itest.agent.approve_once`, one call per plan), the memory vault, the stack's test CA.
#![cfg(unix)]

use crate::e2e::agent_flow as agent;
use crate::e2e::{
    Result, boot_agent_stack, configure_node, create_account, node_get, pair_devices,
    start_pairing_daemon,
};
use std::time::{Duration, Instant};

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn agent_lifecycle_is_driven_through_rf_with_two_daemons() -> Result<()> {
    let stack = boot_agent_stack()?;
    let phone = start_pairing_daemon(&stack, "phone")?;
    configure_node(&phone, &stack.stack.discovery_url)?;
    // The daemon holds exactly one account: the single-account shape that failed on the node.
    let human = create_account(&phone, "Owner")?;
    let pair = pair_devices(&stack, phone, &human, "desktop")?;
    let (primary, desktop, owner) = (&pair.primary, &pair.desktop, &pair.account);

    // Create on the desktop: the request is waiting, nothing is an agent yet.
    let operation = agent::create(desktop, owner, "Demo Agent", "answers the demo questions")?;
    assert!(agent::list(desktop, owner)?.is_empty(), "no agent exists before the approval");

    // The primary finds the request by itself and sees what it decides.
    let pending = agent::wait_pending(primary, owner).map_err(|error| {
        format!("{error}; {}", diagnose(&stack, &[primary, desktop], owner, &operation))
    })?;
    assert_eq!(pending.request_id, operation, "the primary sees the desktop's request");
    assert_eq!(pending.agent_name, "Demo Agent");
    assert_eq!(pending.responsibility, "answers the demo questions");
    assert_eq!((pending.provider.as_str(), pending.model.as_str()), ("provider-e2e", "model-e2e"));
    agent::confirm_presence(primary, owner, &pending.request_hash)?;
    let decided = agent::decide(primary, owner, &pending, true)?;
    assert_eq!(decided["state"], "authorized", "the approval is signed and sent: {decided}");

    // The desktop commits, publishes and completes without any further command but the reads.
    let done = agent::wait_state(desktop, owner, &operation, "complete").map_err(|error| {
        format!("{error}; {}", diagnose(&stack, &[primary, desktop], owner, &operation))
    })?;
    assert!(done.get("receiptJson").is_some(), "the node's receipt is stored: {done}");
    let anchor = pending.agent_anchor.clone();

    // Both devices list and show the agent with its profile.
    for (daemon, label) in [(desktop, "desktop"), (primary, "primary")] {
        let shown = agent::wait_listed(daemon, owner, &anchor)
            .map_err(|error| format!("{error}; files: {}", agent_files(&daemon.data_root)))?;
        assert_eq!(shown["persona"]["name"], "Demo Agent", "{label} shows the persona: {shown}");
        assert_eq!(shown["persona"]["responsibility"], "answers the demo questions");
        assert_eq!(shown["lifecycle"], "U", "{label}: the new agent has an identity and no runtime");
    }

    // The node holds the agent's published custody record: read through the public directory path
    // a peer uses to resolve a principal.
    let manifest = node_get(&stack.stack, &format!("/mvp1/device-manifest/{anchor}"))?;
    assert!(manifest.contains(&anchor), "the node's directory names the agent anchor");
    assert!(manifest.contains("headless_ai"), "the node's record is the agent's: {manifest}");

    // An edit on the desktop reaches the primary by its own sync.
    agent::edit(desktop, owner, &anchor, "Renamed Agent", "answers the demo questions")?;
    wait_for(|| {
        agent::show(primary, owner, &anchor)
            .is_ok_and(|shown| shown["persona"]["name"] == "Renamed Agent")
    })?;

    // A second creation that the primary denies ends with the typed refusal on the desktop.
    let second = agent::create(desktop, owner, "Denied Agent", "never approved")?;
    let waiting = agent::wait_pending(primary, owner)?;
    assert_eq!(waiting.request_id, second);
    // A denial is a signed decision too, so the person confirms it on the primary as well.
    agent::confirm_presence(primary, owner, &waiting.request_hash)?;
    let refused = agent::decide(primary, owner, &waiting, false)?;
    assert_eq!(refused["state"], "refused", "{refused}");
    let seen = agent::wait_state(desktop, owner, &second, "refused")?;
    assert_eq!(seen["error"]["reasonCode"], "authorization_refused", "typed refusal: {seen}");
    assert_eq!(agent::list(desktop, owner)?.len(), 1, "the denied agent was never created");

    // Delete on the desktop: the local state goes, the node keeps the custody record.
    let deleted = agent::delete(desktop, owner, &anchor)?;
    assert_eq!(deleted["cleanup"], "node_record_retained", "{deleted}");
    assert_eq!(deleted["lifecycle"], "X");
    wait_for(|| {
        agent::show(primary, owner, &anchor).is_ok_and(|shown| shown["lifecycle"] == "X")
    })?;
    Ok(())
}

fn wait_for(mut ready: impl FnMut() -> bool) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if ready() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("the awaited state never appeared on the other device".into())
}

/// The node logs and the agent-related lines of each daemon log, for a failure message.
fn diagnose(
    stack: &crate::e2e::PairingStack,
    daemons: &[&crate::e2e::Daemon],
    owner: &crate::e2e::Account,
    operation: &str,
) -> String {
    let mut out = crate::e2e::dump_logs(&stack.stack, &[]);
    // What the node holds for the human: the published device set and its epoch.
    let manifest = node_get(&stack.stack, &format!("/mvp1/device-manifest/{}", owner.principal_commitment))
        .map(|body| {
            let value: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let record = &value["custody"]["publication"]["record"]["body"];
            let listed: Vec<String> = value["custody"]["devices"]
                .as_array()
                .map(|rows| rows.iter().map(|row| row.to_string().chars().take(160).collect()).collect())
                .unwrap_or_default();
            format!(
                "top-level keys={:?} listed devices={listed:?}; epoch={} devices={}",
                value.as_object().map(|map| map.keys().cloned().collect::<Vec<_>>()),
                record["device_set_epoch"],
                record["devices"].as_array().map_or(0, Vec::len)
            )
        })
        .unwrap_or_else(|error| error.to_string());
    if let Some(desktop) = daemons.get(1) {
        let state = agent::status(desktop, owner, operation)
            .map(|value| value.to_string())
            .unwrap_or_else(|error| error.to_string());
        out.push_str(&format!("\n== desktop operation: {state} ==\n"));
    }
    out.push_str(&format!("\n== node directory for the human: {manifest} ==\n"));
    for daemon in daemons {
        let text = std::fs::read_to_string(daemon.data_root.join("daemon.log")).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let tail = lines.len().saturating_sub(70);
        out.push_str(&format!("\n== {} ==\n", daemon.data_root.display()));
        let status = crate::e2e::rf_json(&daemon.socket, &["account", "status", "--account", &owner.id])
            .map(|value| value.to_string())
            .unwrap_or_else(|error| error.to_string());
        out.push_str(&format!("status: {}\n", status.chars().take(2500).collect::<String>()));
        out.push_str(&lines.get(tail..).unwrap_or(&[]).join("\n"));
    }
    out
}

/// The agent-related files under a daemon's data root, with the creation records' state and
/// whether they kept their intent, for a failure message.
fn agent_files(root: &std::path::Path) -> String {
    fn walk(dir: &std::path::Path, out: &mut Vec<String>, depth: usize) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            let text = path.display().to_string();
            if path.is_dir() {
                if depth < 8 {
                    walk(&path, out, depth + 1);
                }
            } else if text.contains("agent") {
                let note = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
                    .map(|value| {
                        format!(
                            " state={} intent={}",
                            value["state"],
                            value["intent_b64"].is_string()
                        )
                    })
                    .unwrap_or_default();
                out.push(format!("{text}{note}"));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out, 0);
    out.join(" | ")
}
