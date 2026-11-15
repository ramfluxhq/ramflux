// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Demo B B9 through the rf binary, a real daemon and a real router: a Surface v2 event
//! built by the SDK encoder round-trips to the peer, a Task is displayed on the peer, and an
//! A2I approval is refused with the typed `generated_authority` code.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    Account, Daemon, boot_stack, configure_node, create_account, dm_conversation,
    exchange_contacts, rf_json, start_daemon, unique, wait_json,
};
use serde_json::{Value, json};
use std::path::Path;

#[ignore = "cli e2e: Demo B B9 rf drivers; explicit QA/CI run only"]
#[test]
fn b9_surface_round_trip_task_display_and_a2i_refusal() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    settle_contact_requests(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = dm_conversation(&alice, &bob)?;
    let scratch = tempfile::TempDir::new()?;

    surface_round_trip(&alice_d, &bob_d, &alice, &bob, &conversation, scratch.path())?;
    task_display(&alice_d, &bob_d, &alice, &bob, &conversation, scratch.path())?;
    expect_a2i_authority_refusal(
        &alice_d,
        &[
            "a2i",
            "append",
            "--account",
            &alice.id,
            "--event",
            &unique("b9-no-grant"),
            "--type",
            "a2i.control",
            "--source-device",
            &alice.device_id,
            "--target-device",
            &alice.device_id,
            "--control-domain",
            "mcp.approval",
            "--action",
            "grant",
            "--subject",
            "demo-b-no-grant",
        ],
    )?;
    let status = rf_json(&alice_d.socket, &["account", "status", "--account", &alice.id])?;
    if status.get("principal_id").and_then(Value::as_str) != Some(alice.principal_id.as_str()) {
        return Err("A2I refusal left the daemon without the active account".into());
    }
    Ok(())
}

/// Alice creates a Surface with `rf surface send`; Bob lists and reads the same surface.
fn surface_round_trip(
    alice_d: &Daemon,
    bob_d: &Daemon,
    alice: &Account,
    bob: &Account,
    conversation: &str,
    scratch: &Path,
) -> e2e::Result<()> {
    let surface_id = unique("demo-b-surface");
    let fallback = unique("Demo B surface fallback");
    let command = scratch.join("create-surface.json");
    std::fs::write(
        &command,
        serde_json::to_vec(&json!({
            "command": "createSurface",
            "surfaceId": surface_id,
            "surfaceType": "status_panel",
            "catalog": "basic",
            "catalogVersion": "1",
            "fallbackText": fallback,
        }))?,
    )?;
    let command_path = command.to_string_lossy().into_owned();
    let sent = rf_json(
        &alice_d.socket,
        &[
            "surface",
            "send",
            "--account",
            &alice.id,
            "--conversation",
            conversation,
            "--version",
            "1",
            "--command-file",
            &command_path,
        ],
    )?;
    if sent.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("surface.send refused: {sent}").into());
    }
    let listed = wait_json(
        bob_d,
        &["surface", "list", "--account", &bob.id, "--conversation", conversation],
        |value| value.to_string().contains(&surface_id),
    )?;
    if !listed.to_string().contains(&surface_id) {
        return Err(format!("peer surface list lacks {surface_id}: {listed}").into());
    }
    let read = wait_json(
        bob_d,
        &[
            "surface",
            "get",
            "--account",
            &bob.id,
            "--surface-id",
            &surface_id,
            "--conversation",
            conversation,
        ],
        |value| value.to_string().contains(&fallback),
    )?;
    if !read.to_string().contains(&fallback) {
        return Err(format!("peer surface get lacks the created fallback: {read}").into());
    }
    let author_view = rf_json(
        &alice_d.socket,
        &["surface", "get", "--account", &alice.id, "--surface-id", &surface_id],
    )?;
    if author_view.to_string().contains(&fallback) {
        Ok(())
    } else {
        Err(format!("author surface get lacks the created fallback: {author_view}").into())
    }
}

/// Alice starts a Task for Bob; Bob's `task list` and `task get` display it. A missing task is
/// reported as a successful read with a null body.
fn task_display(
    alice_d: &Daemon,
    bob_d: &Daemon,
    alice: &Account,
    bob: &Account,
    conversation: &str,
    scratch: &Path,
) -> e2e::Result<()> {
    let task_id = unique("demo-b-task");
    let text = unique("Demo B task text");
    let body = scratch.join("task-start.json");
    std::fs::write(
        &body,
        serde_json::to_vec(&json!({
            "task_id": task_id,
            "conversation_id": conversation,
            "assignee": bob.principal_id,
            "text": text,
        }))?,
    )?;
    let body_path = body.to_string_lossy().into_owned();
    let started = rf_json(
        &alice_d.socket,
        &["task", "start", "--account", &alice.id, "--body-file", &body_path],
    )?;
    if started.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("task.start refused: {started}").into());
    }
    let listed = wait_json(
        bob_d,
        &["task", "list", "--account", &bob.id, "--conversation", conversation],
        |value| value.to_string().contains(&task_id),
    )?;
    if !listed.to_string().contains(&task_id) {
        return Err(format!("peer task list lacks {task_id}: {listed}").into());
    }
    let got =
        wait_json(bob_d, &["task", "get", "--account", &bob.id, "--task-id", &task_id], |value| {
            value.to_string().contains(&text)
        })?;
    if got.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("task.get did not succeed on the peer: {got}").into());
    }
    let missing = rf_json(
        &bob_d.socket,
        &["task", "get", "--account", &bob.id, "--task-id", &unique("absent-task")],
    )?;
    if missing.get("ok").and_then(Value::as_bool) != Some(true)
        || !missing.get("body").is_some_and(Value::is_null)
    {
        return Err(format!("absent task was not reported as a null body: {missing}").into());
    }
    Ok(())
}

fn settle_contact_requests(
    first: &Daemon,
    first_account: &Account,
    second: &Daemon,
    second_account: &Account,
) -> e2e::Result<()> {
    for (daemon, account) in [(first, first_account), (second, second_account)] {
        wait_json(daemon, &["contact", "list", "--account", &account.id], |value| {
            value.pointer("/contacts/0/request_state").and_then(Value::as_str) == Some("accepted")
        })?;
    }
    Ok(())
}

fn expect_a2i_authority_refusal(daemon: &Daemon, args: &[&str]) -> e2e::Result<()> {
    let error = match rf_json(&daemon.socket, args) {
        Ok(value) => return Err(format!("B9 approval unexpectedly succeeded: {value}").into()),
        Err(error) => error.to_string(),
    };
    if !error.contains("generated_authority") {
        return Err(format!("typed Authority reason missing: {error}").into());
    }
    if !error.contains("exit status: 1") {
        return Err(format!("refusal must be a normal CLI exit: {error}").into());
    }
    Ok(())
}
