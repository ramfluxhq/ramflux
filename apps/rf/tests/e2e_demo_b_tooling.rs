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
    exchange_contacts, rf_json, rf_output, start_daemon, unique, wait_json,
};
use ramflux_protocol::{
    A2uiConversationCommand, CreateSurfaceCommand, PatchSurfaceCommand, SurfacePatchOp,
    decode_base64url, surface_snapshot_hash,
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

    surface_round_trip(&Round {
        alice_d: &alice_d,
        bob_d: &bob_d,
        alice: &alice,
        bob: &bob,
        conversation: &conversation,
        scratch: scratch.path(),
    })?;
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

struct Round<'a> {
    alice_d: &'a Daemon,
    bob_d: &'a Daemon,
    alice: &'a Account,
    bob: &'a Account,
    conversation: &'a str,
    scratch: &'a Path,
}

struct SurfaceView {
    surface_id: String,
    version: u64,
    hash: String,
}

struct Created {
    view: SurfaceView,
    snapshot: CreateSurfaceCommand,
}

/// Alice creates a Surface with `rf surface send`; Bob lists and reads the same surface.
fn surface_round_trip(trip: &Round<'_>) -> e2e::Result<()> {
    let created = create_observed_surface(trip)?;
    let patched = patch_observed_surface(trip, &created)?;
    prove_action_round_trip(trip, &patched)
}

fn create_observed_surface(trip: &Round<'_>) -> e2e::Result<Created> {
    let surface_id = unique("demo-b-surface");
    let fallback = unique("Demo B surface fallback");
    let command = trip.scratch.join("create-surface.json");
    std::fs::write(
        &command,
        serde_json::to_vec(&json!({
            "command": "createSurface",
            "surfaceId": surface_id,
            "surfaceType": "status_panel",
            "catalog": "basic",
            "catalogVersion": "1",
            "fallbackText": fallback,
            "allowedActions": [{"name": "choose"}],
        }))?,
    )?;
    let command_path = command.to_string_lossy().into_owned();
    let sent = rf_json(
        &trip.alice_d.socket,
        &[
            "surface",
            "send",
            "--account",
            &trip.alice.id,
            "--conversation",
            trip.conversation,
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
        trip.bob_d,
        &["surface", "list", "--account", &trip.bob.id, "--conversation", trip.conversation],
        |value| value.to_string().contains(&surface_id),
    )?;
    if !listed.to_string().contains(&surface_id) {
        return Err(format!("peer surface list lacks {surface_id}: {listed}").into());
    }
    let read = peer_surface(trip, &surface_id, |value| value.to_string().contains(&fallback))?;
    if !read.to_string().contains(&fallback) {
        return Err(format!("peer surface get lacks the created fallback: {read}").into());
    }
    if !read["snapshot"]["allowedActions"].to_string().contains("choose") {
        return Err(format!("receiver snapshot does not declare choose: {read}").into());
    }
    let author_view = rf_json(
        &trip.alice_d.socket,
        &["surface", "get", "--account", &trip.alice.id, "--surface-id", &surface_id],
    )?;
    if !author_view.to_string().contains(&fallback) {
        return Err(format!("author surface get lacks the created fallback: {author_view}").into());
    }
    let version = required_u64(&author_view, "version")?;
    let hash = required_str(&author_view, "surface_hash")?.to_owned();
    let snapshot: CreateSurfaceCommand = serde_json::from_value(author_view["snapshot"].clone())?;
    let recomputed = surface_snapshot_hash(&snapshot)?;
    if recomputed != hash {
        return Err(format!("author snapshot hash {recomputed} != view {hash}").into());
    }
    Ok(Created { view: SurfaceView { surface_id, version, hash }, snapshot })
}

fn patch_observed_surface(trip: &Round<'_>, created: &Created) -> e2e::Result<SurfaceView> {
    let patched = unique("Demo B patched fallback");
    let mut snapshot = created.snapshot.clone();
    snapshot.fallback_text.clone_from(&patched);
    let new_hash = surface_snapshot_hash(&snapshot)?;
    let next_version = created.view.version.checked_add(1).ok_or("surface version exhausted")?;
    let patch_path = trip.scratch.join("patch-surface.json");
    std::fs::write(
        &patch_path,
        serde_json::to_vec(&A2uiConversationCommand::PatchSurface(PatchSurfaceCommand {
            surface_id: created.view.surface_id.clone(),
            base_surface_hash: created.view.hash.clone(),
            ops: vec![SurfacePatchOp::SetFallbackText { fallback_text: patched.clone() }],
            new_surface_hash: new_hash.clone(),
        }))?,
    )?;
    let patch_file = patch_path.to_string_lossy().into_owned();
    let version_arg = next_version.to_string();
    let patched_send = rf_json(
        &trip.alice_d.socket,
        &[
            "surface",
            "send",
            "--account",
            &trip.alice.id,
            "--conversation",
            trip.conversation,
            "--version",
            &version_arg,
            "--command-file",
            &patch_file,
        ],
    )?;
    if patched_send.get("ok").and_then(Value::as_bool) != Some(true)
        || patched_send.pointer("/body/accepted").and_then(Value::as_bool) != Some(true)
    {
        return Err(format!("surface patch was not accepted: {patched_send}").into());
    }
    let observed = peer_surface(trip, &created.view.surface_id, |value| {
        value.get("surface_hash").and_then(Value::as_str) == Some(new_hash.as_str())
            && value.get("version").and_then(Value::as_u64) == Some(next_version)
            && value.to_string().contains(&patched)
    })?;
    let version = required_u64(&observed, "version")?;
    let hash = required_str(&observed, "surface_hash")?.to_owned();
    if version != next_version || hash != new_hash {
        return Err(format!(
            "receiver patch is {version}/{hash}, expected {next_version}/{new_hash}"
        )
        .into());
    }
    Ok(SurfaceView { surface_id: created.view.surface_id.clone(), version, hash })
}

fn prove_action_round_trip(trip: &Round<'_>, view: &SurfaceView) -> e2e::Result<()> {
    let deny = action_command(&action_send(trip, view, "deny"))?;
    let deny_args: Vec<&str> = deny.iter().map(String::as_str).collect();
    expect_typed_refusal(trip.bob_d, &deny_args, "unknown_action")?;
    let choose = action_command(&action_send(trip, view, "choose"))?;
    let choose_args: Vec<&str> = choose.iter().map(String::as_str).collect();
    let acted = rf_json(&trip.bob_d.socket, &choose_args)?;
    if acted.get("ok").and_then(Value::as_bool) != Some(true)
        || acted.pointer("/body/accepted").and_then(Value::as_bool) != Some(true)
    {
        return Err(format!("allowed surface action was not accepted: {acted}").into());
    }
    let receipt = wait_json(
        trip.alice_d,
        &["surface", "get", "--account", &trip.alice.id, "--surface-id", &view.surface_id],
        |value| {
            action_row(value, "choose").is_some_and(|row| {
                row.get("sender_principal_id").and_then(Value::as_str)
                    == Some(trip.bob.principal_id.as_str())
                    && row.get("receipt_verified").and_then(Value::as_bool) == Some(true)
                    && row.get("version").and_then(Value::as_u64) == Some(view.version)
            })
        },
    )?;
    assert_author_receipt(&receipt, trip.bob, view)
}

fn action_send<'a>(
    trip: &'a Round<'_>,
    view: &'a SurfaceView,
    action_id: &'a str,
) -> ActionSend<'a> {
    ActionSend {
        actor: trip.bob,
        author: trip.alice,
        conversation: trip.conversation,
        surface_id: &view.surface_id,
        version: view.version,
        hash: &view.hash,
        action_id,
        scratch: trip.scratch,
    }
}

fn peer_surface(
    trip: &Round<'_>,
    surface_id: &str,
    ready: impl Fn(&Value) -> bool,
) -> e2e::Result<Value> {
    wait_json(
        trip.bob_d,
        &[
            "surface",
            "get",
            "--account",
            &trip.bob.id,
            "--surface-id",
            surface_id,
            "--conversation",
            trip.conversation,
        ],
        ready,
    )
}

fn assert_author_receipt(receipt: &Value, bob: &Account, view: &SurfaceView) -> e2e::Result<()> {
    let row = action_row(receipt, "choose")
        .ok_or_else(|| format!("author surface has no choose receipt: {receipt}"))?;
    if row.get("sender_principal_id").and_then(Value::as_str) != Some(bob.principal_id.as_str())
        || row.get("sender_device_id").and_then(Value::as_str) != Some(bob.device_id.as_str())
    {
        return Err(format!("author receipt signer is not Bob: {row}").into());
    }
    if row.get("signature").and_then(Value::as_str).is_none_or(str::is_empty) {
        return Err(format!("author receipt has no original signature: {row}").into());
    }
    if row.get("receipt_verified").and_then(Value::as_bool) != Some(true) {
        return Err(format!("author receipt is not verified: {row}").into());
    }
    let wire = action_wire(row)?;
    if wire.get("version").and_then(Value::as_u64) != Some(view.version)
        || wire.get("surfaceHash").and_then(Value::as_str) != Some(view.hash.as_str())
        || wire.get("actionId").and_then(Value::as_str) != Some("choose")
    {
        return Err(format!("author action wire is not the exact decision: {wire}").into());
    }
    Ok(())
}

struct ActionSend<'a> {
    actor: &'a Account,
    author: &'a Account,
    conversation: &'a str,
    surface_id: &'a str,
    version: u64,
    hash: &'a str,
    action_id: &'a str,
    scratch: &'a Path,
}

fn action_command(send: &ActionSend<'_>) -> e2e::Result<Vec<String>> {
    let path = send.scratch.join(format!("action-{}.json", send.action_id));
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "surfaceId": send.surface_id,
            "version": send.version,
            "surfaceHash": send.hash,
            "actionId": send.action_id,
            "values": {"choice": "yes"},
        }))?,
    )?;
    Ok(vec![
        "surface".to_owned(),
        "send".to_owned(),
        "--account".to_owned(),
        send.actor.id.clone(),
        "--conversation".to_owned(),
        send.conversation.to_owned(),
        "--author".to_owned(),
        send.author.principal_id.clone(),
        "--action".to_owned(),
        path.to_string_lossy().into_owned(),
    ])
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
    let absent_id = unique("absent-task");
    let missing_output =
        rf_output(&bob_d.socket, &["task", "get", "--account", &bob.id, "--task-id", &absent_id])?;
    if missing_output.status.code() != Some(0) {
        return Err(format!(
            "absent task read exited {:?}: stdout={} stderr={}",
            missing_output.status.code(),
            String::from_utf8_lossy(&missing_output.stdout),
            String::from_utf8_lossy(&missing_output.stderr)
        )
        .into());
    }
    let missing: Value = serde_json::from_slice(&missing_output.stdout)?;
    if missing.get("ok").and_then(Value::as_bool) != Some(true)
        || !missing.get("body").is_some_and(Value::is_null)
    {
        return Err(format!("absent task was not reported as a null body: {missing}").into());
    }
    let proposal = scratch.join("task-propose.json");
    std::fs::write(
        &proposal,
        serde_json::to_vec(&json!({
            "task_id": unique("demo-b-proposal"),
            "conversation_id": conversation,
            "assignee": bob.principal_id,
            "title": "Demo B",
            "steps": [],
        }))?,
    )?;
    let proposal_path = proposal.to_string_lossy().into_owned();
    let refused = expect_typed_refusal(
        alice_d,
        &["task", "propose", "--account", &alice.id, "--body-file", &proposal_path],
        "invalid_request",
    )?;
    if refused["error"]["message"].as_str().is_none_or(|message| !message.contains("headless")) {
        return Err(
            format!("task propose refusal was not the human-account rule: {refused}").into()
        );
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

fn required_u64(value: &Value, field: &str) -> e2e::Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing {field}: {value}").into())
}

fn required_str<'a>(value: &'a Value, field: &str) -> e2e::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {field}: {value}").into())
}

fn action_row<'a>(view: &'a Value, action_id: &str) -> Option<&'a Value> {
    view.get("actions")?.as_array()?.iter().find(|row| {
        action_wire(row)
            .ok()
            .and_then(|wire| wire.get("actionId").and_then(Value::as_str).map(str::to_owned))
            == Some(action_id.to_owned())
    })
}

fn action_wire(row: &Value) -> e2e::Result<Value> {
    let wire = row
        .get("wire_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("action row has no wire: {row}"))?;
    let raw = decode_base64url(wire)?;
    Ok(serde_json::from_slice(&raw)?)
}

fn expect_typed_refusal(daemon: &Daemon, args: &[&str], code: &str) -> e2e::Result<Value> {
    let output = rf_output(&daemon.socket, args)?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    if output.status.code() != Some(1) {
        return Err(format!(
            "refusal exited {:?}, expected 1; stdout={stdout} stderr={stderr}",
            output.status.code()
        )
        .into());
    }
    let value: Value = serde_json::from_str(stdout.trim())?;
    if value.get("ok").and_then(Value::as_bool) != Some(false)
        || value.pointer("/error/code").and_then(Value::as_str) != Some(code)
    {
        return Err(format!("structured refusal missing {code}: {value}; stderr={stderr}").into());
    }
    if !stderr.contains(code) {
        return Err(format!("stderr lacks typed {code}: {stderr}").into());
    }
    Ok(value)
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
