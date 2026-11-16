// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reply, edit, reaction, delete and typing through the rf binary, a real daemon and a real router.
//! Generation zero refuses the schema-gated methods with the existing `peer_upgrade_required` code.
//! The live branch runs when message schema v1 is active.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    Account, Daemon, Stack, boot_stack, configure_node, crash_daemon, create_account, dm_send,
    dump_logs, exchange_contacts, message_texts, rf_json, rf_json_timeout, start_daemon,
    start_daemon_at, unique, unlock_account, wait_dm_texts, wait_json,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

const REFUSAL: &str = "peer_upgrade_required";

struct World<'a> {
    stack: &'a Stack,
    alice_d: &'a Daemon,
    bob_d: Option<Daemon>,
    alice: &'a Account,
    bob: &'a Account,
    conversation: &'a str,
}

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn conversation_actions_reply_edit_react_delete_and_typing() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    settle_contact_requests(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.principal_commitment,
        &bob.principal_commitment,
    )?;
    let mut world = World {
        stack: &stack,
        alice_d: &alice_d,
        bob_d: Some(bob_d),
        alice: &alice,
        bob: &bob,
        conversation: &conversation,
    };
    if !ramflux_protocol::schema_profile::schema_v1_live() {
        eprintln!("conversation action live rows not exercised: message schema v1 is dormant");
        let seed = "conversation seed";
        dm_send(world.alice_d, world.alice, world.bob, world.conversation, &unique("seed"), seed)?;
        wait_dm_texts(world.bob_daemon()?, world.bob, world.conversation, &[seed])?;
        return dormant(&mut world, seed);
    }
    live(&mut world)
}

fn dormant(world: &mut World<'_>, seed: &str) -> e2e::Result<()> {
    let sent = drive_send(world, "conversation send body")?;
    let submitted =
        sent.pointer("/body/delivery_state").and_then(Value::as_str) == Some("submitted");
    let message_id = sent.pointer("/body/message_id").and_then(Value::as_str);
    if !submitted || message_id.is_none() {
        return Err(format!("conversation.send: {sent}; logs={}", logs(world)).into());
    }
    wait_dm_texts(
        world.bob_daemon()?,
        world.bob,
        world.conversation,
        &[seed, "conversation send body"],
    )
    .map_err(|error| format!("{error}; logs={}", logs(world)))?;
    let before = texts(world)?;
    refuse_mutations(world)?;
    let typing = world.alice_args(&[
        "conversation",
        "typing",
        "start",
        "--account",
        &world.alice.id,
        "--conversation",
        world.conversation,
        "--operation-id",
        &unique("typing-start-op"),
    ])?;
    expect_code(&typing, "message.focus", REFUSAL)?;
    let stop_op = unique("typing-stop-op");
    let stopped = world.alice_args(&[
        "conversation",
        "typing",
        "stop",
        "--account",
        &world.alice.id,
        "--conversation",
        world.conversation,
        "--operation-id",
        &stop_op,
    ])?;
    expect_code(&stopped, "message.submit", REFUSAL)?;
    let watched = watch(world, 2)?;
    expect_empty_watch(&watched)?;
    if texts(world)? != before {
        return Err("typing changed message rows".into());
    }
    reconnect_bob(world)?;
    expect_empty_watch(&watch(world, 2)?)?;
    Ok(())
}

fn refuse_mutations(world: &World<'_>) -> e2e::Result<()> {
    let message = "absent-target";
    for (method, action, extra) in [
        ("conversation.reply", "reply", vec!["--text", "reply text"]),
        ("conversation.edit", "edit", vec!["--text", "edited text", "--expected-revision", "0"]),
        ("conversation.react", "react", vec!["--token", "thumb"]),
        ("conversation.react", "react", vec!["--token", "thumb", "--remove"]),
        ("conversation.delete", "delete", vec!["--scope", "local"]),
        ("conversation.delete", "delete", vec!["--scope", "everyone"]),
    ] {
        let op = unique("mut-op");
        let mut args = vec![
            "conversation",
            action,
            "--account",
            world.alice.id.as_str(),
            "--conversation",
            world.conversation,
            "--message",
            message,
            "--operation-id",
            op.as_str(),
        ];
        args.extend(extra);
        expect_code(&rf_json(&world.alice_d.socket, &args)?, method, REFUSAL)?;
    }
    let op = unique("peer-delete-op");
    let peer = rf_json(
        &world.bob_daemon()?.socket,
        &[
            "conversation",
            "delete",
            "--account",
            &world.bob.id,
            "--conversation",
            world.conversation,
            "--message",
            message,
            "--scope",
            "everyone",
            "--operation-id",
            &op,
        ],
    )?;
    expect_code(&peer, "conversation.delete", REFUSAL)
}

/// Typed content JSON carries event ids as padded standard base64; the view `id` is unpadded
/// base64url. Compare the normalized spelling of the same 32 bytes.
fn same_event_id(typed: &str, view_id: &str) -> bool {
    let normalized: String = typed
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    normalized == view_id
}

fn live(world: &mut World<'_>) -> e2e::Result<()> {
    let sent = require_submitted(world, "live conversation body")?;
    let message = required_str(&sent, "/body/message_id")?.to_owned();
    let original =
        wait_view(world, false, &message, |view| view["text"] == "live conversation body")?;
    expect_kind(&original, "message")?;
    let base = original.get("revision").and_then(Value::as_u64).unwrap_or(0).to_string();
    let reply = mutate(world, "reply", &message, &["--text", "live reply"])?;
    expect_submitted(&reply, "conversation.reply")?;
    let reply_id = required_str(&reply, "/body/message_id")?.to_owned();
    let reply_view = wait_view(world, false, &reply_id, |view| {
        view.pointer("/content/message/replyTo/id")
            .and_then(Value::as_str)
            .is_some_and(|id| same_event_id(id, &message))
            && view["text"] == "live reply"
    })?;
    expect_kind(&reply_view, "message")?;
    let edited =
        mutate(world, "edit", &message, &["--text", "live edit", "--expected-revision", &base])?;
    expect_submitted(&edited, "conversation.edit")?;
    let edited_view = wait_view(world, false, &message, |view| {
        view.pointer("/content/message/text").and_then(Value::as_str) == Some("live edit")
            && view["revision"] == 1
            && view["edited"] == true
    })?;
    if edited_view["text"] != "live edit" || edited_view["kind"].as_str() != Some("message") {
        return Err(format!("recipient edit view: {edited_view}").into());
    }
    expect_stale_edit_conflict(world, &message)?;
    expect_submitted(&mutate(world, "react", &message, &["--token", "👍"])?, "conversation.react")?;
    wait_view(world, false, &message, |view| reaction_tokens(view).contains(&"👍"))?;
    expect_submitted(
        &mutate(world, "react", &message, &["--token", "👍", "--remove"])?,
        "conversation.react",
    )?;
    let cleared = wait_view(world, false, &message, |view| !reaction_tokens(view).contains(&"👍"))?;
    if cleared.pointer("/content/message/text").and_then(Value::as_str) != Some("live edit") {
        return Err(format!("reaction removal changed the edit: {cleared}").into());
    }
    let peer = mutate_as_bob(world, &message)?;
    expect_code(&peer, "conversation.delete", "not_authorized")?;
    expect_submitted(
        &mutate(world, "delete", &reply_id, &["--scope", "everyone"])?,
        "conversation.delete",
    )?;
    let tombstone = wait_view(world, false, &reply_id, |view| view["state"] == "tombstone")?;
    if tombstone["erasure"]["scope"] != "everyone"
        || !tombstone["text"].is_null()
        || !tombstone["content"].is_null()
        || tombstone.to_string().contains("live reply")
    {
        return Err(format!("recipient tombstone: {tombstone}").into());
    }
    let local_sent = require_submitted(world, "local delete body")?;
    let local_id = required_str(&local_sent, "/body/message_id")?.to_owned();
    wait_view(world, false, &local_id, |view| view["text"] == "local delete body")?;
    let local = mutate(world, "delete", &local_id, &["--scope", "local"])?;
    if local.pointer("/body/delivery_state").and_then(Value::as_str) != Some("local") {
        return Err(format!("local delete: {local}").into());
    }
    let author_copy = wait_view(world, true, &local_id, |view| {
        view["state"] == "tombstone" && view["erasure"]["scope"] == "local"
    })?;
    if !author_copy["content"].is_null() {
        return Err(format!("local delete left author content: {author_copy}").into());
    }
    let peer_copy = wait_view(world, false, &local_id, |view| view["text"] == "local delete body")?;
    if peer_copy["state"] == "tombstone" {
        return Err(format!("local delete reached the peer: {peer_copy}").into());
    }
    let typing = observe_typing(world)?;
    assert_typing_absent(world, &typing)?;
    if wait_view(world, false, &local_id, |view| view["text"] == "local delete body").is_err() {
        return Err("peer lost the locally deleted copy after typing".into());
    }
    Ok(())
}

const NODE_STORES: &[&str] =
    &["ramflux-router", "ramflux-federation", "ramflux-gateway", "ramflux-retention"];
/// One client row key that the typing at-rest comparison skips, and why typing cannot live there.
enum ClientKey {
    /// The whole key.
    Exact(&'static str),
    /// `prefix` followed by exactly one non-empty segment without a further `/`.
    Scoped(&'static str),
}

/// Exact client `runtime_actor_state` keys (and the `runtime_outbox` rows that publish them).
const CLIENT_EXEMPT: &[(ClientKey, &str)] = &[
    (
        ClientKey::Exact("own-contact/last-refresh"),
        "wall-clock stamp of the contact backfill timer",
    ),
    (ClientKey::Exact("sync/tick"), "monotonic tick counter of the sync status timer"),
    (ClientKey::Exact("sync/status"), "published sync status snapshot, no message data"),
    (ClientKey::Exact("sync/health"), "published node health snapshot, no message data"),
    (ClientKey::Exact("sync/status/event"), "sequence and time of the last status event"),
    (ClientKey::Exact("sync/health/event"), "sequence and time of the last health event"),
    (ClientKey::Exact("account/networking"), "connectivity state flipped by the offline step"),
    (ClientKey::Exact("inbox/recovery-revision"), "revision stamped on every reconnect"),
    (ClientKey::Scoped("dm-pair/session/"), "message ratchet state, advanced by durable traffic"),
    (ClientKey::Scoped("dm-pair/ephemeral-seals/"), "seal counter, advanced by any sealed frame"),
    (ClientKey::Scoped("dm-pair/active/"), "active pair index written with the ratchet"),
    (ClientKey::Scoped("dm-pair/local/"), "local pair marker written with the ratchet"),
];

/// Exact `runtime_outbox` row kinds (first column) that the comparison skips.
const CLIENT_OUTBOX_KINDS: &[(&str, &str)] = &[(
    "device_directory",
    "directory refreshes drain after a daemon restart; no conversation data",
)];

/// Exact node store tables whose rows change on every handshake or replay-guard admission.
/// Anything not listed here must be identical before and after the typing phase.
const NODE_EXEMPT: &[(&str, &str, &str)] = &[
    ("ramflux-gateway", "gateway_sessions_v2", "one row per session; every reconnect writes it"),
    ("ramflux-gateway", "gateway_session_expiry_v2", "expiry index of gateway_sessions_v2"),
    ("ramflux-gateway", "gateway_resume_tokens_v2", "resume token issued by every handshake"),
    ("ramflux-gateway", "gateway_resume_expiry_v2", "expiry index of gateway_resume_tokens_v2"),
    ("ramflux-gateway", "gateway_replay_entries_v3", "replay-guard tuples of admitted envelopes"),
    ("ramflux-gateway", "gateway_replay_expiry_v3", "expiry index of the replay tuples"),
    ("ramflux-gateway", "gateway_replay_metadata_v3", "replay-guard counters"),
    (
        "ramflux-gateway",
        "gateway_replay_owner_expiry_v3",
        "owner expiry index of the replay tuples",
    ),
    ("ramflux-gateway", "gateway_replay_root_expiry_v3", "root expiry index of the replay tuples"),
    ("ramflux-gateway", "gateway_replay_roots_v3", "per-root replay-guard budget rows"),
    (
        "ramflux-gateway",
        "gateway_state_v1",
        "pre-auth admission counters bumped by every connection",
    ),
    ("ramflux-router", "router_session_entry_v1", "router session binding written on reconnect"),
    ("ramflux-router", "router_replay_tuple_v1", "router replay-guard tuples of admitted frames"),
    ("ramflux-router", "router_replay_expiry_v1", "expiry index of the router replay tuples"),
];
const STORE_CAP: u64 = 32 * 1024 * 1024;

type TableRows = BTreeMap<String, Vec<String>>;
type AccountTables = BTreeMap<String, TableRows>;

struct TypingObservation {
    ids: Vec<String>,
    before: Persistence,
}

struct Persistence {
    client: AccountTables,
    node: AccountTables,
    wal: Vec<String>,
    files: Vec<PathBuf>,
}

fn observe_typing(world: &mut World<'_>) -> e2e::Result<TypingObservation> {
    let before_ids = message_ids(world, false)?;
    let before = settled_stores(world)?;
    let mut ids = explicit_stop(world)?;
    ids.push(unforced_expiry(world)?);
    ids.push(replay_while_live(world)?);
    ids.push(offline_then_reconnect(world)?);
    let after_ids = message_ids(world, false)?;
    if after_ids != before_ids {
        return Err(format!(
            "typing changed message ids: before={before_ids:?} after={after_ids:?}"
        )
        .into());
    }
    Ok(TypingObservation { ids, before })
}

fn explicit_stop(world: &World<'_>) -> e2e::Result<Vec<String>> {
    let start_op = unique("live-typing-start");
    let stop_op = unique("live-typing-stop");
    let watched = watch_ready(world, 8, &start_op, Some(&stop_op))?;
    assert_typing_cleared(&watched)?;
    Ok(vec![start_op, stop_op])
}

/// No stop is sent. The watch must observe `active=false` for that indicator
/// within 5s of its `expires_at`. Silence after the active row fails.
fn unforced_expiry(world: &World<'_>) -> e2e::Result<String> {
    let operation = unique("live-typing-expire");
    let watched = watch_ready(world, 8, &operation, None)?;
    assert_unforced_expiry(&watched, 8)?;
    Ok(operation)
}

fn replay_while_live(world: &mut World<'_>) -> e2e::Result<String> {
    let operation = unique("live-typing-replay");
    let seen = watch_ready(world, 1, &operation, None)?;
    reconnect_bob(world)?;
    let again = watch(world, 1)?;
    expect_empty_watch(&again)?;
    let restarted = again["started_at_ms"].as_u64().ok_or("restarted watch started_at_ms")?;
    assert_replay_within_frame(&seen, restarted)?;
    Ok(operation)
}

fn offline_then_reconnect(world: &mut World<'_>) -> e2e::Result<String> {
    let operation = unique("live-typing-offline");
    let (socket, root) = take_bob(world)?;
    let emitted = match typing_emit(world, "start", &operation) {
        Ok(value) => value,
        Err(error) => {
            restore_bob(world, socket, root)?;
            return Err(error);
        }
    };
    restore_bob(world, socket, root)?;
    if emitted.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("typing while bob was offline: {emitted}").into());
    }
    let again = watch(world, 2)?;
    expect_empty_watch(&again)?;
    Ok(operation)
}

fn assert_unforced_expiry(watched: &Value, secs: u64) -> e2e::Result<()> {
    let started = watched["started_at_ms"].as_u64().ok_or("started_at_ms")?;
    let active = first_active(watched)?;
    let observed = active["observed_at_ms"].as_u64().ok_or("observed_at_ms")?;
    let expires_ms = frame_deadline_ms(active)?;
    let life = expires_ms.saturating_sub(observed);
    if !(1..=5_000).contains(&life) {
        return Err(
            format!("unforced typing lifetime {life} ms is outside 1..=5000: {active}").into()
        );
    }
    let window_end = started.saturating_add(secs.saturating_mul(1_000));
    if expires_ms > window_end {
        return Err(format!(
            "watch ended before the unforced typing deadline: expires={expires_ms} window_end={window_end}"
        )
        .into());
    }
    let author = active.get("author_anchor").and_then(Value::as_str).unwrap_or("");
    let rows = watched["indicators"].as_array().ok_or("indicators")?;
    let mut saw_clear = false;
    for row in rows {
        let at = row["observed_at_ms"].as_u64().ok_or("observed_at_ms")?;
        let row_author = row.get("author_anchor").and_then(Value::as_str).unwrap_or("");
        if row["active"].as_bool() == Some(true) && at >= expires_ms {
            return Err(
                format!("typing still active at {at} after deadline {expires_ms}: {row}").into()
            );
        }
        if row["active"].as_bool() == Some(false) && row_author == author {
            if at.abs_diff(expires_ms) > 5_000 {
                return Err(format!(
                    "unforced clear at {at} is more than 5s from deadline {expires_ms}: {row}"
                )
                .into());
            }
            saw_clear = true;
        }
    }
    if !saw_clear {
        return Err(format!(
            "unforced expiry saw no active=false row within 5s of {expires_ms}: {watched}"
        )
        .into());
    }
    Ok(())
}

fn assert_replay_within_frame(seen: &Value, restarted_at_ms: u64) -> e2e::Result<()> {
    let active = first_active(seen)?;
    let expires_ms = frame_deadline_ms(active)?;
    if restarted_at_ms >= expires_ms {
        return Err(format!(
            "reconnect watch started at {restarted_at_ms} after the frame deadline {expires_ms}: {active}"
        )
        .into());
    }
    Ok(())
}

fn first_active(watched: &Value) -> e2e::Result<&Value> {
    watched
        .get("indicators")
        .and_then(Value::as_array)
        .ok_or("indicators")?
        .iter()
        .find(|row| row.get("active").and_then(Value::as_bool) == Some(true))
        .ok_or_else(|| format!("peer did not show a live typing frame: {watched}").into())
}

fn frame_deadline_ms(row: &Value) -> e2e::Result<u64> {
    let expires_at = row.get("expires_at").and_then(Value::as_u64).ok_or("expires_at")?;
    if expires_at == 0 {
        return Err(format!("active typing frame has no deadline: {row}").into());
    }
    Ok(expires_at.saturating_mul(1_000))
}

fn watch_ready(
    world: &World<'_>,
    secs: u64,
    start_op: &str,
    stop_op: Option<&str>,
) -> e2e::Result<Value> {
    let daemon = world.bob_daemon()?;
    let socket = daemon.socket.clone();
    let account = world.bob.id.clone();
    let conversation = world.conversation.to_owned();
    let ready = world.stack.root.join(unique("typing-ready"));
    let ready_for_child = ready.clone();
    let watched_account = account.clone();
    let worker = std::thread::spawn(move || {
        watch_at(&socket, &watched_account, &conversation, secs, Some(ready_for_child.as_path()))
            .map_err(|error| error.to_string())
    });
    if let Err(error) =
        wait_json(daemon, &["account", "status", "--account", &account], |_| ready.exists())
    {
        let _ = join_watch(worker);
        return Err(error);
    }
    let started = match typing_emit(world, "start", start_op) {
        Ok(value) => value,
        Err(error) => {
            let _ = join_watch(worker);
            return Err(error);
        }
    };
    if let Some(operation) = stop_op {
        match typing_emit(world, "stop", operation) {
            Ok(stopped) if stopped.get("ok").and_then(Value::as_bool) == Some(true) => {}
            Ok(stopped) => {
                let watched = join_watch(worker)?;
                return Err(format!(
                    "typing stop: {stopped}; start={started}; watch={watched}; logs={}",
                    logs(world)
                )
                .into());
            }
            Err(error) => {
                let _ = join_watch(worker);
                return Err(error);
            }
        }
    }
    let watched = join_watch(worker)?;
    if started.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("typing start: {started}; watch={watched}").into());
    }
    Ok(watched)
}

fn typing_emit(world: &World<'_>, action: &str, operation: &str) -> e2e::Result<Value> {
    // Active frames are admitted at most once per 4 s cadence per conversation and target. A
    // frame inside that window reads `rate_limited`; the same operation id is retried until the
    // cadence opens, inside the bounded poll budget.
    wait_json(
        world.alice_d,
        &[
            "conversation",
            "typing",
            action,
            "--account",
            &world.alice.id,
            "--conversation",
            world.conversation,
            "--operation-id",
            operation,
        ],
        |value| value.pointer("/error/code").and_then(Value::as_str) != Some("rate_limited"),
    )
}

fn assert_typing_cleared(watched: &Value) -> e2e::Result<()> {
    let rows = watched.get("indicators").and_then(Value::as_array).ok_or("indicators")?;
    let mut active_at = None;
    let mut clear_at = None;
    for row in rows {
        let active = row.get("active").and_then(Value::as_bool).ok_or("active")?;
        let at = row.get("observed_at_ms").and_then(Value::as_u64).ok_or("observed_at_ms")?;
        if active && active_at.is_none() {
            active_at = Some(at);
        }
        if !active && active_at.is_some() && clear_at.is_none() {
            clear_at = Some(at);
        }
    }
    let (Some(shown), Some(cleared)) = (active_at, clear_at) else {
        return Err(format!("typing was not shown and cleared: {watched}").into());
    };
    let delta = cleared.saturating_sub(shown);
    if delta > 5_000 {
        return Err(format!("typing clear took {delta} ms: {watched}").into());
    }
    Ok(())
}

fn wait_view(
    world: &World<'_>,
    author: bool,
    message: &str,
    ready: impl Fn(&Value) -> bool,
) -> e2e::Result<Value> {
    let (daemon, account) =
        if author { (world.alice_d, world.alice) } else { (world.bob_daemon()?, world.bob) };
    let detail = wait_json(
        daemon,
        &[
            "dm",
            "read",
            "--account",
            &account.id,
            "--conversation",
            world.conversation,
            "--message",
            message,
        ],
        |value| value.get("message").is_some_and(&ready),
    )?;
    if detail["schema"] != "ramflux.message.read_model.v1" {
        return Err(format!("recipient read is not the durable read model: {detail}").into());
    }
    detail.get("message").cloned().ok_or_else(|| format!("message view missing: {detail}").into())
}

fn expect_kind(view: &Value, kind: &str) -> e2e::Result<()> {
    if view["kind"].as_str() != Some(kind) || view["state"].as_str() != Some("content") {
        return Err(format!("expected kind {kind}: {view}").into());
    }
    Ok(())
}

fn reaction_tokens(view: &Value) -> Vec<&str> {
    view["reactions"]
        .as_array()
        .map(|rows| rows.iter().filter_map(|row| row["token"].as_str()).collect())
        .unwrap_or_default()
}

fn message_ids(world: &World<'_>, author: bool) -> e2e::Result<Vec<String>> {
    let page = read_model(world, author, &["--limit", "100"])?;
    let rows = page["messages"].as_array().ok_or("durable message page missing")?;
    Ok(rows.iter().filter_map(|row| row["id"].as_str().map(str::to_owned)).collect())
}

fn assert_typing_absent(world: &World<'_>, typing: &TypingObservation) -> e2e::Result<()> {
    for author in [false, true] {
        let page = read_model(world, author, &["--limit", "100"])?;
        reject_typing_document(&page, &typing.ids)?;
        let changes = read_model(world, author, &["--after-seq", "0", "--limit", "100"])?;
        reject_typing_document(&changes, &typing.ids)?;
    }
    let after = capture_stores(world)?;
    assert_same_stores(&typing.before, &after)?;
    let mut needles = vec!["message.transient".to_owned()];
    needles.extend(typing.ids.iter().cloned());
    let mut files = typing.before.files.clone();
    files.extend(after.files);
    files.sort();
    files.dedup();
    scan_files(&files, &needles)
}

fn read_model(world: &World<'_>, author: bool, extra: &[&str]) -> e2e::Result<Value> {
    let (daemon, account) =
        if author { (world.alice_d, world.alice) } else { (world.bob_daemon()?, world.bob) };
    let mut args = vec![
        "dm".to_owned(),
        "read".to_owned(),
        "--account".to_owned(),
        account.id.clone(),
        "--conversation".to_owned(),
        world.conversation.to_owned(),
    ];
    args.extend(extra.iter().map(|part| (*part).to_owned()));
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    rf_json(&daemon.socket, &refs)
}

fn reject_typing_document(value: &Value, operation_ids: &[String]) -> e2e::Result<()> {
    let rendered = value.to_string();
    if rendered.contains("\"typing\"") {
        return Err(format!("typing content is in a durable read: {value}").into());
    }
    for operation in operation_ids {
        if rendered.contains(operation) {
            return Err(
                format!("typing operation {operation} is in a durable read: {value}").into()
            );
        }
    }
    for row in value_rows(value, "messages").into_iter().chain(value_rows(value, "changes")) {
        if row["kind"].as_str() == Some("typing") {
            return Err(format!("typing message row: {row}").into());
        }
    }
    Ok(())
}

fn value_rows<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value.get(key).and_then(Value::as_array).map(|rows| rows.iter().collect()).unwrap_or_default()
}

/// Earlier sends and reads still produce asynchronous receipts and acknowledgements. Take the
/// baseline only once consecutive captures agree, inside the bounded poll budget.
fn settled_stores(world: &World<'_>) -> e2e::Result<Persistence> {
    const AGREEING_CAPTURES: u32 = 4;
    let last = std::cell::RefCell::new(None::<Persistence>);
    let agreeing = std::cell::Cell::new(0_u32);
    wait_json(world.alice_d, &["account", "status", "--account", &world.alice.id], |_| {
        let Ok(now) = capture_stores(world) else {
            agreeing.set(0);
            return false;
        };
        let same = last
            .borrow()
            .as_ref()
            .is_some_and(|previous| assert_same_stores(previous, &now).is_ok());
        agreeing.set(if same { agreeing.get() + 1 } else { 0 });
        *last.borrow_mut() = Some(now);
        agreeing.get() >= AGREEING_CAPTURES
    })?;
    last.into_inner().ok_or_else(|| "no settled store capture".into())
}

fn capture_stores(world: &World<'_>) -> e2e::Result<Persistence> {
    let mut client = BTreeMap::new();
    let mut files = Vec::new();
    for (name, root, account) in [
        ("alice", world.alice_d.data_root.as_path(), world.alice.id.as_str()),
        ("bob", world.bob_daemon()?.data_root.as_path(), world.bob.id.as_str()),
    ] {
        let (tables, paths) = client_tables(root, account)?;
        client.insert(name.to_owned(), tables);
        files.extend(paths);
    }
    let state = world.stack.root.join("state");
    let mut node = BTreeMap::new();
    for service in NODE_STORES {
        let path = state.join(format!("{service}.redb"));
        require_regular(&path)?;
        files.push(path.clone());
        node.insert((*service).to_owned(), ramflux_node_core::logical_redb_rows(&path)?);
    }
    let wal = ramflux_node_core::logical_wal_records(&state.join("ramflux-router.redb.wal"))?;
    for path in &wal.files {
        require_regular(path)?;
    }
    files.extend(wal.files);
    Ok(Persistence { client, node, wal: wal.records, files })
}

fn client_tables(data_root: &Path, account: &str) -> e2e::Result<(TableRows, Vec<PathBuf>)> {
    let vault = ramflux_storage::read_existing_vault_secret(data_root, account)?;
    let kek = ramflux_sdk::account_db_key_encryption_key(&vault, e2e::PASSPHRASE.as_bytes());
    let (path, key) = ramflux_storage::load_account_db_key(data_root, account, &kek)?;
    require_regular(&path)?;
    let tables = ramflux_storage::logical_table_rows(&path, &key)?;
    let mut files = vec![path.clone()];
    if let Some(wal) = sqlite_wal(&path)? {
        files.push(wal);
    }
    Ok((tables, files))
}

fn sqlite_wal(db: &Path) -> e2e::Result<Option<PathBuf>> {
    let Some(name) = db.file_name().and_then(|value| value.to_str()) else {
        return Err(format!("account database has no file name: {}", db.display()).into());
    };
    let sibling = db.with_file_name(format!("{name}-wal"));
    match std::fs::metadata(&sibling) {
        Ok(meta) if meta.file_type().is_file() => Ok(Some(sibling)),
        Ok(_) => Err(format!("account wal is not a regular file: {}", sibling.display()).into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("stat {}: {error}", sibling.display()).into()),
    }
}

fn require_regular(path: &Path) -> e2e::Result<()> {
    let meta =
        std::fs::metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    if meta.file_type().is_file() {
        Ok(())
    } else {
        Err(format!("not a regular storage file: {}", path.display()).into())
    }
}

fn assert_same_stores(before: &Persistence, after: &Persistence) -> e2e::Result<()> {
    let left = comparable(before);
    let right = comparable(after);
    if let Some(diff) = nested_diff("client", &left.client, &right.client) {
        return Err(diff.into());
    }
    if let Some(diff) = nested_diff("node", &left.node, &right.node) {
        return Err(diff.into());
    }
    if left.wal != right.wal {
        let source = if left.wal.len() > right.wal.len() { &left.wal } else { &right.wal };
        return Err(format!(
            "router wal changed: before={} after={} sample={}",
            left.wal.len(),
            right.wal.len(),
            sample(source.first().map_or("", String::as_str))
        )
        .into());
    }
    Ok(())
}

fn comparable(snapshot: &Persistence) -> Persistence {
    let mut client = BTreeMap::new();
    for (account, tables) in &snapshot.client {
        let mut kept = BTreeMap::new();
        for (table, rows) in tables {
            kept.insert(
                table.clone(),
                rows.iter().filter(|row| !exempt_client_row(table, row)).cloned().collect(),
            );
        }
        client.insert(account.clone(), kept);
    }
    Persistence {
        client,
        // Only the exact handshake and replay-guard tables listed in NODE_EXEMPT are skipped.
        node: snapshot
            .node
            .iter()
            .map(|(service, tables)| {
                let kept = tables
                    .iter()
                    .filter(|(table, _)| !exempt_node_table(service, table))
                    .map(|(table, rows)| (table.clone(), rows.clone()))
                    .collect();
                (service.clone(), kept)
            })
            .collect(),
        wal: snapshot.wal.clone(),
        files: Vec::new(),
    }
}

fn exempt_node_table(service: &str, table: &str) -> bool {
    NODE_EXEMPT.iter().any(|(svc, name, _)| *svc == service && *name == table)
}

fn exempt_client_row(table: &str, line: &str) -> bool {
    let key = match table {
        "runtime_actor_state" => field(line, 0),
        "runtime_outbox" => {
            if CLIENT_OUTBOX_KINDS.iter().any(|(kind, _)| *kind == field(line, 0)) {
                return true;
            }
            field(line, 2)
        }
        _ => return false,
    };
    CLIENT_EXEMPT.iter().any(|(entry, _)| match entry {
        ClientKey::Exact(exact) => key == *exact,
        ClientKey::Scoped(prefix) => {
            key.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
        }
    })
}

fn rows_of<'a>(tables: Option<&'a TableRows>, table: &str) -> &'a [String] {
    match tables.and_then(|rows| rows.get(table)) {
        Some(rows) => rows.as_slice(),
        None => &[],
    }
}

fn field(line: &str, index: usize) -> &str {
    line.split('\t').nth(index).unwrap_or("")
}

fn nested_diff(label: &str, before: &AccountTables, after: &AccountTables) -> Option<String> {
    let mut names = before.keys().chain(after.keys()).collect::<Vec<_>>();
    names.sort();
    names.dedup();
    for name in names {
        let left = before.get(name);
        let right = after.get(name);
        let mut tables = left.map(|rows| rows.keys().collect::<Vec<_>>()).unwrap_or_default();
        tables.extend(right.map(|rows| rows.keys().collect::<Vec<_>>()).unwrap_or_default());
        tables.sort();
        tables.dedup();
        for table in tables {
            let before_rows = rows_of(left, table);
            let after_rows = rows_of(right, table);
            if before_rows != after_rows {
                let extra = after_rows.iter().find(|row| !before_rows.contains(row));
                let missing = before_rows.iter().find(|row| !after_rows.contains(row));
                return Some(format!(
                    "{label}.{name}.{table} before={} after={} sample={}",
                    before_rows.len(),
                    after_rows.len(),
                    sample(extra.or(missing).map_or("", String::as_str))
                ));
            }
        }
    }
    None
}

fn sample(row: &str) -> String {
    let mut text = row.chars().take(48).collect::<String>();
    if row.chars().count() > 48 {
        text.push_str("...");
    }
    text
}

fn scan_files(files: &[PathBuf], needles: &[String]) -> e2e::Result<()> {
    if files.len() > 4_000 {
        return Err("typing at-rest scan exceeded 4000 files".into());
    }
    for path in files {
        let meta =
            std::fs::metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
        if !meta.file_type().is_file() {
            return Err(format!("refusing to read non-regular path {}", path.display()).into());
        }
        if meta.len() > STORE_CAP {
            return Err(format!("typing at-rest file exceeds 32 MiB: {}", path.display()).into());
        }
        let bytes =
            std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
        for needle in needles {
            if !needle.is_empty()
                && bytes.windows(needle.len()).any(|window| window == needle.as_bytes())
            {
                return Err(format!("typing marker {needle} at rest in {}", path.display()).into());
            }
        }
    }
    Ok(())
}

fn drive_send(world: &World<'_>, text: &str) -> e2e::Result<Value> {
    let op = unique("send-op");
    wait_json(
        world.alice_d,
        &[
            "conversation",
            "send",
            "--account",
            &world.alice.id,
            "--conversation",
            world.conversation,
            "--text",
            text,
            "--operation-id",
            &op,
        ],
        send_settled,
    )
}

fn send_settled(value: &Value) -> bool {
    if value.pointer("/body/delivery_state").and_then(Value::as_str) == Some("submitted") {
        return true;
    }
    let code = value.pointer("/error/code").and_then(Value::as_str).unwrap_or("");
    value.get("ok").and_then(Value::as_bool) == Some(false)
        && !matches!(code, "not_connected" | "NetworkingPending" | "ephemeral_unavailable")
}

fn require_submitted(world: &World<'_>, text: &str) -> e2e::Result<Value> {
    let sent = drive_send(world, text)?;
    if sent.pointer("/body/delivery_state").and_then(Value::as_str) != Some("submitted") {
        return Err(format!("conversation.send: {sent}; logs={}", logs(world)).into());
    }
    Ok(sent)
}

fn mutate(world: &World<'_>, action: &str, message: &str, extra: &[&str]) -> e2e::Result<Value> {
    let op = unique("live-op");
    let mut args = vec![
        "conversation".to_owned(),
        action.to_owned(),
        "--account".to_owned(),
        world.alice.id.clone(),
        "--conversation".to_owned(),
        world.conversation.to_owned(),
        "--message".to_owned(),
        message.to_owned(),
        "--operation-id".to_owned(),
        op,
    ];
    args.extend(extra.iter().map(|part| (*part).to_owned()));
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    rf_json(&world.alice_d.socket, &refs)
}

fn mutate_as_bob(world: &World<'_>, message: &str) -> e2e::Result<Value> {
    let op = unique("peer-live-op");
    rf_json(
        &world.bob_daemon()?.socket,
        &[
            "conversation",
            "delete",
            "--account",
            &world.bob.id,
            "--conversation",
            world.conversation,
            "--message",
            message,
            "--scope",
            "everyone",
            "--operation-id",
            &op,
        ],
    )
}

fn expect_stale_edit_conflict(world: &World<'_>, message: &str) -> e2e::Result<()> {
    let conflict =
        mutate(world, "edit", message, &["--text", "stale edit", "--expected-revision", "0"])?;
    expect_code(&conflict, "conversation.edit", "edit_conflict")?;
    if conflict.pointer("/body/code").and_then(Value::as_i64) != Some(7)
        || conflict.pointer("/error/details/target").and_then(Value::as_str) != Some(message)
        || conflict.pointer("/error/details/expected").and_then(Value::as_u64) != Some(2)
        || conflict.pointer("/error/details/received").and_then(Value::as_u64) != Some(1)
    {
        return Err(format!("edit_conflict details: {conflict}").into());
    }
    let kept = wait_view(world, false, message, |view| {
        view.pointer("/content/message/text").and_then(Value::as_str) == Some("live edit")
            && view["revision"] == 1
    })?;
    if kept["text"] != "live edit" {
        return Err(format!("recipient lost the winning revision: {kept}").into());
    }
    Ok(())
}

fn expect_submitted(value: &Value, method: &str) -> e2e::Result<()> {
    if value.get("ok").and_then(Value::as_bool) != Some(true)
        || value.get("method").and_then(Value::as_str) != Some(method)
        || value.pointer("/body/delivery_state").and_then(Value::as_str) != Some("submitted")
    {
        return Err(format!("{method}: {value}").into());
    }
    Ok(())
}

fn expect_code(value: &Value, method: &str, code: &str) -> e2e::Result<()> {
    if value.get("ok").and_then(Value::as_bool) != Some(false)
        || value.get("method").and_then(Value::as_str) != Some(method)
        || value.pointer("/error/code").and_then(Value::as_str) != Some(code)
    {
        return Err(format!("{method} expected {code}: {value}").into());
    }
    Ok(())
}

fn expect_empty_watch(value: &Value) -> e2e::Result<()> {
    let rows = value.get("indicators").and_then(Value::as_array).ok_or("watch indicators")?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) || !rows.is_empty() {
        return Err(format!("watch was not empty: {value}").into());
    }
    Ok(())
}

fn texts(world: &World<'_>) -> e2e::Result<Vec<String>> {
    let read = rf_json(
        &world.bob_daemon()?.socket,
        &["dm", "read", "--account", &world.bob.id, "--conversation", world.conversation],
    )?;
    Ok(message_texts(&read))
}

fn watch(world: &World<'_>, secs: u64) -> e2e::Result<Value> {
    watch_at(&world.bob_daemon()?.socket, &world.bob.id, world.conversation, secs, None)
}

fn watch_at(
    socket: &std::path::Path,
    account: &str,
    conversation: &str,
    secs: u64,
    ready: Option<&std::path::Path>,
) -> e2e::Result<Value> {
    let mut args = vec![
        "conversation".to_owned(),
        "typing".to_owned(),
        "watch".to_owned(),
        "--account".to_owned(),
        account.to_owned(),
        "--conversation".to_owned(),
        conversation.to_owned(),
        "--for-secs".to_owned(),
        secs.to_string(),
    ];
    if let Some(path) = ready {
        args.push("--ready-file".to_owned());
        args.push(path.display().to_string());
    }
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    rf_json_timeout(socket, &refs, Duration::from_secs(secs.saturating_add(8)))
}

fn join_watch(worker: std::thread::JoinHandle<Result<Value, String>>) -> e2e::Result<Value> {
    match worker.join() {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.into()),
        Err(_panic) => Err("typing watch thread panicked".into()),
    }
}

fn take_bob(world: &mut World<'_>) -> e2e::Result<(PathBuf, PathBuf)> {
    let current = world.bob_d.take().ok_or("bob daemon missing")?;
    crash_daemon(current)
}

fn restore_bob(world: &mut World<'_>, socket: PathBuf, root: PathBuf) -> e2e::Result<()> {
    let restarted = start_daemon_at(socket, root)?;
    unlock_account(&restarted, world.bob)?;
    world.bob_d = Some(restarted);
    Ok(())
}

fn reconnect_bob(world: &mut World<'_>) -> e2e::Result<()> {
    let (socket, root) = take_bob(world)?;
    restore_bob(world, socket, root)
}

fn required_str<'a>(value: &'a Value, pointer: &str) -> e2e::Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {pointer} in {value}").into())
}

impl World<'_> {
    fn bob_daemon(&self) -> e2e::Result<&Daemon> {
        self.bob_d.as_ref().ok_or("bob daemon missing".into())
    }

    fn alice_args(&self, args: &[&str]) -> e2e::Result<Value> {
        rf_json(&self.alice_d.socket, args)
    }
}

#[test]
fn unforced_expiry_requires_an_observed_clear() {
    let active = serde_json::json!({
        "active": true,
        "observed_at_ms": 1_000_100_u64,
        "expires_at": 1_005_u64,
        "author_anchor": "alice",
    });
    let silent = serde_json::json!({
        "started_at_ms": 1_000_000_u64,
        "indicators": [active],
    });
    let silent_error = assert_unforced_expiry(&silent, 8).expect_err("silence is not a clear");
    assert!(
        silent_error.to_string().contains("active=false"),
        "test: silence after one active row must fail: {silent_error}"
    );
    let other_author = serde_json::json!({
        "started_at_ms": 1_000_000_u64,
        "indicators": [
            active,
            {
                "active": false,
                "observed_at_ms": 1_005_200_u64,
                "expires_at": 1_005_u64,
                "author_anchor": "bob",
            }
        ],
    });
    let other_error =
        assert_unforced_expiry(&other_author, 8).expect_err("another author is not this clear");
    assert!(
        other_error.to_string().contains("active=false"),
        "test: a clear for a different author does not prove this indicator expired: {other_error}"
    );
    let cleared = serde_json::json!({
        "started_at_ms": 1_000_000_u64,
        "indicators": [
            active,
            {
                "active": false,
                "observed_at_ms": 1_005_400_u64,
                "expires_at": 1_005_u64,
                "author_anchor": "alice",
            }
        ],
    });
    assert_unforced_expiry(&cleared, 8).expect("a clear within 5s of expires_at");
    let late = serde_json::json!({
        "started_at_ms": 1_000_000_u64,
        "indicators": [
            {
                "active": true,
                "observed_at_ms": 1_000_100_u64,
                "expires_at": 1_005_u64,
                "author_anchor": "alice",
            },
            {
                "active": false,
                "observed_at_ms": 1_011_000_u64,
                "expires_at": 1_005_u64,
                "author_anchor": "alice",
            }
        ],
    });
    let late_error = assert_unforced_expiry(&late, 8).expect_err("a late clear");
    assert!(
        late_error.to_string().contains("5s"),
        "test: a clear more than 5s from expires_at fails: {late_error}"
    );
}

#[test]
fn only_listed_client_rows_are_exempt() {
    for (table, row) in [
        ("runtime_actor_state", "dm-pair/session/abc\t01"),
        ("runtime_outbox", "runtime_actor_state\tupdate\tdm-pair/ephemeral-seals/1\t{}"),
        ("runtime_actor_state", "dm-pair/active/pair\t01"),
        ("runtime_actor_state", "dm-pair/local/session\t01"),
        ("runtime_actor_state", "sync/tick\t7"),
        ("runtime_actor_state", "sync/status/event\t{}"),
        ("runtime_actor_state", "own-contact/last-refresh\t1"),
        ("runtime_actor_state", "account/networking\t{}"),
        ("runtime_actor_state", "inbox/recovery-revision\t3"),
        ("runtime_outbox", "device_directory\tupdate\tx\t{}"),
    ] {
        assert!(exempt_client_row(table, row), "test: {table} row `{row}` is listed as exempt");
    }
    for (table, row) in [
        ("runtime_actor_state", "dm-pair/retired/abc\t01"),
        ("runtime_actor_state", "dm-pair/session/abc/extra\t01"),
        ("runtime_actor_state", "dm-pair/session/\t01"),
        ("runtime_actor_state", "sync/attachment/a\t01"),
        ("runtime_actor_state", "sync/tickets\t01"),
        ("runtime_actor_state", "own-contact/last-refresh-extra\t1"),
        ("runtime_outbox", "runtime_actor_state\tupdate\tsync/attachment/a\t{}"),
        ("runtime_outbox", "device_directory_x\tupdate\tx\t{}"),
        ("message_projection", "dm-pair/session/abc"),
        ("outbox_queue", "id\tenv\tclass\tstate\tcipher"),
        ("local_event_log", "event\ttype\tok\tok\tbody"),
        ("receipt_projection", "receipt\tconv\tmsg\tread\tdevice"),
    ] {
        assert!(!exempt_client_row(table, row), "test: {table} row `{row}` must be compared");
    }
}

fn node_snapshot(service: &str, table: &str, rows: &[&str]) -> Persistence {
    let tables = BTreeMap::from([(
        table.to_owned(),
        rows.iter().map(|row| (*row).to_owned()).collect::<Vec<_>>(),
    )]);
    Persistence {
        client: BTreeMap::new(),
        node: BTreeMap::from([(service.to_owned(), tables)]),
        wal: Vec::new(),
        files: Vec::new(),
    }
}

#[test]
fn a_new_unlisted_node_table_that_changes_during_typing_fails_the_comparison() {
    for (service, table) in NODE_EXEMPT.iter().map(|(service, table, _)| (*service, *table)) {
        let result = assert_same_stores(
            &node_snapshot(service, table, &["a"]),
            &node_snapshot(service, table, &["a", "b"]),
        );
        assert!(result.is_ok(), "test: listed table {service}.{table} may change: {result:?}");
    }
    for (service, table) in [
        ("ramflux-gateway", "gateway_typing_cache_v1"),
        ("ramflux-gateway", "gateway_frames_v2"),
        ("ramflux-gateway", "gateway_call_intent_v1"),
        ("ramflux-gateway", "gateway_sessions_v2_shadow"),
        ("ramflux-router", "router_inbox_v1"),
        ("ramflux-router", "gateway_sessions_v2"),
        ("ramflux-federation", "federation_session_log_v1"),
        ("ramflux-retention", "retention_replay_notes_v1"),
    ] {
        let result = assert_same_stores(
            &node_snapshot(service, table, &["a"]),
            &node_snapshot(service, table, &["a", "b"]),
        );
        assert!(
            result.is_err(),
            "test: unlisted table {service}.{table} must fail when it changes"
        );
    }
}

fn logs(world: &World<'_>) -> String {
    let bob = world.bob_d.as_ref();
    let daemons = bob.map_or_else(|| vec![world.alice_d], |daemon| vec![world.alice_d, daemon]);
    dump_logs(world.stack, &daemons)
}

/// A first message to a contact whose request is still in flight is refused until the request
/// settles, so wait for both outbound requests to read accepted before the first send.
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

/// The packed HLC is about 1.2e17, above 2^53. A read through the CLI and the I-JSON ingress
/// guard must carry the split pair and never the packed field.
fn expect_split_hlc(read: &Value) -> e2e::Result<()> {
    let rows = read.get("messages").and_then(Value::as_array).ok_or("read has no messages")?;
    if rows.is_empty() {
        return Err("read returned no message rows".into());
    }
    for row in rows {
        let ms = row.get("hlc_ms").and_then(Value::as_u64).ok_or("row has no hlc_ms")?;
        if ms == 0 || ms >= 1 << 53 || row.get("hlc_logical").and_then(Value::as_u64).is_none() {
            return Err(format!("row carries a bad HLC pair: {row}").into());
        }
        let sequence = row.get("device_sequence").and_then(Value::as_str).ok_or("no sequence")?;
        if sequence.len() != 20 || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("device_sequence is not a 20-digit decimal string: {row}").into());
        }
        if row.get("hlc").is_some() {
            return Err(format!("row still carries the packed hlc: {row}").into());
        }
    }
    Ok(())
}

fn first_send(
    daemon: &Daemon,
    account: &Account,
    conversation: &str,
    text: &str,
) -> e2e::Result<()> {
    let op = unique("first-send-op");
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
        send_settled,
    )?;
    if sent.pointer("/body/delivery_state").and_then(Value::as_str) != Some("submitted") {
        return Err(format!("first conversation.send was not submitted: {sent}").into());
    }
    Ok(())
}

/// Becoming friends creates the canonical direct conversation on both sides: each side can send
/// the very first message with no seed message, no sibling device and no Surface.
#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn befriending_creates_the_direct_conversation_on_both_sides() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    settle_contact_requests(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &alice.principal_commitment,
        &bob.principal_commitment,
    )?;
    let from_alice = unique("first-from-alice");
    let from_bob = unique("first-from-bob");
    let daemons = [&alice_d, &bob_d];
    first_send(&alice_d, &alice, &conversation, &from_alice)
        .and_then(|()| {
            wait_dm_texts(&bob_d, &bob, &conversation, &[from_alice.as_str()])
                .and_then(|read| expect_split_hlc(&read))
        })
        .and_then(|()| first_send(&bob_d, &bob, &conversation, &from_bob))
        .and_then(|()| {
            wait_dm_texts(&alice_d, &alice, &conversation, &[from_bob.as_str()]).map(drop)
        })
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &daemons)).into())
}
