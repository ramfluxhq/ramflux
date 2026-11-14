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
    let conversation = unique("conv-actions");
    let seed = "conversation seed";
    dm_send(&alice_d, &alice, &bob, &conversation, &unique("seed"), seed)?;
    wait_dm_texts(&bob_d, &bob, &conversation, &[seed])?;
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
        ("conversation.edit", "edit", vec!["--text", "edited text"]),
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

fn live(world: &mut World<'_>) -> e2e::Result<()> {
    let sent = require_submitted(world, "live conversation body")?;
    let message = required_str(&sent, "/body/message_id")?;
    wait_dm_texts(world.bob_daemon()?, world.bob, world.conversation, &["live conversation body"])?;
    expect_submitted(
        &mutate(world, "reply", message, &["--text", "live reply"])?,
        "conversation.reply",
    )?;
    expect_submitted(
        &mutate(world, "edit", message, &["--text", "live edit"])?,
        "conversation.edit",
    )?;
    expect_submitted(
        &mutate(world, "react", message, &["--token", "thumb"])?,
        "conversation.react",
    )?;
    expect_submitted(
        &mutate(world, "react", message, &["--token", "thumb", "--remove"])?,
        "conversation.react",
    )?;
    let peer = mutate_as_bob(world, message)?;
    expect_code(&peer, "conversation.delete", "not_authorized")?;
    expect_submitted(
        &mutate(world, "delete", message, &["--scope", "everyone"])?,
        "conversation.delete",
    )?;
    let local_sent = require_submitted(world, "local delete body")?;
    let local_id = required_str(&local_sent, "/body/message_id")?;
    let local = mutate(world, "delete", local_id, &["--scope", "local"])?;
    if local.pointer("/body/delivery_state").and_then(Value::as_str) != Some("local") {
        return Err(format!("local delete: {local}").into());
    }
    observe_typing(world)?;
    reconnect_bob(world)?;
    expect_empty_watch(&watch(world, 2)?)
}

fn observe_typing(world: &World<'_>) -> e2e::Result<()> {
    let before = texts(world)?;
    let socket = world.bob_daemon()?.socket.clone();
    let account = world.bob.id.clone();
    let conversation = world.conversation.to_owned();
    let ready = world.stack.root.join(unique("typing-ready"));
    let ready_for_child = ready.clone();
    let watched_account = account.clone();
    let worker = std::thread::spawn(move || {
        watch_at(&socket, &watched_account, &conversation, 12, Some(ready_for_child.as_path()))
            .map_err(|error| error.to_string())
    });
    wait_json(world.bob_daemon()?, &["account", "status", "--account", &account], |_| {
        ready.exists()
    })?;
    let op = unique("live-typing-op");
    let started = rf_json(
        &world.alice_d.socket,
        &[
            "conversation",
            "typing",
            "start",
            "--account",
            &world.alice.id,
            "--conversation",
            world.conversation,
            "--operation-id",
            &op,
        ],
    )?;
    let watched = join_watch(worker)?;
    if started.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("typing start: {started}; watch={watched}").into());
    }
    assert_typing_cleared(&watched)?;
    if texts(world)? != before {
        return Err(format!("typing changed message rows: {watched}").into());
    }
    Ok(())
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
    if delta > 6_000 {
        return Err(format!("typing clear took {delta} ms: {watched}").into());
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

fn reconnect_bob(world: &mut World<'_>) -> e2e::Result<()> {
    let current = world.bob_d.take().ok_or("bob daemon missing")?;
    let (socket, root) = crash_daemon(current)?;
    let restarted = start_daemon_at(socket, root)?;
    unlock_account(&restarted, world.bob)?;
    world.bob_d = Some(restarted);
    Ok(())
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

fn logs(world: &World<'_>) -> String {
    let bob = world.bob_d.as_ref();
    let daemons = bob.map_or_else(|| vec![world.alice_d], |daemon| vec![world.alice_d, daemon]);
    dump_logs(world.stack, &daemons)
}
