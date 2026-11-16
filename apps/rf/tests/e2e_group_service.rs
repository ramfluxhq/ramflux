// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Three real accounts see one group rename as the same service row between two messages.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use e2e::{
    boot_stack, configure_node, create_account, dump_logs, exchange_contacts, group_create,
    group_send, rf_json, shutdown_daemon, start_daemon, start_daemon_at, unique, unlock_account,
    wait_json, wait_receive_settled,
};
use serde_json::Value;

const SCENARIO_BUDGET: Duration = Duration::from_secs(240);
const POLL_BUDGET: Duration = Duration::from_secs(90);
const BEFORE: &str = "before the rename";
const AFTER: &str = "after the rename";
const RENAMED: &str = "Renamed checklist";

struct Scene<'a> {
    stack: &'a e2e::Stack,
    alice: &'a e2e::Account,
    bob: &'a e2e::Account,
    carol: &'a e2e::Account,
    group: &'a str,
    deadline: Instant,
}

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn group_rename_is_one_service_row_between_messages() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    let carol_d = start_daemon(&stack, "carol")?;
    let (alice, bob, carol) = open_accounts(&stack, &alice_d, &bob_d, &carol_d)?;
    let group = unique("e2e-group-service");
    let scene = Scene {
        stack: &stack,
        alice: &alice,
        bob: &bob,
        carol: &carol,
        group: &group,
        deadline: Instant::now() + SCENARIO_BUDGET,
    };
    reserve_poll(scene.deadline)?;
    group_create(&alice_d, &alice, &group, &[&bob, &carol])?;
    land_before(&scene, &alice_d, &[(&alice_d, &alice), (&bob_d, &bob), (&carol_d, &carol)])?;
    let stopped = shutdown_daemon(carol_d)?;
    let row = rename_online(&scene, &alice_d, &bob_d)?;
    let carol_d = start_settled(&scene, stopped, &carol, &[&alice_d, &bob_d], &row)?;
    let bob_d = restart_settled(&scene, bob_d, &bob, &[&alice_d, &carol_d], &row)?;
    promote_bob(&scene, &alice_d, &bob_d, &carol_d, &row)
}

fn open_accounts(
    stack: &e2e::Stack,
    alice_d: &e2e::Daemon,
    bob_d: &e2e::Daemon,
    carol_d: &e2e::Daemon,
) -> e2e::Result<(e2e::Account, e2e::Account, e2e::Account)> {
    configure_node(alice_d, &stack.discovery_url)?;
    configure_node(bob_d, &stack.discovery_url)?;
    configure_node(carol_d, &stack.discovery_url)?;
    let alice = create_account(alice_d, "Alice")?;
    let bob = create_account(bob_d, "Bob")?;
    let carol = create_account(carol_d, "Carol")?;
    exchange_contacts(alice_d, &alice, bob_d, &bob)?;
    exchange_contacts(alice_d, &alice, carol_d, &carol)?;
    exchange_contacts(bob_d, &bob, carol_d, &carol)?;
    Ok((alice, bob, carol))
}

fn land_before(
    scene: &Scene<'_>,
    sender: &e2e::Daemon,
    parties: &[(&e2e::Daemon, &e2e::Account)],
) -> e2e::Result<()> {
    group_send(sender, scene.alice, scene.group, scene.group, "svc-before", BEFORE)?;
    let logs = daemon_logs(parties);
    for &(daemon, account) in parties {
        reserve_poll(scene.deadline)?;
        wait_json(daemon, &read_args(&account.id, scene.group), |value| {
            text_index(value, BEFORE).is_some()
        })
        .map_err(|error| format!("{error}; logs={}", dump_logs(scene.stack, &logs)))?;
    }
    Ok(())
}

fn rename_online(
    scene: &Scene<'_>,
    alice_d: &e2e::Daemon,
    bob_d: &e2e::Daemon,
) -> e2e::Result<Value> {
    reserve_poll(scene.deadline)?;
    rf_json(
        &alice_d.socket,
        &[
            "group",
            "rename",
            "--account",
            &scene.alice.id,
            "--group",
            scene.group,
            "--name",
            RENAMED,
        ],
    )?;
    group_send(alice_d, scene.alice, scene.group, scene.group, "svc-after", AFTER)?;
    let logs = [alice_d, bob_d];
    let alice_view = wait_positioned(scene, alice_d, scene.alice, &logs)?;
    let bob_view = wait_positioned(scene, bob_d, scene.bob, &logs)?;
    let row = name_row(&alice_view)?.clone();
    same_name_keys(&bob_view, &row)?;
    Ok(row)
}

fn start_settled(
    scene: &Scene<'_>,
    stopped: (PathBuf, PathBuf),
    account: &e2e::Account,
    logs: &[&e2e::Daemon],
    row: &Value,
) -> e2e::Result<e2e::Daemon> {
    let daemon = start_daemon_at(stopped.0, stopped.1)?;
    unlock_account(&daemon, account)?;
    let mut with_self = logs.to_vec();
    with_self.push(&daemon);
    reserve_poll(scene.deadline)?;
    wait_receive_settled(&daemon, account)
        .map_err(|error| format!("{error}; logs={}", dump_logs(scene.stack, &with_self)))?;
    let view = wait_positioned(scene, &daemon, account, &with_self)?;
    same_name_keys(&view, row)?;
    Ok(daemon)
}

fn restart_settled(
    scene: &Scene<'_>,
    daemon: e2e::Daemon,
    account: &e2e::Account,
    logs: &[&e2e::Daemon],
    row: &Value,
) -> e2e::Result<e2e::Daemon> {
    let stopped = shutdown_daemon(daemon)?;
    start_settled(scene, stopped, account, logs, row)
}

fn promote_bob(
    scene: &Scene<'_>,
    alice_d: &e2e::Daemon,
    bob_d: &e2e::Daemon,
    carol_d: &e2e::Daemon,
    row: &Value,
) -> e2e::Result<()> {
    reserve_poll(scene.deadline)?;
    rf_json(
        &alice_d.socket,
        &[
            "group",
            "role",
            "set",
            "--account",
            &scene.alice.id,
            "--group",
            scene.group,
            "--actor",
            &scene.alice.device_id,
            "--member-device",
            &scene.bob.device_id,
            "--role",
            "admin",
        ],
    )?;
    for (daemon, account) in [(alice_d, scene.alice), (bob_d, scene.bob), (carol_d, scene.carol)] {
        reserve_poll(scene.deadline)?;
        wait_json(daemon, &member_args(&account.id, scene.group), |value| {
            member_is_admin(value, &scene.bob.device_id)
        })
        .map_err(|error| format!("{error}; logs={}", dump_logs(scene.stack, &[daemon])))?;
        let view = wait_positioned(scene, daemon, account, &[daemon])?;
        same_name_keys(&view, row)?;
    }
    Ok(())
}

fn daemon_logs<'a>(parties: &'a [(&e2e::Daemon, &e2e::Account)]) -> Vec<&'a e2e::Daemon> {
    parties.iter().map(|&(daemon, _)| daemon).collect()
}

fn wait_positioned(
    scene: &Scene<'_>,
    daemon: &e2e::Daemon,
    account: &e2e::Account,
    logs: &[&e2e::Daemon],
) -> e2e::Result<Value> {
    reserve_poll(scene.deadline)?;
    wait_json(daemon, &read_args(&account.id, scene.group), positioned)
        .map_err(|error| format!("{error}; logs={}", dump_logs(scene.stack, logs)).into())
}

fn name_row(view: &Value) -> e2e::Result<&Value> {
    name_rows(view).into_iter().next().ok_or_else(|| "test: name row missing after the wait".into())
}

fn same_name_keys(view: &Value, row: &Value) -> e2e::Result<()> {
    let peer = name_row(view)?;
    if peer["id"] != row["id"]
        || peer["hlc_ms"] != row["hlc_ms"]
        || peer["hlc_logical"] != row["hlc_logical"]
        || peer["device_sequence"] != row["device_sequence"]
    {
        return Err(format!("service row keys differ: {row} vs {peer}").into());
    }
    Ok(())
}

fn member_args<'a>(account: &'a str, group: &'a str) -> [&'a str; 6] {
    ["group", "members", "--account", account, "--group", group]
}

fn member_is_admin(value: &Value, device_id: &str) -> bool {
    value["member_roster"].as_array().is_some_and(|roster| {
        roster.iter().any(|member| {
            member["identity"]["device_id"].as_str() == Some(device_id)
                && member["role"].as_str() == Some("admin")
        })
    })
}

fn reserve_poll(deadline: Instant) -> e2e::Result<()> {
    if Instant::now().checked_add(POLL_BUDGET).is_none_or(|end| end > deadline) {
        return Err("group service scenario has less than one poll left".into());
    }
    Ok(())
}

fn read_args<'a>(account: &'a str, group: &'a str) -> [&'a str; 8] {
    ["group", "read", "--account", account, "--group", group, "--conversation", group]
}

fn messages(value: &Value) -> Vec<&Value> {
    let mut rows: Vec<&Value> =
        value["messages"].as_array().map(|rows| rows.iter().collect()).unwrap_or_default();
    rows.reverse();
    rows
}

fn name_rows(value: &Value) -> Vec<&Value> {
    messages(value)
        .into_iter()
        .filter(|row| {
            row["kind"] == "service"
                && row["content"]["service"]["action"] == "SERVICE_NAME_CHANGED"
        })
        .collect()
}

fn text_index(value: &Value, text: &str) -> Option<usize> {
    messages(value).iter().position(|row| row["text"].as_str() == Some(text))
}

fn positioned(value: &Value) -> bool {
    let rows = messages(value);
    let Some(name_at) = rows.iter().position(|row| {
        row["kind"] == "service" && row["content"]["service"]["action"] == "SERVICE_NAME_CHANGED"
    }) else {
        return false;
    };
    let name_count = rows
        .iter()
        .filter(|row| {
            row["kind"] == "service"
                && row["content"]["service"]["action"] == "SERVICE_NAME_CHANGED"
        })
        .count();
    let Some(before_at) = rows.iter().position(|row| row["text"].as_str() == Some(BEFORE)) else {
        return false;
    };
    let Some(after_at) = rows.iter().position(|row| row["text"].as_str() == Some(AFTER)) else {
        return false;
    };
    name_count == 1 && before_at < name_at && name_at < after_at
}
