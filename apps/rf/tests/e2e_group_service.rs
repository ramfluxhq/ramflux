// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Three real accounts see one group rename as the same service row between two messages.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use std::time::{Duration, Instant};

use e2e::{
    boot_stack, configure_node, create_account, dump_logs, exchange_contacts, group_create,
    group_send, restart_daemon, rf_json, shutdown_daemon, start_daemon, start_daemon_at, unique,
    unlock_account, wait_json, wait_receive_settled,
};
use serde_json::Value;

const SCENARIO_BUDGET: Duration = Duration::from_secs(240);
const POLL_BUDGET: Duration = Duration::from_secs(90);

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn group_rename_is_one_service_row_between_messages() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    let carol_d = start_daemon(&stack, "carol")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    configure_node(&carol_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    let carol = create_account(&carol_d, "Carol")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    exchange_contacts(&alice_d, &alice, &carol_d, &carol)?;
    exchange_contacts(&bob_d, &bob, &carol_d, &carol)?;

    let deadline = Instant::now() + SCENARIO_BUDGET;
    let group = unique("e2e-group-service");
    let before = "before the rename";
    let after = "after the rename";
    let name = "Renamed checklist";
    reserve_poll(deadline)?;
    group_create(&alice_d, &alice, &group, &[&bob, &carol])?;
    group_send(&alice_d, &alice, &group, &group, "svc-before", before)?;
    for (daemon, account) in [(&alice_d, &alice), (&bob_d, &bob), (&carol_d, &carol)] {
        reserve_poll(deadline)?;
        wait_json(daemon, &read_args(&account.id, &group), |value| {
            text_index(value, before).is_some()
        })
        .map_err(|error| {
            format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d, &carol_d]))
        })?;
    }

    let (carol_socket, carol_root) = shutdown_daemon(carol_d)?;
    reserve_poll(deadline)?;
    rf_json(
        &alice_d.socket,
        &["group", "rename", "--account", &alice.id, "--group", &group, "--name", name],
    )?;
    group_send(&alice_d, &alice, &group, &group, "svc-after", after)?;

    let mut online = Vec::new();
    for (daemon, account) in [(&alice_d, &alice), (&bob_d, &bob)] {
        reserve_poll(deadline)?;
        online.push(wait_positioned(
            &stack,
            daemon,
            account,
            &group,
            before,
            after,
            &[&alice_d, &bob_d],
        )?);
    }
    let first = online.first().ok_or("test: alice view missing")?;
    let row = name_row(first)?.clone();
    let second = online.get(1).ok_or("test: bob view missing")?;
    same_name_keys(second, &row)?;

    let carol_d = start_daemon_at(carol_socket, carol_root)?;
    unlock_account(&carol_d, &carol)?;
    reserve_poll(deadline)?;
    wait_receive_settled(&carol_d, &carol).map_err(|error| {
        format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d, &carol_d]))
    })?;
    let carol_view = wait_positioned(
        &stack,
        &carol_d,
        &carol,
        &group,
        before,
        after,
        &[&alice_d, &bob_d, &carol_d],
    )?;
    same_name_keys(&carol_view, &row)?;

    let bob_d = restart_daemon(bob_d)?;
    unlock_account(&bob_d, &bob)?;
    reserve_poll(deadline)?;
    wait_receive_settled(&bob_d, &bob).map_err(|error| {
        format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d, &carol_d]))
    })?;
    let bob_view = wait_positioned(
        &stack,
        &bob_d,
        &bob,
        &group,
        before,
        after,
        &[&alice_d, &bob_d, &carol_d],
    )?;
    same_name_keys(&bob_view, &row)?;

    reserve_poll(deadline)?;
    rf_json(
        &alice_d.socket,
        &[
            "group",
            "role",
            "set",
            "--account",
            &alice.id,
            "--group",
            &group,
            "--actor",
            &alice.device_id,
            "--member-device",
            &bob.device_id,
            "--role",
            "admin",
        ],
    )?;
    for (daemon, account) in [(&alice_d, &alice), (&bob_d, &bob), (&carol_d, &carol)] {
        reserve_poll(deadline)?;
        wait_json(daemon, &member_args(&account.id, &group), |value| {
            member_is_admin(value, &bob.device_id)
        })
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[daemon])))?;
        let view = wait_positioned(&stack, daemon, account, &group, before, after, &[daemon])?;
        same_name_keys(&view, &row)?;
    }
    Ok(())
}

fn wait_positioned(
    stack: &e2e::Stack,
    daemon: &e2e::Daemon,
    account: &e2e::Account,
    group: &str,
    before: &str,
    after: &str,
    logs: &[&e2e::Daemon],
) -> e2e::Result<Value> {
    wait_json(daemon, &read_args(&account.id, group), |value| positioned(value, before, after))
        .map_err(|error| format!("{error}; logs={}", dump_logs(stack, logs)).into())
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

fn positioned(value: &Value, before: &str, after: &str) -> bool {
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
    let Some(before_at) = rows.iter().position(|row| row["text"].as_str() == Some(before)) else {
        return false;
    };
    let Some(after_at) = rows.iter().position(|row| row["text"].as_str() == Some(after)) else {
        return false;
    };
    name_count == 1 && before_at < name_at && name_at < after_at
}
