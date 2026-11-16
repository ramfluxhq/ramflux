// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Three real accounts see one group rename as the same service row between two messages.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use std::time::{Duration, Instant};

use e2e::{
    boot_stack, configure_node, create_account, dump_logs, exchange_contacts, group_create,
    group_send, rf_json, start_daemon, unique, wait_json,
};
use serde_json::Value;

const SCENARIO_BUDGET: Duration = Duration::from_secs(180);
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

    reserve_poll(deadline)?;
    rf_json(
        &alice_d.socket,
        &["group", "rename", "--account", &alice.id, "--group", &group, "--name", name],
    )?;
    group_send(&alice_d, &alice, &group, &group, "svc-after", after)?;

    let mut views = Vec::new();
    for (daemon, account) in [(&alice_d, &alice), (&bob_d, &bob), (&carol_d, &carol)] {
        reserve_poll(deadline)?;
        let view = wait_json(daemon, &read_args(&account.id, &group), |value| {
            positioned(value, before, after)
        })
        .map_err(|error| {
            format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d, &carol_d]))
        })?;
        let again = rf_json(&daemon.socket, &read_args(&account.id, &group))?;
        if name_rows(&again).len() != 1 {
            return Err(format!("replay read duplicated the name row: {again}").into());
        }
        views.push(view);
    }
    let first = name_rows(&views[0]);
    let row = first.first().ok_or("test: name row missing after the wait")?;
    for view in views.iter().skip(1) {
        let other = name_rows(view);
        let peer = other.first().ok_or("test: peer name row missing")?;
        if peer["id"] != row["id"]
            || peer["hlc_ms"] != row["hlc_ms"]
            || peer["hlc_logical"] != row["hlc_logical"]
            || peer["device_sequence"] != row["device_sequence"]
        {
            return Err(format!("service row keys differ: {row} vs {peer}").into());
        }
    }
    Ok(())
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
