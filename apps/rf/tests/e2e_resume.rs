// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! F2: three DMs while B is down; after restart, all three arrive once, in order.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    assert_texts_once_in_order, boot_stack, configure_node, create_account, dm_send, dump_logs,
    exchange_contacts, shutdown_daemon, start_daemon, start_daemon_at, unique, unlock_account,
    wait_dm_texts,
};

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn f2_restart_catchup_three_dms_once_in_order() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = unique("e2e-resume");
    let (bob_socket, bob_root) = shutdown_daemon(bob_d)?;
    let bodies = ["resume-one", "resume-two", "resume-three"];
    for (index, body) in bodies.iter().enumerate() {
        dm_send(&alice_d, &alice, &bob, &conversation, &format!("msg-{index}"), body)?;
    }
    let bob_d = start_daemon_at(bob_socket, bob_root)?;
    unlock_account(&bob_d, &bob)?;
    let received = wait_dm_texts(&bob_d, &bob, &conversation, &bodies)
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;
    assert_texts_once_in_order(&received, &bodies)
}

#[ignore = "real-process Demo B B7: explicit WAL mode; CLI e2e CI job"]
#[test]
fn b7_offline_twenty_dms_three_group_messages_wal() -> e2e::Result<()> {
    offline_demo_b(true, None, false)
}

#[ignore = "real-process Demo B B7: explicit redb-only mode; CLI e2e CI job"]
#[test]
fn b7_offline_twenty_dms_three_group_messages_redb_only() -> e2e::Result<()> {
    offline_demo_b(false, None, false)
}

#[ignore = "real-process Demo B B7 crash at commit 7 and beyond-batch control; CLI e2e CI job"]
#[test]
fn b7_mid_batch_crash_wal() -> e2e::Result<()> {
    offline_demo_b(true, Some(7), false)?;
    offline_demo_b(true, Some(1000), false)
}

#[ignore = "real-process Demo B B7 crash at commit 7 and beyond-batch control; CLI e2e CI job"]
#[test]
fn b7_mid_batch_crash_redb_only() -> e2e::Result<()> {
    offline_demo_b(false, Some(7), false)?;
    offline_demo_b(false, Some(1000), false)
}

#[ignore = "real-process regression: foreground group read racing ledger receive; CLI e2e CI job"]
#[test]
fn b7_group_read_before_setup_ack_keeps_catchup_live() -> e2e::Result<()> {
    offline_demo_b(false, None, true)?;
    offline_demo_b(true, None, true)
}

fn offline_demo_b(wal: bool, crash_after: Option<u64>, read_before_ack: bool) -> e2e::Result<()> {
    let stack = e2e::boot_stack_with_wal(wal)?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = unique("demo-b-offline-dm");
    let group = unique("demo-b-offline-group");
    establish_group(&stack, (&alice_d, &alice), (&bob_d, &bob), &group, read_before_ack)?;
    let base = e2e::wait_receive_settled(&bob_d, &bob)?;
    let base_cursor = e2e::receive_counter(&base, "committed_cursor")?;
    let (socket, root) = shutdown_daemon(bob_d)?;
    let bodies: Vec<String> = (0..20).map(|i| format!("offline-dm-{i:02}")).collect();
    let mut ids: Vec<String> = (0..20).map(|i| unique(&format!("offline-dm-{i:02}"))).collect();
    for (id, body) in ids.iter().zip(&bodies) {
        dm_send(&alice_d, &alice, &bob, &conversation, id, body)?;
    }
    let group_bodies = ["offline-group-00", "offline-group-01", "offline-group-02"];
    for body in &group_bodies {
        let sent = e2e::group_send(&alice_d, &alice, &group, &group, &unique(body), body)?;
        ids.extend(e2e::group_envelope_ids(&sent, &bob)?);
    }
    e2e::wait_node_pending(&stack, &bob, &ids)?;
    let wal_root = stack.root.join("state/ramflux-router.redb.wal");
    assert_eq!(wal_root.exists(), wal, "storage mode must match the actual WAL artifact");
    let bob_d = restart_bob(socket, root, &stack, &bob, base_cursor, crash_after)?;
    // Observe the node ACKs before any message read can request receive work.
    for id in &ids {
        account_ack(&stack, &bob_d, &bob, id)?;
    }
    let expected: Vec<&str> = bodies.iter().map(String::as_str).collect();
    let received = wait_dm_texts(&bob_d, &bob, &conversation, &expected)
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;
    assert_eq!(e2e::message_texts(&received), bodies, "exact DM set and order");
    let received = e2e::wait_group_texts(
        &bob_d,
        &bob,
        &group,
        &group,
        &["group ready", "offline-group-00", "offline-group-01", "offline-group-02"],
    )?;
    // group.read includes decrypted deliveries, retained native history and the
    // encrypted storage representation. The offline plaintext batch is ordered
    // within its delivery view; history remains independently visible.
    assert_texts_once_in_order(&received, &group_bodies)?;
    assert_eq!(
        e2e::message_texts(&received).iter().filter(|text| text.as_str() == "group ready").count(),
        1,
        "pre-restart group history remains visible exactly once"
    );
    let receive = e2e::wait_receive_settled(&bob_d, &bob)?;
    assert_eq!(receive["catch_up_passes"], 1, "one Connected catch-up, no later poll: {receive}");
    assert!(
        e2e::receive_counter(&receive, "last_acked_seq")?
            <= e2e::receive_counter(&receive, "committed_cursor")?,
        "{receive}"
    );
    let status = e2e::rf_json(&bob_d.socket, &["account", "status", "--account", &bob.id])?;
    assert_eq!(status["session_delivery_mode"], "push", "{status}");
    assert_eq!(status["networking_snapshot"]["receive"]["catch_ups_total"], 1, "{status}");
    eprintln!(
        "B7 storage_wal={wal} crash_after={crash_after:?}: 20 DMs + 3 group messages once in order; status={status}"
    );
    Ok(())
}

fn restart_bob(
    socket: std::path::PathBuf,
    root: std::path::PathBuf,
    stack: &e2e::Stack,
    bob: &e2e::Account,
    base_cursor: u64,
    crash_after: Option<u64>,
) -> e2e::Result<e2e::Daemon> {
    let setting = crash_after.map(|count| count.to_string());
    let env: Vec<(&str, &str)> = setting
        .as_deref()
        .map(|count| ("RAMFLUX_TEST_CRASH_AFTER_COMMITS", count))
        .into_iter()
        .collect();
    let daemon = e2e::spawn_daemon_with_env(socket, root, &env)?;
    if crash_after != Some(7) {
        unlock_account(&daemon, bob)?;
        return Ok(daemon);
    }
    let unlock = e2e::unlock_account_without_wait(&daemon, bob);
    let (socket, root, log) = e2e::await_receive_crash(daemon, bob).map_err(|error| {
        format!("{error}; unlock={unlock:?}; logs={}", e2e::dump_logs(stack, &[]))
    })?;
    let line = log.lines().find(|line| line.contains("RECEIVE_CRASH ")).ok_or("crash marker")?;
    let field = |key: &str| -> e2e::Result<u64> {
        line.split_whitespace()
            .find_map(|word| word.strip_prefix(key))
            .ok_or_else(|| format!("missing crash witness {key}: {line}"))?
            .parse::<u64>()
            .map_err(Into::into)
    };
    let cursor = field("cursor=")?;
    let ack = field("last_acked_seq=")?;
    assert_eq!(field("commits=")?, 7, "calibrated post-commit crash");
    assert!(
        cursor > base_cursor && cursor < base_cursor + 23,
        "crash must interrupt a partially committed batch: base={base_cursor} {line}"
    );
    assert!(ack <= cursor, "ACK must not pass committed C: {line}");
    let node = e2e::mesh_cursor(stack, &bob.target_delivery_id)?;
    let node_ack = node["inbox_seq"].as_u64().ok_or("node ACK cursor")?;
    assert!(node_ack <= cursor, "node observed ACK beyond committed C: {node}; {line}");
    eprintln!("B7 calibrated mid-batch crash: {line}; node={node}");
    let daemon = start_daemon_at(socket, root)?;
    unlock_account(&daemon, bob)?;
    Ok(daemon)
}

fn establish_group(
    stack: &e2e::Stack,
    alice: (&e2e::Daemon, &e2e::Account),
    bob: (&e2e::Daemon, &e2e::Account),
    group: &str,
    read_before_ack: bool,
) -> e2e::Result<()> {
    let (alice_d, alice) = alice;
    let (bob_d, bob) = bob;
    e2e::group_create(alice_d, alice, group, &[bob])?;
    let sent =
        e2e::group_send(alice_d, alice, group, group, &unique("group-setup"), "group ready")?;
    if !read_before_ack {
        for id in e2e::group_envelope_ids(&sent, bob)? {
            account_ack(stack, bob_d, bob, &id)?;
        }
    }
    e2e::wait_group_texts(bob_d, bob, group, group, &["group ready"])?;
    Ok(())
}

fn account_ack(
    stack: &e2e::Stack,
    daemon: &e2e::Daemon,
    account: &e2e::Account,
    id: &str,
) -> e2e::Result<()> {
    e2e::wait_node_observed_ack(stack, account, id).map(|_| ()).map_err(|error| {
        format!(
            "{error}; status={:?}; logs={}",
            e2e::rf_json(&daemon.socket, &["account", "status", "--account", &account.id]),
            e2e::dump_logs(stack, &[daemon])
        )
        .into()
    })
}
