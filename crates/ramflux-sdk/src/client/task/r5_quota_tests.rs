// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! No-role group traffic and aggregate capacity preserve unrelated and locally active tasks.
use super::*;

#[test]
fn r5_no_role_group_updates_from_the_named_assignee_are_dropped_without_holdback() -> TestResult {
    let f = Fixture::new()?;
    let other = register(&f, "other", 81)?;
    f.human.create_group("group", "human-device")?;
    for id in ["agent-device", "other-device"] {
        f.human.add_group_member("group", id, "member")?;
    }
    f.human.account_db()?.persist_client_record(
        "conversation",
        "group-thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let c = sign(
        &f.agent,
        "group-thread",
        "start",
        peer_start("unrelated", "group-thread", "agent", "other"),
    )?;
    assert!(!project(&f.human, &c)?.accepted);
    for n in 0..12 {
        let update = sign(
            &other,
            "group-thread",
            &format!("update-{n}"),
            TaskEventBody::Update(TaskUpdate {
                task_id: "unrelated".into(),
                version: 2 + n,
                state: TaskStatus::Running,
                steps: Vec::new(),
                result_ref: None,
                result_summary: None,
            }),
        )?;
        let outcome = project(&f.human, &update)?;
        assert!(!outcome.pending, "a named party of a no-role task must not spend holdback");
    }
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 0);
    let legitimate = sign(
        &other,
        "group-thread",
        "legitimate",
        peer_start("unrelated", "group-thread", "other", "human"),
    )?;
    assert!(
        project(&f.human, &legitimate)?.accepted,
        "a new signer can start a genuinely local task"
    );
    Ok(())
}

#[test]
fn r5_aggregate_compaction_prefers_terminal_history_and_never_discards_a_local_active_task()
-> TestResult {
    let f = Fixture::new()?;
    for id in ["active", "terminal"] {
        assert!(project(&f.human, &sign(&f.human, "thread", id, start(id, "thread"))?)?.accepted);
    }
    let cancel = sign(
        &f.human,
        "thread",
        "cancel",
        TaskEventBody::Cancel(TaskCancel { task_id: "terminal".into(), base_revision: 1 }),
    )?;
    assert!(project(&f.human, &cancel)?.accepted);
    for (id, bytes) in [("active", 24 * 1024 * 1024), ("terminal", 8 * 1024 * 1024)] {
        let key = scoped("lifecycle", "thread", id)?;
        let mut row: super::super::lifecycle::Lifecycle =
            f.human.account_db()?.load_actor_state(&key)?.ok_or("lifecycle")?;
        row.usage = std::collections::BTreeMap::from([("human".into(), retained_usage(bytes))]);
        f.human.account_db()?.persist_actor_state(&key, &row)?;
    }
    let carrier = sign(&f.human, "thread", "new", start("new", "thread"))?;
    let mut usage = super::super::quota::Usage::default();
    usage.charge(&carrier, u64::try_from(carrier.bytes()?.len())?, None)?;
    f.human.admit_global_task_history(
        &carrier,
        &std::collections::BTreeMap::from([("human".into(), usage)]),
        false,
    )?;
    assert_ne!(f.human.task_get(Some("thread"), "active")?["compacted"], true);
    assert_eq!(f.human.task_get(Some("thread"), "terminal")?["compacted"], true);
    let key = scoped("lifecycle", "thread", "active")?;
    let mut row: super::super::lifecycle::Lifecycle =
        f.human.account_db()?.load_actor_state(&key)?.ok_or("lifecycle")?;
    row.usage.get_mut("human").ok_or("usage")?.bytes = 32 * 1024 * 1024;
    f.human.account_db()?.persist_actor_state(&key, &row)?;
    assert!(
        f.human
            .admit_global_task_history(
                &carrier,
                &std::collections::BTreeMap::from([("human".into(), retained_usage(1))]),
                false
            )
            .is_err()
    );
    assert_ne!(f.human.task_get(Some("thread"), "active")?["compacted"], true);
    Ok(())
}

fn retained_usage(bytes: u64) -> super::super::quota::Usage {
    let mut usage = super::super::quota::Usage::default();
    usage.bytes = bytes;
    usage.events = 1;
    usage
}

#[test]
fn r5_pruning_announces_a_typed_removal_and_drops_the_task_row() -> TestResult {
    let f = Fixture::new()?;
    assert!(
        project(&f.human, &sign(&f.human, "thread", "start", start("task", "thread"))?)?.accepted
    );
    assert!(
        project(
            &f.human,
            &sign(
                &f.human,
                "thread",
                "cancel",
                TaskEventBody::Cancel(TaskCancel { task_id: "task".into(), base_revision: 1 })
            )?
        )?
        .accepted
    );
    let row: super::super::lifecycle::Lifecycle = f
        .human
        .account_db()?
        .load_actor_state(&scoped("lifecycle", "thread", "task")?)?
        .ok_or("lifecycle")?;
    f.human.compact_task(&row, true)?;
    assert!(f.human.task_get(Some("thread"), "task")?.is_null());
    assert!(f.human.account_db()?.journal_after(0, 128)?.iter().any(|e| e.topic == "task.changed"
        && e.body["kind"] == "removed"
        && e.body["task_id"] == "task"));
    Ok(())
}

#[test]
fn r6_a_malformed_lifecycle_row_does_not_block_compaction_of_valid_terminal_history() -> TestResult
{
    let f = Fixture::new()?;
    assert!(project(&f.human, &sign(&f.human, "thread", "old", start("old", "thread"))?)?.accepted);
    assert!(
        project(
            &f.human,
            &sign(
                &f.human,
                "thread",
                "done",
                TaskEventBody::Cancel(TaskCancel { task_id: "old".into(), base_revision: 1 })
            )?
        )?
        .accepted
    );
    let storage = scoped("lifecycle", "thread", "old")?;
    let mut row: super::super::lifecycle::Lifecycle =
        f.human.account_db()?.load_actor_state(&storage)?.ok_or("lifecycle")?;
    row.usage =
        std::collections::BTreeMap::from([("human".into(), retained_usage(32 * 1024 * 1024))]);
    f.human.account_db()?.persist_actor_state(&storage, &row)?;
    f.human.account_db()?.persist_actor_state(
        &scoped("lifecycle", "thread", "malformed")?,
        &json!({"updated_at":i64::MAX,"usage":{}}),
    )?;
    let c = sign(&f.human, "thread", "new", start("new", "thread"))?;
    f.human.admit_global_task_history(
        &c,
        &std::collections::BTreeMap::from([("human".into(), retained_usage(1))]),
        false,
    )?;
    assert_eq!(f.human.task_get(Some("thread"), "old")?["compacted"], true);
    Ok(())
}

#[test]
fn r7_one_invalid_history_does_not_block_other_eligible_tasks_from_compacting() -> TestResult {
    let f = Fixture::new()?;
    for id in ["bad", "good"] {
        assert!(project(&f.human, &sign(&f.human, "thread", id, start(id, "thread"))?)?.accepted);
        let storage = scoped("lifecycle", "thread", id)?;
        let mut row: super::super::lifecycle::Lifecycle =
            f.human.account_db()?.load_actor_state(&storage)?.ok_or("lifecycle")?;
        row.compaction_eligible = true;
        f.human.account_db()?.persist_actor_state(&storage, &row)?;
    }
    let mut history = f.human.task_history("thread", "bad")?;
    history.events.first_mut().ok_or("history")?.carrier.signature = "invalid".into();
    f.human.account_db()?.persist_actor_state(&scoped("history", "thread", "bad")?, &history)?;
    f.human.maintain_task_lifecycle(crate::time::now_unix_timestamp())?;
    assert_eq!(f.human.task_get(Some("thread"), "good")?["compacted"], true);
    assert_ne!(f.human.task_get(Some("thread"), "bad")?["compacted"], true);
    Ok(())
}
