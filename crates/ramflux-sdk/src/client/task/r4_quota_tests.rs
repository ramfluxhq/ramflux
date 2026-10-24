// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scope-specific stalls, signer tombstones, aggregate fairness and verified roster recovery.
use super::*;
#[test]
fn a_task_at_its_event_limit_does_not_stall_the_assignees_other_tasks() -> TestResult {
    let f = Fixture::new()?;
    for id in ["long", "other"] {
        assert!(project(&f.human, &sign(&f.human, "thread", id, start(id, "thread"))?)?.accepted);
    }
    let mut history = f.human.task_history("thread", "long")?;
    for version in 2..=256 {
        let c = sign(
            &f.agent,
            "thread",
            &format!("progress-{version}"),
            TaskEventBody::Update(TaskUpdate {
                result_summary: None,
                task_id: "long".into(),
                version,
                state: TaskStatus::Running,
                steps: Vec::new(),
                result_ref: None,
            }),
        )?;
        history.events.push(AcceptedEvent {
            public_key: f.human.task_signer_key("agent", "agent-device")?,
            carrier: c,
            actor_kind_verified: false,
            received_at: 1,
            decision_certificate: None,
            membership: None,
        });
    }
    let task = history.state()?.task().cloned().ok_or("task")?;
    f.human.account_db()?.persist_actor_state(&scoped("history", "thread", "long")?, &history)?;
    f.human.record_task_lifecycle(&task, &history)?;
    let overflow = sign(
        &f.agent,
        "thread",
        "overflow",
        TaskEventBody::Update(TaskUpdate {
            result_summary: None,
            task_id: "long".into(),
            version: 257,
            state: TaskStatus::Running,
            steps: Vec::new(),
            result_ref: None,
        }),
    )?;
    let rejected = project(&f.human, &overflow)?;
    assert!(!rejected.accepted);
    assert_eq!(rejected.reason_code, Some(crate::TaskRefusalCode::TaskQuotaExhausted));
    assert_eq!(f.human.task_get(Some("thread"), "long")?["stalled_by_assignee"], true);
    assert_ne!(f.human.task_get(Some("thread"), "other")?["stalled_by_assignee"], true);
    let update = sign(
        &f.agent,
        "thread",
        "other-progress",
        TaskEventBody::Update(TaskUpdate {
            result_summary: None,
            task_id: "other".into(),
            version: 2,
            state: TaskStatus::Running,
            steps: Vec::new(),
            result_ref: None,
        }),
    )?;
    assert!(project(&f.human, &update)?.accepted);
    let count = f.human.account_db()?.journal_bounds()?.head_seq;
    assert!(!project(&f.human, &overflow)?.accepted);
    assert_eq!(f.human.account_db()?.journal_bounds()?.head_seq, count);
    Ok(())
}
#[test]
fn a_no_role_tombstone_does_not_squat_on_a_different_signers_legitimate_task() -> TestResult {
    let f = Fixture::new()?;
    let other = register(&f, "other", 81)?;
    f.human.create_group("group", "human-device")?;
    f.human.add_group_member("group", &member(&f.human, "agent-device")?, "member")?;
    f.human.add_group_member("group", &member(&f.human, "other-device")?, "member")?;
    f.human.account_db()?.persist_client_record(
        "conversation",
        "group-thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let bad = sign(
        &f.agent,
        "group-thread",
        "squat",
        peer_start("deploy", "group-thread", "agent", "agent"),
    )?;
    assert!(!project(&f.human, &bad)?.accepted);
    let good = sign(
        &other,
        "group-thread",
        "genuine",
        peer_start("deploy", "group-thread", "other", "human"),
    )?;
    assert!(project(&f.human, &good)?.accepted);
    assert_eq!(f.human.task_get(Some("group-thread"), "deploy")?["requester"], "other");
    Ok(())
}
#[test]
fn stale_snapshot_membership_cannot_wedge_task_ingress_local_mutations_or_verified_removals()
-> TestResult {
    for path in ["start", "cancel", "add", "remove", "kick", "ban"] {
        let f = Fixture::new()?;
        f.human.create_group("group", "human-device")?;
        f.human.add_group_member("group", &member(&f.human, "agent-device")?, "member")?;
        f.human.create_signed_group_role_change(
            "group",
            "human-device",
            "agent-device",
            "admin",
        )?;
        let epoch = f.human.group_state("group")?.group_epoch;
        f.human.account_db()?.upsert_group_member_snapshot("group", "ghost", "member", epoch)?;
        f.human.account_db()?.persist_client_record(
            "conversation",
            "group-thread",
            &json!({"kind":"group","group_id":"group"}),
        )?;
        match path {
            "start" | "cancel" => {
                let c = sign(
                    &f.agent,
                    "group-thread",
                    "start",
                    peer_start("group-task", "group-thread", "agent", "human"),
                )?;
                assert!(project(&f.human, &c)?.accepted, "start failed after snapshot skew");
                if path == "cancel" {
                    let c = sign(
                        &f.agent,
                        "group-thread",
                        "cancel",
                        TaskEventBody::Cancel(TaskCancel {
                            task_id: "group-task".into(),
                            base_revision: 1,
                        }),
                    )?;
                    assert!(project(&f.human, &c)?.accepted);
                }
            }
            "add" => {
                let mut newcomer = client(&f.root.join("newcomer"), "newcomer", 91)?;
                newcomer.create_device_branch("newcomer", "new-member", 1, [93; 32]);
                f.human.persist_identity_directory(&super::super::own::manifest(&newcomer)?)?;
                assert!(
                    f.human
                        .add_group_member("group", &member(&f.human, "new-member")?, "member")?
                        .members
                        .contains("new-member")
                );
            }
            "remove" => {
                assert!(
                    !f.human
                        .remove_group_member("group", "human-device", "agent-device")?
                        .members
                        .contains("agent-device")
                );
            }
            "kick" => {
                let (_, state) = f.human.create_signed_group_member_kick(
                    "group",
                    "human-device",
                    "agent-device",
                    "removed",
                )?;
                assert!(!state.members.contains("agent-device"));
            }
            "ban" => {
                let (_, state) = f.human.create_signed_group_member_ban(
                    "group",
                    "human-device",
                    "agent-device",
                    "banned",
                )?;
                assert!(!state.members.contains("agent-device"));
            }
            _ => return Err("unknown regression path".into()),
        }
    }
    Ok(())
}
#[test]
fn task_messages_carry_the_task_id_and_terminal_summaries_survive_compaction() -> TestResult {
    let f = Fixture::new()?;
    let c = sign(&f.human, "thread", "start", start("summary", "thread"))?;
    assert!(project(&f.human, &c)?.accepted);
    let c = sign(
        &f.agent,
        "thread",
        "complete",
        TaskEventBody::Update(TaskUpdate {
            task_id: "summary".into(),
            version: 2,
            state: TaskStatus::Done,
            steps: Vec::new(),
            result_ref: Some("result-object".into()),
            result_summary: Some("Completed with a bounded result summary".into()),
        }),
    )?;
    assert!(project(&f.human, &c)?.accepted);
    let view = f.human.task_get(Some("thread"), "summary")?;
    assert_eq!(view["result_summary"], "Completed with a bounded result summary");
    assert_eq!(view["actors"]["requester"]["principal_id"], "human");
    assert_eq!(view["actors"]["assignee"]["principal_id"], "agent");
    assert_eq!(view["actors"]["requester"]["actor_kind_verified"], false);
    assert_eq!(view["actors"]["assignee"]["actor_kind_verified"], false);
    assert_eq!(
        f.human.task_message_metadata("thread", "complete")?.ok_or("metadata")?["task_id"],
        "summary"
    );
    let row = f
        .human
        .account_db()?
        .load_actor_state::<super::super::lifecycle::Lifecycle>(&scoped(
            "lifecycle",
            "thread",
            "summary",
        )?)?
        .ok_or("lifecycle")?;
    f.human.compact_task(&row, false)?;
    assert_eq!(
        f.human.task_get(Some("thread"), "summary")?["result_summary"],
        view["result_summary"]
    );
    let events = f.human.account_db()?.journal_after(0, 256)?;
    assert!(events.iter().any(|e| e.topic == "task.changed" && e.body["compacted"] == true));
    f.human.compact_task(&row, true)?;
    let events = f.human.account_db()?.journal_after(0, 256)?;
    assert!(events.iter().any(|e| e.topic == "task.changed" && e.body["removed"] == true));
    Ok(())
}
#[test]
fn the_aggregate_history_cap_reclaims_the_largest_signer_without_discarding_a_small_peer()
-> TestResult {
    let f = Fixture::new()?;
    for id in ["large", "small"] {
        let TaskEventBody::Proposal(mut body) = proposal() else {
            return Err("proposal fixture".into());
        };
        body.task_id = id.into();
        assert!(
            project(&f.human, &sign(&f.agent, "thread", id, TaskEventBody::Proposal(body))?)?
                .accepted
        );
        let index = scoped("lifecycle", "thread", id)?;
        let mut row: super::super::lifecycle::Lifecycle =
            f.human.account_db()?.load_actor_state(&index)?.ok_or("index")?;
        // Exercise the aggregate-index boundary independently of the lower signer bound.
        // Each boundary attempt still compacts a real signed history and retains its checkpoint.
        row.usage.clear();
        let mut usage = super::super::quota::Usage::default();
        usage.bytes = if id == "large" { 24 * 1024 * 1024 } else { 8 * 1024 * 1024 };
        usage.events = 1;
        row.usage.insert(id.into(), usage);
        f.human.account_db()?.persist_actor_state(&index, &row)?;
    }
    let c = sign(&f.human, "thread", "new", start("new", "thread"))?;
    let mut usage = super::super::quota::Usage::default();
    usage.charge(&c, u64::try_from(c.bytes()?.len())?, None)?;
    f.human.admit_global_task_history(
        &c,
        &std::collections::BTreeMap::from([("human".into(), usage)]),
        false,
    )?;
    assert_eq!(f.human.task_get(Some("thread"), "large")?["compacted"], true);
    assert_ne!(f.human.task_get(Some("thread"), "small")?["compacted"], true);
    assert_eq!(
        f.human.task_history("thread", "large")?.state()?.task().ok_or("checkpoint")?.version,
        1
    );
    Ok(())
}
