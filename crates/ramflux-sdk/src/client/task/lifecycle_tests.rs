// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Regression coverage for peer-scoped lifetime capacity and terminal retention.
use super::*;
use ramflux_protocol::TaskCancel;
#[test]
fn self_assigned_peer_starts_cannot_consume_the_local_accounts_task_capacity() -> TestResult {
    let f = Fixture::new()?;
    for index in 0..128 {
        let c = sign(
            &f.agent,
            "thread",
            &format!("flood-{index}"),
            TaskEventBody::Start(TaskStart {
                task_id: format!("flood-{index}"),
                conversation_id: "thread".into(),
                requester: "agent".into(),
                assignee: "agent".into(),
                text: "self assigned".into(),
                constraints: None,
            }),
        )?;
        assert!(!project(&f.human, &c)?.accepted);
    }
    assert_eq!(f.human.account_db()?.task_state_usage("task/history/")?.0, 0);
    let good = sign(&f.human, "thread", "good", start("good", "thread"))?;
    assert!(project(&f.human, &good)?.accepted);
    Ok(())
}
#[test]
fn exhausting_one_peers_active_quota_records_rejections_without_blocking_another_source()
-> TestResult {
    let f = Fixture::new()?;
    for index in 0..17 {
        let c = sign(
            &f.human,
            "thread",
            &format!("start-{index}"),
            start(&format!("task-{index}"), "thread"),
        )?;
        assert_eq!(project(&f.agent, &c)?.accepted, index < 16);
    }
    let c = sign(
        &f.agent,
        "thread",
        "other-source",
        TaskEventBody::Start(TaskStart {
            task_id: "other-source".into(),
            conversation_id: "thread".into(),
            requester: "agent".into(),
            assignee: "human".into(),
            text: "independent source".into(),
            constraints: None,
        }),
    )?;
    assert!(project(&f.agent, &c)?.accepted);
    assert_eq!(f.agent.account_db()?.task_state_usage("task/history/")?.0, 17);
    Ok(())
}
#[test]
fn terminal_compaction_keeps_projection_and_certificate_hashes_without_reusing_decisions()
-> TestResult {
    let f = Fixture::new()?;
    decisions::open(&f, "task")?;
    decisions::store(&f, &decisions::grant(&f)?)?;
    let resolve = sign(
        &f.human,
        "thread",
        "resolve",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.agent, &resolve)?.accepted);
    let history = f.agent.task_history("thread", "task")?;
    let consumed = history
        .events
        .last()
        .and_then(|e| e.decision_certificate.as_ref())
        .ok_or("certificate")?
        .decision_key
        .clone();
    let cancel = sign(
        &f.human,
        "thread",
        "cancel",
        TaskEventBody::Cancel(TaskCancel { task_id: "task".into(), base_revision: 3 }),
    )?;
    assert!(project(&f.agent, &cancel)?.accepted);
    let now = crate::time::now_unix_timestamp();
    f.agent.maintain_task_lifecycle(now + 8 * 86400)?;
    assert_eq!(f.agent.task_history("thread", "task")?.events.len(), 0);
    let view = f.agent.task_get(Some("thread"), "task")?;
    assert_eq!(view["compacted"], true);
    assert_eq!(view["certificate_hashes"].as_array().ok_or("hashes")?.len(), 1);
    assert!(f.agent.account_db()?.load_actor_state::<serde_json::Value>(&consumed)?.is_some());
    assert!(
        !project(&f.agent, &sign(&f.human, "thread", "restart", start("task", "thread"))?)?
            .accepted
    );
    f.agent.maintain_task_lifecycle(now + 91 * 86400)?;
    assert!(f.agent.task_get(Some("thread"), "task")?.is_null());
    assert!(f.agent.account_db()?.load_actor_state::<serde_json::Value>(&consumed)?.is_some());
    Ok(())
}
#[test]
fn terminal_count_retention_compacts_old_bodies_and_fully_prunes_older_projection_rows()
-> TestResult {
    let f = Fixture::new()?;
    f.agent.account_db()?.write_transaction(|| {
        for index in 0..145 {
            let id = format!("terminal-{index}");
            let a = sign(&f.human, "thread", &format!("start-{index}"), start(&id, "thread"))?;
            let b = sign(
                &f.human,
                "thread",
                &format!("cancel-{index}"),
                TaskEventBody::Cancel(TaskCancel { task_id: id.clone(), base_revision: 1 }),
            )?;
            let events = [a, b]
                .into_iter()
                .map(|c| {
                    Ok(AcceptedEvent {
                        public_key: f.agent.task_signer_key(&c.principal_id, &c.device_id)?,
                        carrier: c,
                        actor_kind_verified: actor_kind_verified(&f.human, "human", "human-device"),
                        received_at: crate::time::now_unix_timestamp(),
                        decision_certificate: None,
                        membership: None,
                    })
                })
                .collect::<Result<Vec<_>, SdkError>>()?;
            let history = TaskHistory {
                events,
                checkpoint: None,
                created_at: 1,
                updated_at: crate::time::now_unix_timestamp(),
            };
            let state = history.state()?;
            let task = state.task().ok_or_else(|| invalid("task"))?;
            f.agent
                .account_db()?
                .persist_actor_state(&scoped("history", "thread", &id)?, &history)?;
            f.agent.account_db()?.persist_actor_state(&scoped("view", "thread", &id)?, task)?;
            f.agent.record_task_lifecycle(task, &history)?;
        }
        Ok::<_, SdkError>(())
    })?;
    assert!(f.agent.account_db()?.task_state_usage("task/history/")?.0 <= 16);
    assert_eq!(f.agent.account_db()?.task_state_usage("task/view/")?.0, 128);
    assert_eq!(f.agent.account_db()?.task_state_usage("task/lifecycle/")?.0, 128);
    Ok(())
}

#[test]
fn a_requester_can_cancel_after_its_assignee_leaves_the_group() -> TestResult {
    let f = Fixture::new()?;
    f.human.create_group("group", "human-device")?;
    f.human.add_group_member("group", "agent-device", "member")?;
    f.human.account_db()?.persist_client_record(
        "conversation",
        "group-thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    assert!(
        project(
            &f.human,
            &sign(&f.human, "group-thread", "start", start("task", "group-thread"))?
        )?
        .accepted
    );
    f.human.remove_group_member("group", "human-device", "agent-device")?;
    let c = sign(
        &f.human,
        "group-thread",
        "cancel",
        TaskEventBody::Cancel(TaskCancel { task_id: "task".into(), base_revision: 1 }),
    )?;
    assert!(project(&f.human, &c)?.accepted);
    assert_eq!(f.human.task_get(Some("group-thread"), "task")?["state"], "cancelled");
    Ok(())
}
#[test]
fn replayed_decision_ids_leave_no_reservation_for_an_otherwise_valid_second_grant() -> TestResult {
    let f = Fixture::new()?;
    decisions::open(&f, "task")?;
    decisions::store(&f, &decisions::grant(&f)?)?;
    let first = sign(
        &f.human,
        "thread",
        "first-resolve",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.agent, &first)?.accepted);
    let mut grant = decisions::grant(&f)?;
    grant.grant_id = "second-grant".into();
    grant.signing_body.grant_id = grant.grant_id.clone();
    grant.signature = ramflux_crypto::sign_with_device_branch(
        f.human.device_branch.as_ref().ok_or("device")?,
        &grant.signing_body,
    )?;

    let update = sign(
        &f.agent,
        "thread",
        "second-needs-me",
        TaskEventBody::Update(TaskUpdate {
            result_summary: None,
            task_id: "task".into(),
            version: 4,
            state: TaskStatus::NeedsMe,
            steps: vec![TaskStep {
                id: "step".into(),
                title: "Run command".into(),
                state: TaskStatus::NeedsMe,
                needs_me: Some(ramflux_protocol::NeedsMe::Approval {
                    grant_id: grant.grant_id.clone(),
                }),
            }],
            result_ref: None,
        }),
    )?;
    assert!(project(&f.agent, &update)?.accepted);
    grant.signing_body.task_binding = Some(f.agent.task_approval_binding(
        "thread",
        "task",
        "step",
        &ramflux_protocol::NeedsMe::Approval { grant_id: grant.grant_id.clone() },
    )?);
    grant.signature = ramflux_crypto::sign_with_device_branch(
        f.human.device_branch.as_ref().ok_or("device")?,
        &grant.signing_body,
    )?;
    decisions::store(&f, &grant)?;
    let mut resolution = decisions::resolution("task", ramflux_protocol::TaskDecision::Resume);
    resolution.base_revision = 4;
    resolution.target = ramflux_protocol::NeedsMe::Approval { grant_id: grant.grant_id };
    let replay = sign(&f.human, "thread", "replayed-decision", TaskEventBody::Resolve(resolution))?;
    assert!(!project(&f.agent, &replay)?.accepted);
    assert_eq!(f.agent.account_db()?.task_state_usage("task/decision_reserved/")?.0, 0);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?["version"], 4);
    Ok(())
}

#[test]
fn unverified_actor_fallbacks_never_claim_a_human_approved_the_task() -> TestResult {
    let f = Fixture::new()?;
    assert!(project(&f.human, &sign(&f.agent, "thread", "proposal", proposal())?)?.accepted);
    let c = sign(
        &f.human,
        "thread",
        "accept",
        TaskEventBody::Accept(TaskAccept { task_id: "proposal".into(), version: 2 }),
    )?;
    let outcome = project(&f.human, &c)?;
    assert!(outcome.accepted);
    assert!(outcome.fallback_text.contains("accepted (actor kind unverified)"));
    assert!(!outcome.fallback_text.contains("by a human"));
    assert_eq!(
        f.human.task_get(Some("thread"), "proposal")?["actor_kind_verified"],
        actor_kind_verified(&f.human, "human", "human-device")
    );
    assert_eq!(
        f.human.task_message_metadata("thread", "accept")?.ok_or("metadata")?["actor_kind_verified"],
        actor_kind_verified(&f.human, "human", "human-device")
    );
    Ok(())
}

#[test]
fn commit_certificate_cache_is_peer_bounded_and_expires_without_erasing_consumed_decisions()
-> TestResult {
    let f = Fixture::new()?;
    let db = f.agent.account_db()?;
    let now = crate::time::now_unix_timestamp();
    let consumed = key("decision_used", "grant-sentinel");
    db.persist_actor_state(&consumed, &json!({"consumed":true}))?;
    db.write_transaction(|| {
        db.persist_actor_state(
            &key("committed_decision", "honest"),
            &json!({"assignee":"honest","conversation_id":"other","issued_at":now}),
        )?;
        for index in 0..100 {
            db.persist_actor_state(
                &key("committed_decision", &format!("flood-{index}")),
                &json!({"assignee":"flood","conversation_id":"flood-thread","issued_at":now}),
            )?;
        }
        db.prune_task_certificates(now)
    })?;
    assert_eq!(db.task_state_usage("task/committed_decision/")?.0, 33);
    assert!(
        db.load_actor_state::<serde_json::Value>(&key("committed_decision", "honest"))?.is_some()
    );
    db.prune_task_certificates(now + 8 * 86400)?;
    assert_eq!(db.task_state_usage("task/committed_decision/")?.0, 0);
    assert!(db.load_actor_state::<serde_json::Value>(&consumed)?.is_some());
    Ok(())
}
