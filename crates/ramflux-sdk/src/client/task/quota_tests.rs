// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signer isolation, fair holdback and requester recovery under adversarial task churn.
use super::*;
use ramflux_protocol::TaskCancel;
fn register(f: &Fixture, id: &str, seed: u8) -> Result<RamfluxClient, SdkError> {
    let peer = client(&f.root.join(id), id, seed)?;
    let branch = peer.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    f.human.account_db()?.persist_client_record("device", &branch.device_id, &json!({"principal_id":id,"principal_commitment":crate::identity_root_public_key_commitment(&ramflux_protocol::encode_base64url(peer.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?.signing_key.verifying_key().to_bytes()))?,"signing_public_key":ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes())}))?;
    Ok(peer)
}
fn peer_start(id: &str, conversation: &str, source: &str, assignee: &str) -> TaskEventBody {
    TaskEventBody::Start(TaskStart {
        task_id: id.into(),
        conversation_id: conversation.into(),
        requester: source.into(),
        assignee: assignee.into(),
        text: "work".into(),
        constraints: None,
    })
}
fn early(peer: &RamfluxClient, conversation: &str, id: &str) -> Result<carrier::Carrier, SdkError> {
    sign(
        peer,
        conversation,
        id,
        TaskEventBody::Update(TaskUpdate {
            result_summary: None,
            task_id: id.into(),
            version: 2,
            state: TaskStatus::Running,
            steps: Vec::new(),
            result_ref: None,
        }),
    )
}
fn seed_large_assignee_history(f: &Fixture) -> TestResult {
    for index in 0..7 {
        let id = format!("task-{index}");
        assert!(project(&f.human, &sign(&f.human, "thread", &id, start(&id, "thread"))?)?.accepted);
    }
    // Seed a valid, signed committed prefix once; all boundary attempts use normal ingress.
    for task in 0..7 {
        let id = format!("task-{task}");
        let mut history = f.human.task_history("thread", &id)?;
        for offset in 0..16 {
            let c = sign(
                &f.agent,
                "thread",
                &format!("update-{}", offset * 7 + task),
                TaskEventBody::Update(TaskUpdate {
                    result_summary: None,
                    task_id: id.clone(),
                    version: 2 + offset,
                    state: TaskStatus::Running,
                    steps: (0..64)
                        .map(|step| TaskStep {
                            id: format!("step-{step}"),
                            title: "\u{7532}".repeat(256),
                            state: TaskStatus::Running,
                            needs_me: None,
                        })
                        .collect(),
                    result_ref: None,
                }),
            )?;
            history.events.push(AcceptedEvent {
                public_key: f.human.task_signer_key("agent", "agent-device")?,
                carrier: c,
                actor_kind_verified: actor_kind_verified(&f.human, "agent", "agent-device"),
                received_at: crate::time::now_unix_timestamp(),
                decision_certificate: None,
                membership: None,
            });
        }
        let state = history.state()?;
        let task = state.task().ok_or("task")?;
        f.human.account_db()?.persist_actor_state(&scoped("history", "thread", &id)?, &history)?;
        f.human.account_db()?.persist_actor_state(&scoped("view", "thread", &id)?, task)?;
        f.human.record_task_lifecycle(task, &history)?;
    }
    Ok(())
}
fn cancel_on(
    receiver: &RamfluxClient,
    signer: &RamfluxClient,
    id: &str,
    revision: u64,
) -> TestResult {
    assert!(
        project(
            receiver,
            &sign(
                signer,
                "thread",
                &format!("cancel:{id}"),
                TaskEventBody::Cancel(TaskCancel { task_id: id.into(), base_revision: revision })
            )?
        )?
        .accepted
    );
    Ok(())
}
fn verify_independent_requester_capacity(
    f: &Fixture,
) -> Result<RamfluxClient, Box<dyn std::error::Error>> {
    let other = register(f, "other", 81)?;
    f.human.account_db()?.persist_client_record(
        "conversation",
        "other-thread",
        &json!({"kind":"direct","participants":["human","other"]}),
    )?;
    for index in 0..4 {
        let id = format!("fresh-{index}");
        let mut body = peer_start(&id, "other-thread", "human", "other");
        if let TaskEventBody::Start(start) = &mut body {
            start.text = "f".repeat(16_384);
        }
        let c = sign(&f.human, "other-thread", &id, body)?;
        check_delivery_size(c.bytes()?.len())?;
        assert!(
            project(&f.human, &c)?.accepted,
            "an assignee cannot consume the requester's transport-sized requests to another executor"
        );
    }
    Ok(other)
}
#[test]
fn an_assignees_one_hundred_sixty_updates_cannot_spend_the_requesters_quota_or_prevent_cancellation()
-> TestResult {
    let f = Fixture::new()?;
    seed_large_assignee_history(&f)?;
    let mut rejected = 0;
    for index in 112..160 {
        let id = format!("task-{}", index % 7);
        let version =
            f.human.task_get(Some("thread"), &id)?["version"].as_u64().ok_or("revision")? + 1;
        let steps = if index < 120 {
            (0..64)
                .map(|step| TaskStep {
                    id: format!("step-{step}"),
                    title: "\u{7532}".repeat(256),
                    state: TaskStatus::Running,
                    needs_me: None,
                })
                .collect()
        } else {
            Vec::new()
        };
        let c = sign(
            &f.agent,
            "thread",
            &format!("update-{index}"),
            TaskEventBody::Update(TaskUpdate {
                result_summary: None,
                task_id: id,
                version,
                state: TaskStatus::Running,
                steps,
                result_ref: None,
            }),
        )?;
        if !project(&f.human, &c)?.accepted {
            rejected += 1;
        }
    }
    assert!(rejected > 0, "the assignee must exhaust its own bounded history budget");
    let other = verify_independent_requester_capacity(&f)?;
    let revision =
        f.human.task_get(Some("thread"), "task-0")?["version"].as_u64().ok_or("revision")?;
    assert!(
        project(
            &f.human,
            &sign(
                &f.human,
                "thread",
                "cancel",
                TaskEventBody::Cancel(TaskCancel {
                    task_id: "task-0".into(),
                    base_revision: revision
                })
            )?
        )?
        .accepted
    );
    assert_eq!(f.human.task_get(Some("thread"), "task-1")?["stalled_by_assignee"], true);
    f.human.maintain_task_lifecycle(crate::time::now_unix_timestamp())?;
    assert!(f.human.task_history("thread", "task-1")?.events.is_empty());
    assert_eq!(f.human.task_get(Some("thread"), "task-1")?["compacted"], true);
    let mut reopened = RamfluxClient::new();
    reopened.create_identity_root("human", [61; 32]);
    reopened.create_device_branch("human", "human-device", 1, [62; 32]);
    reopened.open_account_index(f.root.join("human"))?;
    reopened.unlock_account("human", b"task-test-secret")?;
    let revision =
        reopened.task_get(Some("thread"), "task-1")?["version"].as_u64().ok_or("revision")?;
    assert!(
        project(
            &reopened,
            &sign(
                &f.human,
                "thread",
                "cancel-after-reopen",
                TaskEventBody::Cancel(TaskCancel {
                    task_id: "task-1".into(),
                    base_revision: revision
                })
            )?
        )?
        .accepted
    );
    assert_eq!(reopened.task_get(Some("thread"), "task-1")?["state"], "cancelled");
    drop(reopened);
    drop(other);
    Ok(())
}
#[test]
fn a_compacted_stalled_intervention_preserves_verified_resolution_and_single_use() -> TestResult {
    let f = Fixture::new()?;
    decisions::open(&f, "task")?;
    let db = f.agent.account_db()?;
    let index = scoped("lifecycle", "thread", "task")?;
    let mut row = db.load_actor_state::<serde_json::Value>(&index)?.ok_or("lifecycle")?;
    row["compaction_eligible"] = json!(true);
    db.persist_actor_state(&index, &row)?;
    f.agent.maintain_task_lifecycle(crate::time::now_unix_timestamp())?;
    assert!(f.agent.task_history("thread", "task")?.events.is_empty());
    assert!(
        serde_json::to_value(f.agent.task_history("thread", "task")?)?.get("checkpoint").is_none()
    );
    let trusted = f.agent.task_history("thread", "task")?;
    let mut forged = serde_json::to_value(&trusted)?;
    forged["checkpoint"] = serde_json::to_value(&trusted.checkpoint)?;
    let received: TaskHistory = serde_json::from_value(forged)?;
    assert!(received.checkpoint.is_none());
    assert!(received.state()?.task().is_none());
    decisions::store(&f, &decisions::grant(&f)?)?;
    let c = sign(
        &f.human,
        "thread",
        "resolve",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.agent, &c)?.accepted);
    assert!(project(&f.agent, &c)?.accepted, "the same delivery has an idempotent receipt");
    let mut replay = c.clone();
    replay.message_id = "different-delivery".into();
    // A newly signed carrier of the same decision cannot spend it again.
    let replay = sign(
        &f.human,
        "thread",
        &replay.message_id,
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(!project(&f.agent, &replay)?.accepted);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?["version"], 3);
    Ok(())
}
#[test]
fn thirty_two_single_hold_pairs_cannot_exclude_a_new_honest_sender() -> TestResult {
    let f = Fixture::new()?;
    let mut peers = Vec::new();
    for source in 0..4u8 {
        let id = format!("peer-{source}");
        let peer = register(&f, &id, 90 + source * 2)?;
        for conversation in 0..8 {
            let thread = format!("{id}-{conversation}");
            f.human.account_db()?.persist_client_record(
                "conversation",
                &thread,
                &json!({"kind":"direct","participants":["human",id]}),
            )?;
            assert!(project(&f.human, &early(&peer, &thread, "gap")?)?.pending);
        }
        peers.push(peer);
    }
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 32);
    assert!(project(&f.human, &early(&f.agent, "thread", "honest-gap")?)?.pending);
    let rows = f.human.account_db()?.task_record_page::<serde_json::Value>(
        "task/pending/",
        "task/pending/",
        33,
    )?;
    assert_eq!(rows.len(), 32);
    assert!(rows.iter().any(|(_, r)| r["carrier"]["message_id"] == "honest-gap"));
    drop(peers);
    Ok(())
}
#[test]
fn rejected_no_role_group_tasks_never_hold_their_followup_events() -> TestResult {
    let f = Fixture::new()?;
    f.human.create_group("group", "human-device")?;
    f.human.add_group_member("group", "agent-device", "member")?;
    f.human.account_db()?.persist_client_record(
        "conversation",
        "group-thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let c = sign(
        &f.agent,
        "group-thread",
        "unrelated",
        peer_start("unrelated", "group-thread", "agent", "agent"),
    )?;
    assert!(!project(&f.human, &c)?.accepted);
    for index in 0..40 {
        let c = sign(
            &f.agent,
            "group-thread",
            &format!("followup-{index}"),
            TaskEventBody::Update(TaskUpdate {
                result_summary: None,
                task_id: "unrelated".into(),
                version: 2 + index,
                state: TaskStatus::Running,
                steps: Vec::new(),
                result_ref: None,
            }),
        )?;
        let outcome = project(&f.human, &c)?;
        assert!(!outcome.accepted);
        assert!(!outcome.pending);
    }
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 0);
    assert_eq!(f.human.account_db()?.task_state_usage("task/no_role/")?.0, 1);
    assert!(f.human.task_get(Some("group-thread"), "unrelated")?.is_null());
    Ok(())
}
#[test]
fn twenty_one_peer_terminal_rounds_compact_only_that_peers_history() -> TestResult {
    let f = Fixture::new()?;
    assert!(
        project(&f.human, &sign(&f.human, "thread", "mine", start("mine", "thread"))?)?.accepted
    );
    cancel_on(&f.human, &f.human, "mine", 1)?;
    // A local accept and local assignee work are voluntary signer actions, not peer allocations.
    assert!(project(&f.human, &sign(&f.agent, "thread", "proposal", proposal())?)?.accepted);
    assert!(
        project(
            &f.human,
            &sign(
                &f.human,
                "thread",
                "accept",
                TaskEventBody::Accept(TaskAccept { task_id: "proposal".into(), version: 2 })
            )?
        )?
        .accepted
    );
    cancel_on(&f.human, &f.human, "proposal", 2)?;
    assert!(
        project(
            &f.human,
            &sign(&f.agent, "thread", "worked", peer_start("worked", "thread", "agent", "human"))?
        )?
        .accepted
    );
    assert!(
        project(
            &f.human,
            &sign(
                &f.human,
                "thread",
                "work",
                TaskEventBody::Update(TaskUpdate {
                    result_summary: None,
                    task_id: "worked".into(),
                    version: 2,
                    state: TaskStatus::Running,
                    steps: Vec::new(),
                    result_ref: None
                })
            )?
        )?
        .accepted
    );
    cancel_on(&f.human, &f.agent, "worked", 2)?;
    let index = scoped("lifecycle", "thread", "mine")?;
    let mut row =
        f.human.account_db()?.load_actor_state::<serde_json::Value>(&index)?.ok_or("lifecycle")?;
    row["updated_at"] = json!(crate::time::now_unix_timestamp() - 1);
    f.human.account_db()?.persist_actor_state(&index, &row)?;
    for index in 0..21 {
        let id = format!("peer-{index}");
        assert!(
            project(
                &f.human,
                &sign(&f.agent, "thread", &id, peer_start(&id, "thread", "agent", "human"))?
            )?
            .accepted
        );
        cancel_on(&f.human, &f.agent, &id, 1)?;
    }
    assert_eq!(f.human.task_history("thread", "mine")?.events.len(), 2);
    assert_ne!(f.human.task_get(Some("thread"), "mine")?["compacted"], true);
    assert_eq!(f.human.task_history("thread", "proposal")?.events.len(), 3);
    assert_eq!(f.human.task_history("thread", "worked")?.events.len(), 3);
    assert!(f.human.account_db()?.task_state_usage("task/history/")?.0 <= 19);
    Ok(())
}
#[test]
fn four_senders_at_their_rate_limits_cannot_spend_the_local_senders_rate_budget() -> TestResult {
    let f = Fixture::new()?;
    let mut peers = Vec::new();
    for index in 0..4u8 {
        let id = format!("peer-{index}");
        let peer = register(&f, &id, 100 + index * 2)?;
        f.human.account_db()?.persist_client_record(
            "conversation",
            &id,
            &json!({"kind":"direct","participants":["human",id]}),
        )?;
        for item in 0..128 {
            let task = format!("task-{item}");
            let c = sign(&peer, &id, &task, peer_start(&task, &id, &id, &id))?;
            assert!(!project(&f.human, &c)?.accepted);
        }
        peers.push(peer);
    }
    assert!(
        project(&f.human, &sign(&f.human, "thread", "fresh", start("fresh", "thread"))?)?.accepted
    );
    drop(peers);
    Ok(())
}
#[test]
fn fallback_actor_kind_qualifiers_follow_the_callers_single_verified_kind_result() -> TestResult {
    let f = Fixture::new()?;
    let c = sign(
        &f.human,
        "thread",
        "accept",
        TaskEventBody::Accept(TaskAccept { task_id: "task".into(), version: 2 }),
    )?;
    let event = c.event()?;
    assert!(
        event.fallback_text_with_actor_kind(false).contains("accepted (actor kind unverified)")
    );
    assert!(!event.fallback_text_with_actor_kind(true).contains("actor kind unverified"));
    assert!(!event.fallback_text_with_actor_kind(true).contains("by a human"));
    assert_eq!(event.fallback_text(), event.fallback_text_with_actor_kind(false));
    Ok(())
}
#[test]
fn the_ordinary_history_event_limit_keeps_a_reserved_requester_cancellation_slot() -> TestResult {
    let f = Fixture::new()?;
    assert!(
        project(&f.human, &sign(&f.human, "thread", "start", start("task", "thread"))?)?.accepted
    );
    let mut history = f.human.task_history("thread", "task")?;
    for version in 2..=256 {
        let c = sign(
            &f.agent,
            "thread",
            &format!("update-{version}"),
            TaskEventBody::Update(TaskUpdate {
                result_summary: None,
                task_id: "task".into(),
                version,
                state: TaskStatus::Running,
                steps: Vec::new(),
                result_ref: None,
            }),
        )?;
        history.events.push(AcceptedEvent {
            public_key: f.human.task_signer_key("agent", "agent-device")?,
            carrier: c,
            actor_kind_verified: actor_kind_verified(&f.human, "agent", "agent-device"),
            received_at: 1,
            decision_certificate: None,
            membership: None,
        });
    }
    let state = history.state()?;
    let task = state.task().ok_or("task")?;
    f.human.account_db()?.persist_actor_state(&scoped("history", "thread", "task")?, &history)?;
    f.human.account_db()?.persist_actor_state(&scoped("view", "thread", "task")?, task)?;
    f.human.record_task_lifecycle(task, &history)?;
    cancel_on(&f.human, &f.human, "task", 256)?;
    assert_eq!(f.human.task_get(Some("thread"), "task")?["state"], "cancelled");
    Ok(())
}

#[path = "r4_quota_tests.rs"]
mod r4;
