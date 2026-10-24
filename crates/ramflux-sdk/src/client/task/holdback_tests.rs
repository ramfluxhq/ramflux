// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Colluding peer and silent-executor regressions for independent local intent progress.
use super::*;
fn early(c: &RamfluxClient, thread: &str, id: &str) -> Result<carrier::Carrier, SdkError> {
    sign(
        c,
        thread,
        id,
        TaskEventBody::Update(TaskUpdate {
            task_id: id.into(),
            version: 2,
            state: TaskStatus::Running,
            steps: Vec::new(),
            result_ref: None,
        }),
    )
}
#[test]
fn four_colluding_peers_cannot_exclude_an_honest_peer_or_the_local_requesters_resolve() -> TestResult
{
    let f = Fixture::new()?;
    decisions::open(&f, "task")?;
    let mut peers = Vec::new();
    for index in 0..4u8 {
        let id = format!("peer-{index}");
        let peer = client(&f.root.join(&id), &id, 90 + index * 2)?;
        let device = peer.device_branch.as_ref().ok_or("device")?;
        f.human.account_db()?.persist_client_record("device", &device.device_id, &json!({"principal_id":id,"signing_public_key":ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes())}))?;
        f.human.account_db()?.persist_client_record(
            "conversation",
            &id,
            &json!({"kind":"direct","participants":["human",id]}),
        )?;
        for event in 0..8 {
            assert!(project(&f.human, &early(&peer, &id, &format!("gap-{event}"))?)?.pending);
        }
        peers.push(peer);
    }
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 32);
    assert!(project(&f.human, &early(&f.agent, "thread", "honest-gap")?)?.pending);
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 32);
    let holds = f.human.account_db()?.task_record_page::<serde_json::Value>(
        "task/pending/",
        "task/pending/",
        33,
    )?;
    assert!(holds.iter().any(|(_, row)| row["carrier"]["message_id"] == "honest-gap"));
    let resolve = sign(
        &f.human,
        "thread",
        "local-resolve",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.human, &resolve)?.pending);
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_pending/")?.0, 1);
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 32);
    drop(peers);
    Ok(())
}
#[test]
fn silent_executor_timeouts_release_local_slots_while_the_intents_remain_visible() -> TestResult {
    let f = Fixture::new()?;
    for index in 0..9 {
        let id = format!("task-{index}");
        decisions::open(&f, &id)?;
        let c = sign(
            &f.human,
            "thread",
            &format!("resolve-{index}"),
            TaskEventBody::Resolve(decisions::resolution(
                &id,
                ramflux_protocol::TaskDecision::Resume,
            )),
        )?;
        if index < 8 {
            assert!(project(&f.human, &c)?.pending);
        } else {
            assert!(project(&f.human, &c).is_err());
        }
    }
    f.human.retry_pending_tasks(crate::time::now_unix_timestamp() + 61)?;
    let c = sign(
        &f.human,
        "thread",
        "resolve-after-timeout",
        TaskEventBody::Resolve(decisions::resolution(
            "task-8",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.human, &c)?.pending);
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_pending/")?.0, 1);
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_intent_status/")?.0, 8);
    let metadata =
        f.human.task_message_metadata("thread", "resolve-0")?.ok_or("pending metadata")?;
    assert_eq!(metadata["pending"], true);
    assert!(metadata["fallback_text"].as_str().ok_or("fallback")?.contains("timed out"));
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 0);
    Ok(())
}

#[test]
fn upgrading_a_local_resolve_from_the_old_peer_pool_releases_its_peer_and_timeout_slots()
-> TestResult {
    let f = Fixture::new()?;
    decisions::open(&f, "task")?;
    let c = sign(
        &f.human,
        "thread",
        "old-intent",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    let now = crate::time::now_unix_timestamp();
    let old =
        scoped("pending", "thread", &serde_json::to_string(&(&c.principal_id, &c.message_id))?)?;
    f.human.account_db()?.persist_actor_state(&old, &json!({"carrier":c,"conversation":"thread","message":"old-intent","at":now,"expires_at":now+600}))?;
    f.human.retry_pending_tasks(now)?;
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 0);
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_pending/")?.0, 1);
    f.human.retry_pending_tasks(now + 61)?;
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_pending/")?.0, 0);
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_intent_status/")?.0, 1);
    Ok(())
}
