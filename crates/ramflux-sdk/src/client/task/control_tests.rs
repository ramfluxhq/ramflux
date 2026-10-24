// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Executor controls retain pending requester intents until authenticated confirmation arrives.
use super::*;
fn entry(principal: &str, device: &str) -> crate::GatewayInboxEntry {
    crate::GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: "target".into(),
        envelope: ramflux_protocol::Envelope {
            schema: "ramflux.envelope.v1".into(),
            version: 1,
            domain: "task".into(),
            ext: ramflux_protocol::Ext::default(),
            signed: crate::prelude::sdk_device_signed_fields(device, ""),
            envelope_id: "control-envelope".into(),
            source_principal_id: principal.into(),
            source_device_id: device.into(),
            target_delivery_id: "target".into(),
            routing_set_id: None,
            delivery_class: ramflux_protocol::DeliveryClass::SelfDeviceControl,
            priority: ramflux_protocol::Priority::Normal,
            ttl: 600,
            created_at: crate::time::now_unix_timestamp(),
            encrypted_payload: String::new(),
            payload_hash: String::new(),
        },
    }
}
#[test]
fn executor_acknowledgement_applies_the_original_pending_intent_only_from_the_authenticated_executor()
-> TestResult {
    let f = Fixture::new()?;
    decisions::open(&f, "task")?;
    let intent = sign(
        &f.human,
        "thread",
        "intent",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.human, &intent)?.pending);
    let control = control::Control::Intent {
        carrier_base64: ramflux_protocol::encode_base64url(intent.bytes()?),
    }
    .bytes()?;
    assert!(f.agent.receive_task_control(
        &entry("human", "human-device"),
        "thread",
        None,
        &control
    )?);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?["version"], 2);
    decisions::store(&f, &decisions::grant(&f)?)?;
    assert_eq!(f.agent.retry_pending_tasks(crate::time::now_unix_timestamp())?, 1);
    let jobs =
        f.agent.account_db()?.task_record_page::<control::AckJob>("task/ack/", "task/ack/", 65)?;
    assert_eq!(jobs.len(), 1);
    let ack = control::Control::Ack(Box::new(jobs[0].1.ack.clone())).bytes()?;
    assert!(
        f.human
            .receive_task_control(&entry("human", "human-device"), "thread", None, &ack)
            .is_err()
    );
    assert_eq!(f.human.task_get(Some("thread"), "task")?["version"], 2);
    assert!(f.human.receive_task_control(&entry("agent", "agent-device"), "thread", None, &ack)?);
    assert_eq!(f.human.task_get(Some("thread"), "task")?["version"], 3);
    assert_eq!(f.human.task_history("thread", "task")?.events.len(), 3);
    assert!(f.human.receive_task_control(&entry("agent", "agent-device"), "thread", None, &ack)?);
    assert_eq!(f.human.task_history("thread", "task")?.events.len(), 3);
    Ok(())
}
#[test]
fn an_identical_intent_retry_requeues_a_lost_confirmation_without_reconsuming_the_decision()
-> TestResult {
    let f = Fixture::new()?;
    decisions::open(&f, "task")?;
    decisions::store(&f, &decisions::grant(&f)?)?;
    let intent = sign(
        &f.human,
        "thread",
        "intent",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.agent, &intent)?.accepted);
    let jobs =
        f.agent.account_db()?.task_record_page::<control::AckJob>("task/ack/", "task/ack/", 65)?;
    assert_eq!(jobs.len(), 1);
    f.agent.account_db()?.delete_task_state(&jobs[0].0)?;
    assert!(project(&f.agent, &intent)?.accepted);
    assert_eq!(f.agent.account_db()?.task_state_usage("task/ack/")?.0, 1);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?["version"], 3);
    assert_eq!(f.agent.task_history("thread", "task")?.events.len(), 3);
    Ok(())
}

#[test]
fn a_late_executor_ack_commits_a_compacted_local_intent_and_preserves_its_original_message()
-> TestResult {
    let f = Fixture::new()?;
    decisions::open(&f, "task")?;
    let intent = sign(
        &f.human,
        "thread",
        "intent",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.human, &intent)?.pending);
    f.human.retry_pending_tasks(crate::time::now_unix_timestamp() + 61)?;
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_pending/")?.0, 0);
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_intent_status/")?.0, 1);
    decisions::store(&f, &decisions::grant(&f)?)?;
    assert!(project(&f.agent, &intent)?.accepted);
    let jobs =
        f.agent.account_db()?.task_record_page::<control::AckJob>("task/ack/", "task/ack/", 65)?;
    let ack = control::Control::Ack(Box::new(jobs[0].1.ack.clone())).bytes()?;
    assert!(f.human.receive_task_control(&entry("agent", "agent-device"), "thread", None, &ack)?);
    assert_eq!(f.human.task_get(Some("thread"), "task")?["version"], 3);
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_intent_status/")?.0, 0);
    assert_eq!(
        f.human.task_message_metadata("thread", "intent")?.ok_or("metadata")?["pending"],
        false
    );
    Ok(())
}
#[test]
fn compacted_local_intents_still_reject_message_id_collisions_from_a_different_event() -> TestResult
{
    let f = Fixture::new()?;
    decisions::open(&f, "task")?;
    let intent = sign(
        &f.human,
        "thread",
        "intent",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.human, &intent)?.pending);
    f.human.retry_pending_tasks(crate::time::now_unix_timestamp() + 61)?;
    let collision = sign(&f.human, "thread", "intent", start("different-task", "thread"))?;
    assert!(project(&f.human, &collision).is_err());
    assert!(f.human.task_get(Some("thread"), "different-task")?.is_null());
    assert_eq!(f.human.account_db()?.task_state_usage("task/local_intent_status/")?.0, 1);
    Ok(())
}
