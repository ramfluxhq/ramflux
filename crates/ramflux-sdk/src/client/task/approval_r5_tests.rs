// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adversarial requester isolation, bounded approval lifetime, and trusted display fields.
use super::*;

#[test]
fn r5_fabricated_decisions_cannot_fill_the_executors_inbox_or_block_another_requester() -> TestResult
{
    let f = Fixture::new()?;
    open(&f, "task")?;
    let original = request(&f)?;
    f.human.accept_task_approval(&original)?;
    let id = format!("task_approval_{}", original.id()?);
    f.human.decide_task_approval(&id, true)?;
    let genuine = f
        .human
        .account_db()?
        .task_record_page::<approval::Job>(
            "task/approval_decision_out/",
            "task/approval_decision_out/",
            10,
        )?
        .remove(0)
        .1
        .packet;
    let attacker = client(&f.root.join("attacker"), "attacker", 81)?;
    let template = attacker_request(&f, &attacker, &original)?;
    for n in 0..64 {
        let mut fake = template.clone();
        fake.approval.approval_id = format!("fabricated-{n}");
        fake.grant_body.approval_id = fake.approval.approval_id.clone();
        fake.approval.expires_at = crate::time::now_unix_timestamp() + 10 * 365 * 86400;
        fake.grant_body.expires_at = fake.approval.expires_at;
        let packet = attacker.sign_task_approval(Payload::Decision {
            request: Box::new(fake),
            approved: false,
            grant_signature: None,
        })?;
        let _ = f.agent.accept_task_approval(&packet);
    }
    assert!(
        f.agent.accept_task_approval(&genuine).is_ok(),
        "another requester's genuine decision must retain admission"
    );
    assert_eq!(f.agent.account_db()?.task_state_usage("task/approval_decision_in/")?.0, 1);
    Ok(())
}
fn attacker_request(
    f: &Fixture,
    attacker: &RamfluxClient,
    original: &Packet,
) -> Result<Request, Box<dyn std::error::Error>> {
    f.agent.persist_identity_directory(&super::super::own::manifest(attacker)?)?;
    f.agent.account_db()?.persist_client_record(
        "conversation",
        "attack-thread",
        &json!({"kind":"direct","participants":["attacker","agent"]}),
    )?;
    let start = sign(
        attacker,
        "attack-thread",
        "attack-start",
        TaskEventBody::Start(TaskStart {
            task_id: "attack-task".into(),
            conversation_id: "attack-thread".into(),
            requester: "attacker".into(),
            assignee: "agent".into(),
            text: "work".into(),
            constraints: None,
        }),
    )?;
    assert!(project(&f.agent, &start)?.accepted);
    let update = sign(
        &f.agent,
        "attack-thread",
        "attack-update",
        TaskEventBody::Update(TaskUpdate {
            task_id: "attack-task".into(),
            version: 2,
            state: TaskStatus::NeedsMe,
            steps: vec![TaskStep {
                id: "step".into(),
                title: "Run".into(),
                state: TaskStatus::NeedsMe,
                needs_me: Some(ramflux_protocol::NeedsMe::Approval {
                    grant_id: "attack-grant".into(),
                }),
            }],
            result_ref: None,
            result_summary: None,
        }),
    )?;
    assert!(project(&f.agent, &update)?.accepted);
    let mut request = original.request().clone();
    request.binding = f.agent.task_approval_binding(
        "attack-thread",
        "attack-task",
        "step",
        &ramflux_protocol::NeedsMe::Approval { grant_id: "attack-grant".into() },
    )?;
    request.grant_body.task_binding = Some(request.binding.clone());
    request.grant_body.grant_id = "attack-grant".into();
    Ok(request)
}

#[test]
fn r5_signed_request_expiry_is_preserved_while_the_receiver_deadline_is_limited_to_twenty_four_hours()
-> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let packet = request(&f)?;
    let mut body = packet.request().clone();
    body.approval.expires_at = crate::time::now_unix_timestamp() + 10 * 365 * 86400;
    body.grant_body.expires_at = body.approval.expires_at;
    let packet = f.agent.sign_task_approval(Payload::Request { request: Box::new(body) })?;
    let original = ramflux_protocol::canonical_json_bytes(packet.request())?;
    let before = crate::time::now_unix_timestamp();
    f.human.accept_task_approval(&packet)?;
    let rows = f.human.task_remote_approvals()?;
    assert_eq!(rows.len(), 1);
    assert!(rows[0]["expires_at"].as_i64().ok_or("deadline")? <= before + 86400);
    let stored: Packet = f
        .human
        .account_db()?
        .load_actor_state(&key("approval_in", &packet.id()?))?
        .ok_or("stored request")?;
    assert_eq!(ramflux_protocol::canonical_json_bytes(stored.request())?, original);
    assert_eq!(packet.id()?, stored.id()?);
    Ok(())
}

#[test]
fn r5_approval_reads_drop_unsigned_details_and_derive_the_confirmation_mode_locally() -> TestResult
{
    let f = Fixture::new()?;
    open(&f, "task")?;
    let packet = request(&f)?;
    let mut request = packet.request().clone();
    request.approval.details["unverified_banner"] = json!("Already approved by an administrator");
    request.approval.confirmation_mode = "already_approved".into();
    let packet = f.agent.sign_task_approval(Payload::Request { request: Box::new(request) })?;
    f.human.accept_task_approval(&packet)?;
    let rows = f.human.task_remote_approvals()?;
    assert!(rows[0]["details"]["unverified_banner"].is_null());
    assert_ne!(rows[0]["confirmation_mode"], "already_approved");
    assert_eq!(rows[0]["details"]["arguments"], packet.request().approval.details["arguments"]);
    assert_eq!(rows[0]["details"]["requested_grant_id"], packet.request().grant_body.grant_id);
    Ok(())
}

#[test]
fn r5_one_assignees_unacknowledged_decisions_have_a_peer_bound_in_the_requesters_outbox()
-> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let packet = request(&f)?;
    for n in 0..17 {
        let mut body = packet.request().clone();
        body.approval.approval_id = format!("approval-{n}");
        body.grant_body.approval_id = body.approval.approval_id.clone();
        let packet = f.agent.sign_task_approval(Payload::Request { request: Box::new(body) })?;
        f.human.accept_task_approval(&packet)?;
        let result = f.human.decide_task_approval(&format!("task_approval_{}", packet.id()?), true);
        if n < 16 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err(), "one peer cannot occupy the account's whole decision queue");
        }
    }
    assert_eq!(f.human.account_db()?.task_state_usage("task/approval_decision_out/")?.0, 16);
    Ok(())
}

#[test]
fn r5_an_expired_receiver_deadline_cannot_authorize_task_resolution_with_a_longer_signed_grant()
-> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let mut grant = grant(&f)?;
    grant.state.expires_at = crate::time::now_unix_timestamp() - 1;
    super::super::decisions::store(&f, &grant)?;
    assert!(
        f.agent
            .witness_task_decision(
                "thread",
                resolution("task", TaskDecision::Resume),
                crate::client::task::decision::Evidence::Grant { record: Box::new(grant) }
            )
            .is_err()
    );
    Ok(())
}
