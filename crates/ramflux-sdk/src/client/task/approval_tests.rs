// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Requester-visible task approval requests, signed cross-device decisions, and durable pending reads.
use super::decisions::{grant, open, resolution};
use super::*;
use crate::client::task::approval::{Packet, Payload, Request};
use ramflux_protocol::TaskDecision;
use serde_json::Value;
fn request(f: &Fixture) -> Result<Packet, SdkError> {
    let grant = grant(f)?;
    let mut body = grant.signing_body;
    let arguments = json!({"command":"echo approved"});
    body.arguments_hash = Some(ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::MCP_GRANT,
        &ramflux_protocol::canonical_json_bytes(&arguments)?,
    ));
    let binding = body.task_binding.clone().ok_or_else(|| invalid("binding"))?;
    let approval = crate::LocalMcpApprovalRecord {
        approval_id: body.approval_id.clone(),
        server_id: body.server_id.clone(),
        tool_name: body.tool_name.clone(),
        capability: body.capability.clone(),
        risk_level: ramflux_protocol::RiskLevel::High,
        tool_scope: body.tool_scope.clone(),
        confirmation_mode: "remote_app".into(),
        expires_at: body.expires_at,
        status: "pending".into(),
        details: json!({"arguments":arguments,"requested_grant_id":body.grant_id,"single_use":true,"arguments_hash":body.arguments_hash,"task_binding":binding}),
    };
    let packet = f.agent.sign_task_approval(Payload::Request {
        request: Box::new(Request { binding, approval, grant_body: body }),
    })?;
    f.agent.account_db()?.persist_actor_state(&key("approval_source", &packet.id()?), &packet)?;
    Ok(packet)
}
#[test]
fn a_requesters_second_device_reads_the_remote_approval_and_returns_a_task_bound_signed_decision()
-> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let packet = request(&f)?;
    f.human.accept_task_approval(&packet)?;
    let mut sibling = client(&f.root.join("human2"), "human", 61)?;
    sibling.create_device_branch("human", "human2-device", 1, [65; 32]);
    // The same-root history carries the task and verified peer device key, never an executable grant.
    super::own::manifests(&f)?;
    sibling.import_own_task_packets(&f.human.own_task_packets("human2-device")?, "human-device")?;
    sibling.accept_task_approval(&packet)?;
    let rows = sibling.task_remote_approvals()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["task_binding"]["task_id"], "task");
    let id = rows[0]["approval_id"].as_str().ok_or("approval id")?;
    assert_eq!(sibling.canonical_task_approval_decision(id, "thread", "task", "step")?, "approval");
    assert!(sibling.canonical_task_approval_decision(id, "thread", "other", "step").is_err());
    assert!(
        sibling
            .account_db()?
            .journal_after(0, 128)?
            .iter()
            .any(|row| row.topic == "mcp.approval.request")
    );
    let decision = sibling.decide_task_approval(id, true)?;
    assert_eq!(decision["decision_id"], "approval");
    assert_eq!(sibling.task_remote_approvals()?, Vec::<Value>::new());
    let jobs = sibling.account_db()?.task_record_page::<approval::Job>(
        "task/approval_decision_out/",
        "task/approval_decision_out/",
        10,
    )?;
    let reply = &jobs[0].1.packet;
    let d = sibling.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    for local in [&f.agent, &f.human] {
        local.account_db()?.persist_client_record("device",&d.device_id,&json!({"principal_id":"human","signing_public_key":ramflux_protocol::encode_base64url(d.signing_key.verifying_key().to_bytes())}))?;
        local.accept_task_approval(reply)?;
        local.accept_task_approval(reply)?;
    }
    assert_eq!(f.human.task_remote_approvals()?, Vec::<Value>::new());
    let Payload::Decision { grant_signature: Some(signature), request, .. } = &reply.payload else {
        return Err("decision missing".into());
    };
    ramflux_crypto::verify_device_branch_signature(
        &ramflux_protocol::encode_base64url(d.signing_key.verifying_key().to_bytes()),
        &request.grant_body,
        signature,
    )?;
    let mut changed = reply.clone();
    if let Payload::Decision { request, .. } = &mut changed.payload {
        request.binding.opening_revision += 1;
    }
    assert!(f.agent.accept_task_approval(&changed).is_err());
    assert!(
        f.human.decide_task_approval(id, false).is_err(),
        "another device cannot replace the first decision"
    );
    drop(sibling);
    Ok(())
}
#[test]
fn requester_approval_is_a_durable_pending_resolution_after_writer_restart() -> TestResult {
    let mut f = Fixture::new()?;
    open(&f, "task")?;
    let c = sign(
        &f.human,
        "thread",
        "intent",
        TaskEventBody::Resolve(resolution("task", TaskDecision::Resume)),
    )?;
    assert!(project(&f.human, &c)?.pending);
    let before = f.human.task_get(Some("thread"), "task")?["pending_resolution"].clone();
    assert_eq!(before["task_id"], "task");
    assert_eq!(before["state"], "awaiting_executor");
    drop(f.human.active_account_db.take());
    f.human.unlock_account("human", b"task-test-secret")?;
    let restored = &f.human;
    assert_eq!(restored.task_get(Some("thread"), "task")?["pending_resolution"], before);
    let view = restored.task_get(Some("thread"), "task")?;
    assert_eq!(view["actors"]["requester"]["actor_kind_verified"], false);
    assert_eq!(view["actors"]["assignee"]["actor_kind_verified"], false);
    Ok(())
}

#[test]
fn an_assignee_cannot_show_different_arguments_from_the_human_signed_tool_capability() -> TestResult
{
    let f = Fixture::new()?;
    open(&f, "task")?;
    let mut packet = request(&f)?;
    if let Payload::Request { request } = &mut packet.payload {
        request.approval.details["arguments"] = json!({"command":"different"});
    }
    let changed = f.agent.sign_task_approval(packet.payload)?;
    assert!(f.human.accept_task_approval(&changed).is_err());
    assert_eq!(f.human.task_remote_approvals()?, Vec::<Value>::new());
    Ok(())
}

#[test]
fn peer_request_capacity_cannot_consume_the_requesters_decision_return_headroom() -> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let packet = request(&f)?;
    f.human.accept_task_approval(&packet)?;
    let db = f.human.account_db()?;
    // Seed the local encrypted queue indexes at their boundary. The decision uses
    // the actual validated request and the normal attended decision implementation.
    for i in 0..63 {
        db.persist_actor_state(&key("approval_in", &format!("full-{i}")), &packet)?;
    }
    for i in 0..32 {
        db.persist_actor_state(
            &key("approval_out", &format!("full-{i}")),
            &approval::Job { packet: packet.clone(), attempts: 0, next_at: 0 },
        )?;
    }
    let id = format!("task_approval_{}", packet.id()?);
    let result = f.human.decide_task_approval(&id, true)?;
    assert_eq!(result["status"], "approved");
    assert_eq!(db.task_state_usage("task/approval_decision_out/")?.0, 1);
    assert_eq!(db.task_state_usage("task/approval_decision_in/")?.0, 0);
    assert_eq!(db.task_state_usage("task/approval_receipt/")?.0, 1);
    assert_eq!(f.human.decide_task_approval(&id, true)?["status"], "approved");
    assert!(f.human.decide_task_approval(&id, false).is_err());
    Ok(())
}

#[test]
fn r5_pending_resolution_names_its_step_across_restart_and_executor_timeout() -> TestResult {
    let mut f = Fixture::new()?;
    open(&f, "task")?;
    let c = sign(
        &f.human,
        "thread",
        "intent",
        TaskEventBody::Resolve(resolution("task", TaskDecision::Resume)),
    )?;
    assert!(project(&f.human, &c)?.pending);
    assert_eq!(f.human.task_get(Some("thread"), "task")?["pending_resolution"]["step_id"], "step");
    drop(f.human.active_account_db.take());
    f.human.unlock_account("human", b"task-test-secret")?;
    assert_eq!(f.human.task_get(Some("thread"), "task")?["pending_resolution"]["step_id"], "step");
    f.human.release_local_task_slots(crate::time::now_unix_timestamp() + 61)?;
    let pending = f.human.task_get(Some("thread"), "task")?["pending_resolution"].clone();
    assert_eq!(pending["step_id"], "step");
    assert_eq!(pending["state"], "executor_timeout");
    Ok(())
}

#[path = "approval_r5_tests.rs"]
mod r5;
