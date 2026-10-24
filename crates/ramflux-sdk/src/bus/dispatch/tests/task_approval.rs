// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The approval courier feeds the existing MCP validator before an executor can resume.
use super::*;
use crate::bus::runtime_tests;
use crate::client::task::Delivery;
use ramflux_protocol::{
    NeedsMe, TaskDecision, TaskEvent, TaskEventBody, TaskResolve, TaskStart, TaskStatus, TaskStep,
    TaskUpdate,
};
use std::sync::{Arc, atomic::AtomicBool};
#[test]
fn a_remote_requester_approval_round_trip_is_accepted_by_mcp_before_the_agent_resumes()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("task-approval-mcp");
    let mut agent = runtime_tests::account(
        &root.join("agent"),
        "agent",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let human = runtime_tests::account(
        &root.join("human"),
        "human",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    open_task(&human, &agent)?;
    let arguments = json!({"command":"echo approved"});
    let hash = ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::MCP_GRANT,
        &ramflux_protocol::canonical_json_bytes(&arguments)?,
    );
    agent.mcp_pending_approvals.insert("approval".into(),LocalMcpApprovalRecord {approval_id:"approval".into(),server_id:"shell".into(),tool_name:"run".into(),capability:McpCapability::RunShell,risk_level:RiskLevel::High,tool_scope:None,confirmation_mode:"remote_app".into(),expires_at:now_unix_timestamp()+300,status:"pending".into(),details:json!({"requested_grant_id":"grant","arguments":arguments,"arguments_hash":hash,"single_use":true,"full_delegation":false})});
    queue_requests(&mut agent)?;
    let jobs = agent.client.account_db()?.task_record_page::<Job>(
        "task/approval_out/",
        "task/approval_out/",
        10,
    )?;
    assert_eq!(jobs.len(), 1);
    human.client.accept_task_approval(&jobs[0].1.packet)?;
    let rows = list(&human)?;
    assert_eq!(rows.len(), 1);
    let id = rows[0]["approval_id"].as_str().ok_or("id")?;
    human.client.decide_task_approval(id, true)?;
    let decisions = human.client.account_db()?.task_record_page::<Job>(
        "task/approval_decision_out/",
        "task/approval_decision_out/",
        10,
    )?;
    agent.client.accept_task_approval(&decisions[0].1.packet)?;
    apply_decisions(&mut agent)?;
    apply_decisions(&mut agent)?;
    let grant = agent.mcp_grants.get("grant").ok_or("MCP grant not accepted")?;
    assert!(grant.signing_body.task_binding.is_some());
    assert_eq!(grant.signed_by_device_id, "device-human");
    let body = TaskResolve {
        task_id: "task".into(),
        base_revision: 2,
        step_id: "step".into(),
        target: NeedsMe::Approval { grant_id: "grant".into() },
        decision_id: "approval".into(),
        decision: TaskDecision::Resume,
    };
    let d = human.client.device_branch.as_ref().ok_or("device")?;
    let c = human.client.sign_task_event(
        TaskEvent::new(
            "thread".into(),
            TaskEventBody::Resolve(body),
            sdk_device_signed_fields(&d.device_id, ""),
        )?,
        "resolve".into(),
        None,
    )?;
    assert!(
        agent
            .client
            .project_task_message(
                &Delivery {
                    conversation: "thread",
                    message: "resolve",
                    principal: "human",
                    device: &d.device_id,
                    at: now_unix_timestamp()
                },
                &c.bytes()?
            )?
            .ok_or("resolve")?
            .accepted
    );
    assert_eq!(agent.client.task_get(Some("thread"), "task")?["version"], 3);
    agent.client.account_db()?.set_mcp_grant_revoked("grant")?;
    let id = decisions[0].1.packet.id()?;
    agent.client.account_db()?.delete_task_state(&key("approval_applied", &id))?;
    agent.client.account_db()?.delete_task_state(&key("approval_receipt", &id))?;
    agent
        .client
        .account_db()?
        .persist_actor_state(&key("approval_source", &id), &jobs[0].1.packet)?;
    agent
        .client
        .account_db()?
        .persist_actor_state(&key("approval_decision_in", &id), &decisions[0].1.packet)?;
    apply_decisions(&mut agent)?;
    assert!(
        agent.mcp_grants.get("grant").ok_or("consumed grant")?.state.revoked,
        "recovery cannot re-enable a consumed grant"
    );
    drop(agent);
    drop(human);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn open_task(
    human: &LocalBusAccountState,
    agent: &LocalBusAccountState,
) -> Result<(), Box<dyn std::error::Error>> {
    for (local, remote) in [(agent, human), (human, agent)] {
        local.client.persist_identity_directory(&crate::client::task::tests::own::manifest(
            &remote.client,
        )?)?;
        local.client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"direct","participants":["human","agent"]}),
        )?;
    }
    let bodies = [
        TaskEventBody::Start(TaskStart {
            task_id: "task".into(),
            conversation_id: "thread".into(),
            requester: "human".into(),
            assignee: "agent".into(),
            text: "Inspect".into(),
            constraints: None,
        }),
        TaskEventBody::Update(TaskUpdate {
            task_id: "task".into(),
            version: 2,
            state: TaskStatus::NeedsMe,
            steps: vec![TaskStep {
                id: "step".into(),
                title: "Run".into(),
                state: TaskStatus::NeedsMe,
                needs_me: Some(NeedsMe::Approval { grant_id: "grant".into() }),
            }],
            result_ref: None,
            result_summary: None,
        }),
    ];
    for (i, body) in bodies.into_iter().enumerate() {
        let author = if i == 0 { &human } else { &agent };
        let d = author.client.device_branch.as_ref().ok_or("device")?;
        let c = author.client.sign_task_event(
            TaskEvent::new("thread".into(), body, sdk_device_signed_fields(&d.device_id, ""))?,
            format!("event-{i}"),
            None,
        )?;
        for local in [human, agent] {
            assert!(
                local
                    .client
                    .project_task_message(
                        &Delivery {
                            conversation: "thread",
                            message: &c.message_id,
                            principal: &c.principal_id,
                            device: &c.device_id,
                            at: now_unix_timestamp()
                        },
                        &c.bytes()?
                    )?
                    .ok_or("projection")?
                    .accepted
            );
        }
    }

    Ok(())
}

#[path = "task_approval_r5.rs"]
mod r5;
