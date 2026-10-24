// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonical decision equivalence, courier isolation, retirement, and visible retry recovery.
use super::*;
use ramflux_protocol::TaskCancel;
type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn pair(label: &str) -> Case<(PathBuf, LocalBusAccountState, LocalBusAccountState)> {
    let root = runtime_tests::root(label);
    let agent = runtime_tests::account(
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
    Ok((root, agent, human))
}
fn open_named(
    human: &LocalBusAccountState,
    agent: &LocalBusAccountState,
    id: &str,
    grant: &str,
) -> Case {
    open_for(human, agent, id, grant, "thread")
}
fn open_for(
    human: &LocalBusAccountState,
    agent: &LocalBusAccountState,
    id: &str,
    grant: &str,
    conversation: &str,
) -> Case {
    let human_id = human.client.device_branch.as_ref().ok_or("human")?.principal_id.clone();
    let agent_id = agent.client.device_branch.as_ref().ok_or("agent")?.principal_id.clone();
    for (local, remote) in [(human, agent), (agent, human)] {
        let device = remote.client.device_branch.as_ref().ok_or("device")?;
        local.client.account_db()?.persist_client_record("device",&device.device_id,&json!({"principal_id":device.principal_id,"signing_public_key":ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes())}))?;
        local.client.account_db()?.persist_client_record(
            "conversation",
            conversation,
            &json!({"kind":"direct","participants":[human_id,agent_id]}),
        )?;
    }
    let bodies = [
        TaskEventBody::Start(TaskStart {
            task_id: id.into(),
            conversation_id: conversation.into(),
            requester: human_id.clone(),
            assignee: agent_id.clone(),
            text: "Inspect".into(),
            constraints: None,
        }),
        TaskEventBody::Update(TaskUpdate {
            task_id: id.into(),
            version: 2,
            state: TaskStatus::NeedsMe,
            steps: vec![TaskStep {
                id: "step".into(),
                title: "Run".into(),
                state: TaskStatus::NeedsMe,
                needs_me: Some(NeedsMe::Approval { grant_id: grant.into() }),
            }],
            result_ref: None,
            result_summary: None,
        }),
    ];
    for (index, body) in bodies.into_iter().enumerate() {
        let actor = if index == 0 { human } else { agent };
        let d = actor.client.device_branch.as_ref().ok_or("device")?;
        let c = actor.client.sign_task_event(
            TaskEvent::new(conversation.into(), body, sdk_device_signed_fields(&d.device_id, ""))?,
            format!("{id}:{index}"),
            None,
        )?;
        for local in [human, agent] {
            assert!(
                local
                    .client
                    .project_task_message(
                        &Delivery {
                            conversation,
                            message: &c.message_id,
                            principal: &c.principal_id,
                            device: &c.device_id,
                            at: now_unix_timestamp()
                        },
                        &c.bytes()?
                    )?
                    .ok_or("task")?
                    .accepted
            );
        }
    }
    Ok(())
}
fn pending(agent: &mut LocalBusAccountState, id: &str, grant: &str) -> Case {
    insert_pending(agent, id, grant)?;
    queue_requests(agent)?;
    Ok(())
}
fn insert_pending(agent: &mut LocalBusAccountState, id: &str, grant: &str) -> Case {
    let arguments = json!({"command":"echo approved","numeric_limit":1});
    let hash = ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::MCP_GRANT,
        &ramflux_protocol::canonical_json_bytes(&arguments)?,
    );
    agent.mcp_pending_approvals.insert(id.into(),LocalMcpApprovalRecord {approval_id:id.into(),server_id:"shell".into(),tool_name:"run".into(),capability:McpCapability::RunShell,risk_level:RiskLevel::High,tool_scope:None,confirmation_mode:"remote_app".into(),expires_at:now_unix_timestamp()+300,status:"pending".into(),details:json!({"requested_grant_id":grant,"arguments":arguments,"arguments_hash":hash,"single_use":true,"full_delegation":false})});
    Ok(())
}
fn request_job(agent: &LocalBusAccountState, task: &str) -> Case<Job> {
    agent
        .client
        .account_db()?
        .task_record_page::<Job>("task/approval_out/", "task/approval_out/", 101)?
        .into_iter()
        .find(|(_, j)| j.packet.request().binding.task_id == task)
        .map(|(_, j)| j)
        .ok_or_else(|| "request job missing".into())
}
fn decide(human: &LocalBusAccountState, packet: &Packet, approved: bool) -> Case<Job> {
    human.client.accept_task_approval(packet)?;
    let id = packet.id()?;
    human.client.decide_task_approval(&format!("task_approval_{id}"), approved)?;
    human
        .client
        .account_db()?
        .load_actor_state(&key("approval_decision_out", &id))?
        .ok_or_else(|| "decision missing".into())
}

#[test]
fn r5_canonically_identical_decisions_apply_the_executors_original_request_and_do_not_wedge_other_grants()
-> Case {
    let (root, mut agent, human) = pair("canonical-task-decision")?;
    open_named(&human, &agent, "alias", "grant-alias")?;
    pending(&mut agent, "alias", "grant-alias")?;
    let request = request_job(&agent, "alias")?;
    let decision = decide(&human, &request.packet, false)?;
    let mut payload = decision.packet.payload.clone();
    if let Payload::Decision { request, .. } = &mut payload {
        request.approval.details["arguments"]["numeric_limit"] = json!(1.0);
    }
    let alias = human.client.sign_task_approval(payload)?;
    assert_eq!(alias.id()?, decision.packet.id()?);
    assert_ne!(serde_json::to_vec(alias.request())?, serde_json::to_vec(request.packet.request())?);
    agent.client.accept_task_approval(&alias)?;
    apply_decisions(&mut agent)?;
    let denial: Value =
        agent.client.account_db()?.load_actor_state("mcp/denied/alias")?.ok_or("denial")?;
    assert!(
        denial["details"]["arguments"]["numeric_limit"].is_i64(),
        "apply the executor's original typed request"
    );
    open_named(&human, &agent, "genuine", "grant-genuine")?;
    pending(&mut agent, "genuine", "grant-genuine")?;
    let job = request_job(&agent, "genuine")?;
    let decision = decide(&human, &job.packet, true)?;
    agent.client.accept_task_approval(&decision.packet)?;
    apply_decisions(&mut agent)?;
    assert!(agent.mcp_grants.contains_key("grant-genuine"));
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn r5_a_bad_legacy_decision_cannot_skip_cleanup_or_new_request_admission() -> Case {
    let (root, mut agent, human) = pair("isolated-bad-approval")?;
    open_named(&human, &agent, "task", "grant")?;
    let storage = key("approval_decision_in", "bad");
    agent
        .client
        .account_db()?
        .persist_actor_state(&storage, &json!({"invalid_legacy_row":true}))?;
    agent
        .client
        .account_db()?
        .persist_actor_state(&key("approval_applied", "expired"), &json!({"expires_at":1}))?;
    insert_pending(&mut agent, "new-approval", "grant")?;
    drive(&mut agent).await?;
    assert!(!agent.client.account_db()?.actor_state_exists(&storage)?);
    assert!(!agent.client.account_db()?.actor_state_exists(&key("approval_applied", "expired"))?);
    assert!(agent.client.account_db()?.task_state_usage("task/approval_source/")?.0 > 0);
    assert!(agent.client.account_db()?.task_state_usage("task/approval_rejected/")?.0 > 0);
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn r5_exhausted_decision_delivery_is_visible_as_failed_and_attended_retry_reuses_the_signature()
-> Case {
    let (root, mut agent, mut human) = pair("approval-delivery-retry")?;
    open_named(&human, &agent, "task", "grant")?;
    pending(&mut agent, "approval", "grant")?;
    let request = request_job(&agent, "task")?;
    let mut job = decide(&human, &request.packet, true)?;
    let id = job.packet.id()?;
    let storage = key("approval_decision_out", &id);
    let bytes = job.packet.bytes()?;
    job.attempts = 7;
    job.next_at = 0;
    human.client.account_db()?.persist_actor_state(&storage, &job)?;
    drive(&mut human).await?;
    let row = list(&human)?
        .into_iter()
        .find(|v| v["approval_id"] == format!("task_approval_{id}"))
        .ok_or("decision delivery not visible")?;
    assert_eq!(row["delivery_state"], "failed");
    assert_eq!(row["reason_code"], "retry_exhausted");
    let result = human.client.decide_task_approval(&format!("task_approval_{id}"), true)?;
    assert_eq!(result["delivery_state"], "pending");
    let retry: Job = human.client.account_db()?.load_actor_state(&storage)?.ok_or("retry job")?;
    assert_eq!(retry.attempts, 0);
    assert_eq!(retry.packet.bytes()?, bytes);
    assert!(human.client.decide_task_approval(&format!("task_approval_{id}"), false).is_err());
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn r5_more_than_sixty_four_honest_approvals_apply_within_one_day_without_retaining_full_decisions()
-> Case {
    let (root, mut agent, human) = pair("approval-throughput")?;
    for n in 0..65 {
        let task = format!("task-{n}");
        let grant = format!("grant-{n}");
        let approval = format!("approval-{n}");
        // Model successive minute windows within one day, preserving production rate limits.
        for local in [&human, &agent] {
            let db = local.client.account_db()?;
            for principal in ["human", "agent"] {
                for scope in ["account", "principal", "cancel"] {
                    let storage = key("rate", &format!("{scope}:{principal}"));
                    if let Some(mut row) = db.load_actor_state::<Value>(&storage)? {
                        row["start"] = json!(now_unix_timestamp() - 61);
                        db.persist_actor_state(&storage, &row)?;
                    }
                }
            }
        }
        open_named(&human, &agent, &task, &grant)?;
        pending(&mut agent, &approval, &grant)?;
        let request = request_job(&agent, &task)?;
        let decision = decide(&human, &request.packet, true)?;
        agent.client.accept_task_approval(&decision.packet)?;
        apply_decisions(&mut agent)?;
        assert!(agent.mcp_grants.contains_key(&grant), "approval {n} was not applied");
        // Model transport ACK separately; only the production application retires decision state.
        for (account, namespace) in [(&human, "approval_decision_out"), (&agent, "approval_out")] {
            account
                .client
                .account_db()?
                .delete_task_state(&key(namespace, &decision.packet.id()?))?;
        }
        let device = human.client.device_branch.as_ref().ok_or("device")?;
        let complete = human.client.sign_task_event(
            TaskEvent::new(
                "thread".into(),
                TaskEventBody::Cancel(TaskCancel { task_id: task.clone(), base_revision: 2 }),
                sdk_device_signed_fields(&device.device_id, ""),
            )?,
            format!("{task}:done"),
            None,
        )?;
        for local in [&human, &agent] {
            let result = local
                .client
                .project_task_message(
                    &Delivery {
                        conversation: "thread",
                        message: &complete.message_id,
                        principal: &complete.principal_id,
                        device: &complete.device_id,
                        at: now_unix_timestamp(),
                    },
                    &complete.bytes()?,
                )?
                .ok_or("completion")?;
            assert!(result.accepted, "completion {n} rejected");
            // Model the independent own-device worker draining its per-task forward job.
            local
                .client
                .account_db()?
                .delete_task_state(&crate::client::task::scoped("forward", "thread", &task)?)?;
        }
    }
    assert_eq!(agent.mcp_grants.len(), 65);
    assert_eq!(agent.client.account_db()?.task_state_usage("task/approval_decision_in/")?.0, 0);
    assert_eq!(agent.client.account_db()?.task_state_usage("task/approval_source/")?.0, 0);
    assert!(agent.client.account_db()?.task_state_usage("task/approval_receipt/")?.0 <= 64);
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn r5_an_applied_grant_keeps_the_executors_receiver_deadline_without_rewriting_its_signature()
-> Case {
    let (root, mut agent, human) = pair("approval-effective-expiry")?;
    open_named(&human, &agent, "task", "grant")?;
    insert_pending(&mut agent, "approval", "grant")?;
    let now = now_unix_timestamp();
    agent.mcp_pending_approvals.get_mut("approval").ok_or("approval")?.expires_at =
        now + 10 * 365 * 86400;
    queue_requests(&mut agent)?;
    let request = request_job(&agent, "task")?;
    let decision = decide(&human, &request.packet, true)?;
    agent.client.accept_task_approval(&decision.packet)?;
    apply_decisions(&mut agent)?;
    let grant = agent.mcp_grants.get("grant").ok_or("installed grant")?;
    assert!(grant.state.expires_at <= now + 86401);
    assert_eq!(grant.signing_body.expires_at, request.packet.request().grant_body.expires_at);
    let stored: LocalMcpGrantRecord =
        agent.client.account_db()?.load_mcp_grant("grant")?.ok_or("persisted grant")?;
    assert_eq!(stored.state.expires_at, grant.state.expires_at);
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[path = "task_approval_r6.rs"]
mod r6;
