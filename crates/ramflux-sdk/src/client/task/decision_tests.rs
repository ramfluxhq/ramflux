// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real signed grant evidence, durable intervention reservation, and receipt authority.
use super::*;
use crate::{LocalMcpApprovalRecord, LocalMcpGrantRecord, LocalMcpGrantSigningBody};
use ramflux_protocol::{McpCapability, NeedsMe, RiskLevel, TaskDecision, TaskResolve};
use ramflux_storage::McpGrantWrite;
fn open(f: &Fixture, id: &str) -> Result<(), SdkError> {
    let start = sign(&f.human, "thread", &format!("start-{id}"), start(id, "thread"))?;
    let needs = sign(
        &f.agent,
        "thread",
        &format!("needs-{id}"),
        TaskEventBody::Update(TaskUpdate {
            task_id: id.into(),
            version: 2,
            state: TaskStatus::NeedsMe,
            steps: vec![TaskStep {
                id: "step".into(),
                title: "Run command".into(),
                state: TaskStatus::NeedsMe,
                needs_me: Some(NeedsMe::Approval { grant_id: "grant".into() }),
            }],
            result_ref: None,
        }),
    )?;
    for client in [&f.human, &f.agent] {
        assert!(project(client, &start)?.accepted);
        assert!(project(client, &needs)?.accepted);
    }
    Ok(())
}
fn resolution(id: &str, decision: TaskDecision) -> TaskResolve {
    TaskResolve {
        task_id: id.into(),
        base_revision: 2,
        step_id: "step".into(),
        target: NeedsMe::Approval { grant_id: "grant".into() },
        decision_id: "approval".into(),
        decision,
    }
}
fn grant(f: &Fixture) -> Result<LocalMcpGrantRecord, SdkError> {
    let d = f.human.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let body = LocalMcpGrantSigningBody {
        approval_id: "approval".into(),
        grant_id: "grant".into(),
        server_id: "server".into(),
        tool_name: "run".into(),
        tool_scope: None,
        capability: McpCapability::RunShell,
        registry_hash: "registry".into(),
        tool_manifest_set_hash: "manifest".into(),
        full_delegation: false,
        single_use: true,
        arguments_hash: Some("arguments-hash".into()),
        expires_at: crate::time::now_unix_timestamp() + 300,
    };
    Ok(LocalMcpGrantRecord {
        grant_id: "grant".into(),
        state: ramflux_sync::McpGrantState {
            server_id: body.server_id.clone(),
            tool_name: body.tool_name.clone(),
            tool_scope: None,
            registry_hash: body.registry_hash.clone(),
            tool_manifest_set_hash: body.tool_manifest_set_hash.clone(),
            full_delegation: false,
            allowed_capabilities: std::collections::BTreeSet::from([McpCapability::RunShell]),
            revoked: false,
            expires_at: body.expires_at,
        },
        signed_by_device_id: d.device_id.clone(),
        signer_public_key: ramflux_protocol::encode_base64url(
            d.signing_key.verifying_key().to_bytes(),
        ),
        signature: ramflux_crypto::sign_with_device_branch(d, &body)?,
        signing_body: body,
        confirmation_mode: "remote_app".into(),
    })
}
fn store(f: &Fixture, g: &LocalMcpGrantRecord) -> Result<(), SdkError> {
    f.agent.account_db()?.upsert_mcp_grant(&McpGrantWrite {
        grant_id: &g.grant_id,
        target_ai_device_id: &g.state.server_id,
        source_app_device_id: &g.signed_by_device_id,
        capability: "run_shell",
        risk_level: "high",
        registry_hash: &g.state.registry_hash,
        tool_manifest_set_hash: &g.state.tool_manifest_set_hash,
        expires_at: g.state.expires_at,
        signature: &g.signature,
        created_at: crate::time::now_unix_timestamp(),
        revoked: g.state.revoked,
        grant: g,
    })?;
    Ok(())
}
fn signed_resolution(
    client: &RamfluxClient,
    resolution: TaskResolve,
    proof: &decision::DecisionProof,
) -> Result<carrier::Carrier, SdkError> {
    let d = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let event = TaskEvent::new(
        "thread".into(),
        TaskEventBody::Resolve(resolution),
        crate::prelude::sdk_device_signed_fields(&d.device_id, ""),
    )
    .map_err(|e| invalid(e.to_string()))?;
    client.sign_task_event(event, "resolve".into(), Some(proof.encoded()?))
}
#[test]
fn approval_resolution_requires_the_existing_human_signed_grant_and_never_authorizes_an_agent_self_resolution()
-> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let g = grant(&f)?;
    let res = resolution("task", TaskDecision::Resume);
    assert!(
        f.agent
            .witness_task_decision(
                "thread",
                res.clone(),
                decision::Evidence::Grant { record: Box::new(g.clone()) }
            )
            .is_err()
    );
    store(&f, &g)?;
    let proof = f.agent.witness_task_decision(
        "thread",
        res.clone(),
        decision::Evidence::Grant { record: Box::new(g) },
    )?;
    assert!(!project(&f.agent, &signed_resolution(&f.agent, res.clone(), &proof)?)?.accepted);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?["version"], 2);
    let human = signed_resolution(&f.human, res, &proof)?;
    assert!(project(&f.agent, &human)?.accepted);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?["state"], "running");
    assert!(project(&f.agent, &human)?.accepted);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?["version"], 3);
    Ok(())
}
#[test]
fn one_grant_decision_is_reserved_for_one_task_before_any_human_device_can_resolve_it() -> TestResult
{
    let f = Fixture::new()?;
    open(&f, "one")?;
    open(&f, "two")?;
    let g = grant(&f)?;
    store(&f, &g)?;
    let proof = f.agent.witness_task_decision(
        "thread",
        resolution("one", TaskDecision::Resume),
        decision::Evidence::Grant { record: Box::new(g.clone()) },
    )?;
    let retry = f.agent.witness_task_decision(
        "thread",
        resolution("one", TaskDecision::Resume),
        decision::Evidence::Grant { record: Box::new(g.clone()) },
    )?;
    assert_eq!(proof.encoded()?, retry.encoded()?);
    assert!(
        f.agent
            .witness_task_decision(
                "thread",
                resolution("two", TaskDecision::Resume),
                decision::Evidence::Grant { record: Box::new(g) }
            )
            .is_err()
    );
    assert!(
        !project(
            &f.agent,
            &signed_resolution(&f.human, resolution("two", TaskDecision::Resume), &proof)?
        )?
        .accepted
    );
    assert_eq!(f.agent.task_get(Some("thread"), "two")?["version"], 2);
    Ok(())
}
#[test]
fn a_forged_grant_key_or_changed_arguments_cannot_become_a_task_decision() -> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let mut g = grant(&f)?;
    store(&f, &g)?;
    g.signing_body.arguments_hash = Some("changed".into());
    assert!(
        f.agent
            .witness_task_decision(
                "thread",
                resolution("task", TaskDecision::Resume),
                decision::Evidence::Grant { record: Box::new(g) }
            )
            .is_err()
    );
    let mut g = grant(&f)?;
    let d = f.agent.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    g.signed_by_device_id = d.device_id.clone();
    g.signer_public_key =
        ramflux_protocol::encode_base64url(d.signing_key.verifying_key().to_bytes());
    g.signature = ramflux_crypto::sign_with_device_branch(d, &g.signing_body)?;
    store(&f, &g)?;
    assert!(
        f.agent
            .witness_task_decision(
                "thread",
                resolution("task", TaskDecision::Resume),
                decision::Evidence::Grant { record: Box::new(g) }
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn a_verified_existing_mcp_denial_resolves_the_task_without_creating_any_grant() -> TestResult {
    let f = Fixture::new()?;
    open(&f, "task")?;
    let record = LocalMcpApprovalRecord {
        approval_id: "approval".into(),
        server_id: "server".into(),
        tool_name: "run".into(),
        capability: McpCapability::RunShell,
        risk_level: RiskLevel::High,
        tool_scope: None,
        confirmation_mode: "remote_app".into(),
        expires_at: crate::time::now_unix_timestamp() + 300,
        status: "denied".into(),
        details: json!({"requested_grant_id":"grant","single_use":true,"arguments_hash":"args"}),
    };
    let res = resolution("task", TaskDecision::Deny);
    assert!(
        f.agent
            .witness_task_decision(
                "thread",
                res.clone(),
                decision::Evidence::Denied { record: Box::new(record.clone()) }
            )
            .is_err()
    );
    f.agent.account_db()?.persist_actor_state("mcp/denied/approval", &record)?;
    let proof = f.agent.witness_task_decision(
        "thread",
        res.clone(),
        decision::Evidence::Denied { record: Box::new(record) },
    )?;
    assert!(project(&f.agent, &signed_resolution(&f.human, res, &proof)?)?.accepted);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?["state"], "failed");
    assert!(f.agent.account_db()?.load_mcp_grant::<LocalMcpGrantRecord>("grant")?.is_none());
    Ok(())
}
