// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Task decisions use actual validated surface actions; form values stay at the creator.
use super::*;
use crate::client::surface::{Carrier as SurfaceCarrier, PayloadKind, SurfaceSender};
use ramflux_protocol::{NeedsMe, TaskDecision, TaskResolve};
fn surface_carrier(
    sender: &RamfluxClient,
    kind: PayloadKind,
    message: &str,
    wire: &[u8],
) -> Result<SurfaceCarrier, SdkError> {
    let device = sender.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    sender.sign_surface_carrier(SurfaceCarrier {
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        payload_kind: kind,
        conversation_id: "thread".into(),
        surface_id: "form".into(),
        message_id: message.into(),
        sender_principal_id: device.principal_id.clone(),
        sender_device_id: device.device_id.clone(),
        author_principal_id: "agent".into(),
        wire_base64: ramflux_protocol::encode_base64url(wire),
        signature: String::new(),
        snapshot: None,
    })
}
fn surface_project(
    client: &RamfluxClient,
    c: &SurfaceCarrier,
) -> Result<crate::client::surface::Outcome, SdkError> {
    client
        .project_surface_message(
            "thread",
            &c.message_id,
            SurfaceSender {
                principal: &c.sender_principal_id,
                device: &c.sender_device_id,
                envelope_id: &c.message_id,
                expires_at: None,
                group_epoch: None,
            },
            &c.bytes()?,
            false,
        )?
        .ok_or_else(|| invalid("surface absent"))
}
fn exercise(input: bool, read_only: bool) -> TestResult {
    let f = Fixture::new()?;
    let command = ramflux_protocol::A2uiConversationCommand::CreateSurface(
        ramflux_protocol::CreateSurfaceCommand {
            surface_id: "form".into(),
            surface_type: ramflux_protocol::SurfaceType::StatusPanel,
            catalog: "basic".into(),
            catalog_version: "1".into(),
            fallback_text: "Decision needed".into(),
            fallback_markdown: None,
            components: vec![json!({"id":"answer","text":"Choose"})],
            data_model: serde_json::Map::default(),
            allowed_actions: vec![json!({"name":"answer"})],
        },
    );
    let create = serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.conversation.v2","conversationId":"thread","version":1,"command":command}),
    )?;
    let c = surface_carrier(&f.agent, PayloadKind::Event, "create-form", &create)?;
    for local in [&f.human, &f.agent] {
        assert!(surface_project(local, &c)?.accepted);
    }
    let start = sign(&f.human, "thread", "start", start("task", "thread"))?;
    let target = if input {
        NeedsMe::Input { surface_id: "form".into() }
    } else {
        NeedsMe::Choice { surface_id: "form".into() }
    };
    let update = sign(
        &f.agent,
        "thread",
        "needs",
        TaskEventBody::Update(TaskUpdate {
            task_id: "task".into(),
            version: 2,
            state: TaskStatus::NeedsMe,
            steps: vec![TaskStep {
                id: "step".into(),
                title: "Answer".into(),
                state: TaskStatus::NeedsMe,
                needs_me: Some(target.clone()),
            }],
            result_ref: None,
        }),
    )?;
    for local in [&f.human, &f.agent] {
        assert!(project(local, &start)?.accepted);
        assert!(project(local, &update)?.accepted);
    }
    let view = f.agent.surface_get("form", 0, None)?;
    let values = json!({"decision":"resume","private_input":"PRIVATE_TASK_FORM_VALUE"});
    let action = serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.action.v2","conversationId":"thread","surfaceId":"form","version":1,"surfaceHash":view["surface_hash"],"actionId":"answer","values":values,"argsHash":ramflux_protocol::surface_args_hash(&values)?}),
    )?;
    let action = surface_carrier(&f.human, PayloadKind::Action, "answer-form", &action)?;
    assert!(surface_project(&f.agent, &action)?.accepted);
    let view = f.agent.surface_get("form", 0, None)?;
    let decision_id = view["actions"][0]["id"].as_str().ok_or("decision id")?;
    if read_only {
        let rows = f.agent.account_db()?.surface_history_page::<serde_json::Value>(
            "surface/actions/",
            "surface/actions/",
            100,
        )?;
        let (key, mut row) =
            rows.into_iter().find(|(_, row)| row["id"] == decision_id).ok_or("stored action")?;
        row["actionable"] = json!(false);
        f.agent.account_db()?.persist_actor_state(&key, &row)?;
    }

    let resolution = TaskResolve {
        task_id: "task".into(),
        base_revision: 2,
        step_id: "step".into(),
        target,
        decision_id: decision_id.into(),
        decision: TaskDecision::Resume,
    };
    let mut wrong = resolution.clone();
    wrong.decision = TaskDecision::Deny;
    let rejected = sign(&f.human, "thread", "wrong-outcome", TaskEventBody::Resolve(wrong))?;
    assert!(!project(&f.agent, &rejected)?.accepted);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?["version"], 2);
    let intent =
        sign(&f.human, "thread", "resolve-form", TaskEventBody::Resolve(resolution.clone()))?;
    assert!(project(&f.human, &intent)?.pending);
    assert!(project(&f.agent, &intent)?.accepted);
    let history = f.agent.task_history("thread", "task")?;
    let cert =
        history.events.last().and_then(|e| e.decision_certificate.as_ref()).ok_or("certificate")?;
    assert!(
        !String::from_utf8(ramflux_protocol::decode_base64url(&cert.encoded()?)?)?
            .contains("PRIVATE_TASK_FORM_VALUE")
    );
    f.human.save_task_commit_certificate(&intent, cert)?;
    assert_eq!(f.human.retry_pending_tasks(crate::time::now_unix_timestamp())?, 1);
    assert_eq!(f.human.task_get(Some("thread"), "task")?["version"], 3);
    let replay = sign(&f.human, "thread", "replay-form", TaskEventBody::Resolve(resolution))?;
    assert!(!project(&f.agent, &replay)?.accepted);
    if read_only {
        assert_eq!(f.agent.surface_get("form", 0, None)?["actions"][0]["actionable"], false);
    }
    Ok(())
}
#[test]
fn choice_resolution_uses_a_creator_validated_surface_action_without_exporting_values() -> TestResult
{
    exercise(false, false)
}
#[test]
fn input_resolution_uses_a_creator_validated_surface_action_without_exporting_values() -> TestResult
{
    exercise(true, false)
}

#[test]
fn a_read_only_creator_receipt_confirms_the_task_without_executing_a_surface_action() -> TestResult
{
    exercise(true, true)
}
