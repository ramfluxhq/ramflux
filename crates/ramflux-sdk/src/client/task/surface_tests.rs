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
        typed: None,
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
        posted_at: None,
        updated_at: None,
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
async fn native_fixture()
-> Result<(Fixture, std::sync::Arc<crate::custody::tests::TestVault>), Box<dyn std::error::Error>> {
    let mut f = Fixture::new()?;
    let (human, agent, vault) = crate::client::surface::test_support::owned_pair_with_vault(
        &f.root.join("surface-native"),
        "human",
        "agent",
    )
    .await?;
    f.human = human;
    f.agent = agent;
    for client in [&f.human, &f.agent] {
        client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"direct","participants":["human","agent"]}),
        )?;
    }
    create_form(&f)?;
    Ok((f, vault))
}
async fn exercise(input: bool, read_only: bool) -> TestResult {
    exercise_with_restart(input, read_only, false).await
}
async fn exercise_with_restart(input: bool, read_only: bool, restart: bool) -> TestResult {
    let (mut f, vault) = native_fixture().await?;
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
            result_summary: None,
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
    let action = answer_action(&f.human, &f.agent)?;
    if restart {
        assert!(f.human.stage_surface_outgoing(&action, None)?.accepted);
    }
    assert!(surface_project(&f.agent, &action)?.accepted);
    let view = f.agent.surface_get("form", 0, None)?;
    let decision_id = view["actions"][0]["action_receipt_id"].as_str().ok_or("decision id")?;
    assert_eq!(view["action_receipt_id"], decision_id);
    assert_eq!(view["actions"][0]["receipt_verified"], true);
    check_receipt_roundtrip(&f.agent, &action, decision_id)?;
    if read_only {
        mark_read_only(&f.agent, &action, decision_id)?;
    }

    let binding = if restart {
        drop(f.human.active_account_db.take());
        f.human.unlock_account("human", b"surface-test-secret")?;
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            f.human.initialize_born_v3_branch("human-device", vault.clone()),
        )
        .await??;
        let recovered = f.human.surface_get("form", 0, None)?;
        assert_eq!(recovered["actions"][0]["receipt_verified"], false);
        assert_eq!(recovered["actions"][0]["actionable"], false);
        assert_eq!(recovered["actions"][0]["action_receipt_id"], decision_id);
        f.human.surface_get("form", 0, None)?["actions"][0]["task_binding"].clone()
    } else {
        json!({"task_id":"task","step_id":"step"})
    };
    let resolution = TaskResolve {
        task_id: binding["task_id"].as_str().ok_or("receipt task id")?.into(),
        base_revision: 2,
        step_id: binding["step_id"].as_str().ok_or("receipt step id")?.into(),
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
    let outcome = project(&f.agent, &intent)?;
    assert!(
        outcome.accepted,
        "typed Task creator receipt refused: {:?} {:?}",
        outcome.reason_code, outcome.reject
    );
    let history = f.agent.task_history("thread", "task")?;
    let cert =
        history.events.last().and_then(|e| e.decision_certificate.as_ref()).ok_or("certificate")?;
    let wire = ramflux_protocol::decode_base64url(&cert.encoded()?)?;
    let private_value = b"PRIVATE_TASK_FORM_VALUE";
    assert!(
        !wire.windows(private_value.len()).any(|window| window == private_value),
        "typed creator receipt must not export private form values"
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
fn answer_action(
    requester: &RamfluxClient,
    author: &RamfluxClient,
) -> Result<SurfaceCarrier, Box<dyn std::error::Error>> {
    let view = author.surface_get("form", 0, None)?;
    let values = json!({"decision":"resume","private_input":"PRIVATE_TASK_FORM_VALUE"});
    let mut frame = ramflux_protocol::ActionFrame {
        schema: ramflux_protocol::ACTION_SCHEMA.into(),
        conversation_id: "thread".into(),
        surface_version: 1,
        surface_hash: view["surface_hash"].as_str().ok_or("surface hash")?.into(),
        source_instance: Vec::new(),
        task_binding: Some(ramflux_protocol::TaskBinding {
            task_id: "task".into(),
            step_id: "step".into(),
        }),
        args_hash: String::new(),
        a2ui: ramflux_protocol::ActionMessage {
            version: "1.0".into(),
            action: ramflux_protocol::Action {
                name: "answer".into(),
                surface_id: "form".into(),
                source_component_id: "answer".into(),
                timestamp: "2026-11-14T00:00:00Z".into(),
                context: values.as_object().ok_or("context")?.clone(),
                user_message: None,
                metadata: None,
            },
        },
    };
    frame.args_hash = frame.arguments_hash()?;
    let action = frame.wire_bytes()?;
    surface_carrier(requester, PayloadKind::Action, "answer-form", &action).map_err(Into::into)
}
#[tokio::test]
async fn choice_resolution_uses_a_creator_validated_surface_action_without_exporting_values()
-> TestResult {
    exercise(false, false).await
}
#[tokio::test]
async fn input_resolution_uses_a_creator_validated_surface_action_without_exporting_values()
-> TestResult {
    exercise(true, false).await
}

#[tokio::test]
async fn a_read_only_creator_receipt_confirms_the_task_without_executing_a_surface_action()
-> TestResult {
    exercise(true, true).await
}

fn mark_read_only(
    client: &RamfluxClient,
    action: &SurfaceCarrier,
    decision_id: &str,
) -> Result<(), SdkError> {
    let key = format!(
        "{}/{}",
        crate::client::surface::key("actions", &action.surface_reference()?),
        decision_id
    );
    let mut row = client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&key)?
        .ok_or_else(|| invalid("stored action missing"))?;
    row["actionable"] = json!(false);
    client.account_db()?.persist_actor_state(&key, &row)?;
    Ok(())
}

#[tokio::test]
async fn r5_a_retained_signed_action_names_the_task_and_step_after_requester_restart_before_creator_receipt_arrival()
-> TestResult {
    exercise_with_restart(true, false, true).await
}

fn create_form(f: &Fixture) -> TestResult {
    let mut snapshot =
        crate::client::surface::test_support::text_snapshot("form", "Decision needed", "Choose");
    snapshot.components = vec![
        json!({"id":"root","component":"Card","child":"form"}),
        json!({"id":"form","component":"Column","children":["input","answer"]}),
        json!({"id":"input","component":"TextField","label":"Private input","value":{"@path":"/private_input"}}),
        json!({"id":"label","component":"Text","text":"Answer"}),
        json!({"id":"answer","component":"Button","child":"label","action":{"event":{"name":"answer","context":{"decision":"resume","private_input":{"@path":"/private_input"}}}}}),
    ];
    snapshot.data_model = json!({"private_input":""});
    let create =
        crate::client::surface::test_support::create_frame("thread", &snapshot)?.wire_bytes()?;
    let c = surface_carrier(&f.agent, PayloadKind::Event, "create-form", &create)?;
    for local in [&f.human, &f.agent] {
        assert!(surface_project(local, &c)?.accepted);
    }
    Ok(())
}

fn check_receipt_roundtrip(
    client: &RamfluxClient,
    action: &SurfaceCarrier,
    id: &str,
) -> TestResult {
    let encoded = client.task_surface_receipt("thread", "form", "agent", id)?;
    let reference = action.surface_reference()?;
    let key = format!("{}/{id}", crate::client::surface::key("actions", &reference));
    let mut row =
        client.account_db()?.load_actor_state::<serde_json::Value>(&key)?.ok_or("receipt row")?;
    let original: SurfaceCarrier = serde_json::from_value(row["attestation"].clone())?;
    let decoded = SurfaceCarrier::decode(&ramflux_protocol::decode_base64url(&encoded)?)?
        .ok_or("receipt decode")?;
    assert_eq!(
        original.to_generated()?,
        decoded.to_generated()?,
        "Surface receipt must retain its exact typed signing fields"
    );
    client.verify_surface_carrier(&decoded, "agent", &decoded.sender_device_id)?;
    let explicit = explicit_zero_surface_timestamp(client, decoded.to_generated()?)?;
    row["attestation"] = serde_json::to_value(explicit)?;
    client.account_db()?.persist_actor_state(&key, &row)?;
    Ok(())
}

fn explicit_zero_surface_timestamp(
    client: &RamfluxClient,
    mut value: ramflux_protocol::message::SurfaceCarrier,
) -> Result<SurfaceCarrier, Box<dyn std::error::Error>> {
    use prost::Message as _;
    // Explicit presence of a zero scalar must survive native storage and re-encoding.
    // The v3 proof is a single event; there is no separate checkpoint/content carrier.
    value.posted_at = Some(0);
    value.signature.clear();
    let signer = client.device_branch.as_ref().ok_or("creator device")?;
    value.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &crate::client::task::generated::typed_transcript(
            "SurfaceCarrier",
            &value.encode_to_vec(),
        )?,
        signer,
    );
    let decoded =
        SurfaceCarrier::decode(&value.encode_to_vec())?.ok_or("explicit typed receipt")?;
    let mut restored: SurfaceCarrier = serde_json::from_value(serde_json::to_value(&decoded)?)?;
    assert_eq!(
        restored.to_generated()?,
        value,
        "reload must preserve explicitly present empty protobuf fields and their signature"
    );
    client.verify_surface_carrier(&restored, "agent", &restored.sender_device_id)?;
    restored.message_id.push_str("-tampered-native-view");
    assert!(
        client.verify_surface_carrier(&restored, "agent", &restored.sender_device_id).is_err(),
        "retained typed bytes cannot authenticate a changed native projection"
    );
    Ok(decoded)
}
