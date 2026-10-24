// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
mod task_support;
use ramflux_protocol::*;
use serde_json::{Value, json};
use task_support::*;
fn decode(value: &Value) -> std::result::Result<TaskEvent, TaskReject> {
    TaskEvent::from_wire_bytes(&serde_json::to_vec(value).map_err(ProtocolError::from)?)
}
fn changed(event: &TaskEvent, path: &str, value: Value) -> Result<TaskEvent> {
    let mut wire = serde_json::to_value(event)?;
    if path == "/ext" {
        wire["ext"] = value;
    } else {
        *wire.pointer_mut(path).ok_or("field")? = value;
    }
    Ok(decode(&wire)?)
}
#[test]
fn every_event_round_trips_and_rejects_unknown_fields_at_each_wire_layer() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    for event in [
        h.event(start())?,
        a.event(proposal())?,
        h.event(TaskEventBody::Accept(TaskAccept { task_id: "task".into(), version: 2 }))?,
        h.event(TaskEventBody::Decline(TaskDecline { task_id: "task".into(), version: 2 }))?,
        a.event(update(2, TaskStatus::NeedsMe, vec![blocked("s", approval())]))?,
        h.event(TaskEventBody::Cancel(TaskCancel { task_id: "task".into(), base_revision: 1 }))?,
        h.event(resolve(3, approval(), TaskDecision::Resume))?,
    ] {
        let wire = serde_json::to_value(&event)?;
        assert_eq!(decode(&wire)?, event);
        for path in ["", "/event", "/event/body"] {
            let mut bad = wire.clone();
            bad.pointer_mut(path)
                .and_then(Value::as_object_mut)
                .ok_or("object")?
                .insert("unknown".into(), json!(true));
            assert!(decode(&bad).is_err());
        }
        assert!(!event.fallback_text().is_empty());
    }
    let mut nested = serde_json::to_value(a.event(update(
        2,
        TaskStatus::NeedsMe,
        vec![blocked("s", approval())],
    ))?)?;
    nested["event"]["body"]["steps"][0]["unknown"] = json!(0);
    assert!(decode(&nested).is_err());
    Ok(())
}
#[test]
fn intervention_types_cannot_contain_zero_two_or_the_wrong_target() -> Result {
    for good in [
        json!({"kind":"approval","grant_id":"g"}),
        json!({"kind":"choice","surface_id":"s"}),
        json!({"kind":"input","surface_id":"s"}),
    ] {
        let v: NeedsMe = serde_json::from_value(good.clone())?;
        assert_eq!(serde_json::to_value(v)?, good);
    }
    for bad in [
        json!({"kind":"approval"}),
        json!({"kind":"approval","surface_id":"s"}),
        json!({"kind":"approval","grant_id":"g","surface_id":"s"}),
        json!({"kind":"choice","grant_id":"g","surface_id":"s"}),
        json!({"kind":"input","grant_id":"g","surface_id":"s"}),
        json!({"kind":"other","surface_id":"s"}),
    ] {
        assert!(serde_json::from_value::<NeedsMe>(bad).is_err());
    }
    Ok(())
}
#[test]
fn schema_domain_and_critical_extensions_are_checked_before_application() -> Result {
    let event = Actor::human().event(start())?;
    let wire = serde_json::to_value(event)?;
    for (path, value) in [
        ("/schema", json!("other")),
        ("/version", json!(2)),
        ("/domain", json!(domain::MCP_GRANT)),
        ("/ext", json!({"critical.unknown":true})),
        ("/conversation_id", json!("elsewhere")),
    ] {
        let mut bad = wire.clone();
        if path == "/ext" {
            bad["ext"] = value;
        } else {
            *bad.pointer_mut(path).ok_or("field")? = value;
        }
        let error = decode(&bad).err().ok_or("expected reject")?;
        match path {
            "/schema" | "/version" => assert!(matches!(error, TaskReject::InvalidSchema)),
            "/domain" => assert!(matches!(error, TaskReject::InvalidDomain)),
            "/ext" => assert!(matches!(
                error,
                TaskReject::Protocol(ProtocolError::UnknownCriticalExtension(_))
            )),
            _ => assert!(matches!(error, TaskReject::ContextMismatch)),
        }
    }
    Ok(())
}
#[test]
fn signatures_bind_context_payload_extensions_and_the_pinned_signing_identity() -> Result {
    let a = Actor::agent();
    let h = Actor::human();
    let other = Actor::other();
    let valid = a.event(update(2, TaskStatus::Running, vec![]))?;
    valid.verify(&a.signer())?;
    for (path, value) in [
        ("/conversation_id", json!("other-chat")),
        ("/ext", json!({"label":"altered"})),
        ("/signature", json!("invalid")),
        ("/event/body/version", json!(3)),
    ] {
        assert!(matches!(
            changed(&valid, path, value)?.verify(&a.signer()),
            Err(TaskReject::InvalidSignature)
        ));
    }
    assert!(matches!(valid.verify(&other.signer()), Err(TaskReject::WrongSigner)));
    let forged = TaskSigner { signing_key_id: a.key_id, ..h.signer() };
    assert!(matches!(valid.verify(&forged), Err(TaskReject::InvalidSignature)));
    let empty = TaskSigner { principal_id: "", ..a.signer() };
    assert!(matches!(valid.verify(&empty), Err(TaskReject::WrongSigner)));
    assert!(matches!(
        changed(&valid, "/signing_key_id", json!("unbound"))?.verify(&a.signer()),
        Err(TaskReject::WrongSigner)
    ));
    Ok(())
}
#[test]
fn scalar_title_text_step_and_exact_canonical_byte_limits_are_enforced() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    let mut body = start();
    if let TaskEventBody::Start(v) = &mut body {
        v.text = "x".repeat(MAX_TASK_TEXT_CHARS);
    }
    h.event(body.clone())?.validate()?;
    if let TaskEventBody::Start(v) = &mut body {
        v.text.push('x');
    }
    assert!(matches!(h.event(body), Err(TaskReject::InvalidField("text"))));
    let mut body = proposal();
    if let TaskEventBody::Proposal(v) = &mut body {
        v.title = "🦀".repeat(MAX_TASK_TITLE_CHARS);
        v.steps =
            (0..MAX_TASK_STEPS).map(|i| step(&format!("s{i}"), TaskStatus::Proposed)).collect();
    }
    a.event(body.clone())?.validate()?;
    if let TaskEventBody::Proposal(v) = &mut body {
        v.title.push('x');
    }
    assert!(matches!(a.event(body), Err(TaskReject::InvalidField("title"))));
    assert!(matches!(
        a.event(update(
            2,
            TaskStatus::Running,
            (0..=MAX_TASK_STEPS).map(|i| step(&format!("s{i}"), TaskStatus::Running)).collect()
        )),
        Err(TaskReject::TooManySteps)
    ));
    let event = h.event(start())?;
    let mut wire = serde_json::to_value(&event)?;
    wire["ext"] = json!({"padding":""});
    let overhead = canonical_json_bytes(&wire)?.len();
    wire["ext"]["padding"] = json!("x".repeat(MAX_TASK_EVENT_BYTES - overhead));
    let bytes = canonical_json_bytes(&wire)?;
    assert_eq!(bytes.len(), MAX_TASK_EVENT_BYTES);
    decode(&wire)?.validate()?;
    wire["ext"]["padding"] = json!("x".repeat(MAX_TASK_EVENT_BYTES - overhead + 1));
    assert!(matches!(decode(&wire), Err(TaskReject::EventTooLarge)));
    Ok(())
}
#[test]
fn identifiers_optional_fields_and_intervention_consistency_have_typed_rejections() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    for (event, paths) in [
        (
            h.event(start())?,
            vec![
                "/conversation_id",
                "/signing_key_id",
                "/event/body/task_id",
                "/event/body/requester",
                "/event/body/assignee",
                "/event/body/text",
                "/event/body/constraints",
            ],
        ),
        (a.event(proposal())?, vec!["/event/body/proposer", "/event/body/assignee"]),
        (
            h.event(resolve(3, approval(), TaskDecision::Resume))?,
            vec!["/event/body/step_id", "/event/body/decision_id", "/event/body/target/grant_id"],
        ),
    ] {
        for path in paths {
            let mut wire = serde_json::to_value(&event)?;
            *wire.pointer_mut(path).ok_or("field")? = json!("");
            assert!(matches!(decode(&wire), Err(TaskReject::InvalidField(_))));
        }
    }
    let mut body = update(2, TaskStatus::Done, vec![]);
    if let TaskEventBody::Update(v) = &mut body {
        v.result_ref = Some(String::new());
    }
    assert!(matches!(a.event(body), Err(TaskReject::InvalidField("result_ref"))));
    for bad in [
        TaskStep { id: String::new(), ..step("s", TaskStatus::Running) },
        TaskStep { title: "x".repeat(257), ..step("s", TaskStatus::Running) },
        blocked("s", NeedsMe::Input { surface_id: String::new() }),
    ] {
        assert!(matches!(
            a.event(update(2, TaskStatus::Running, vec![bad])),
            Err(TaskReject::InvalidField(_))
        ));
    }
    assert!(matches!(
        a.event(update(
            2,
            TaskStatus::Running,
            vec![step("s", TaskStatus::Running), step("s", TaskStatus::Running)]
        )),
        Err(TaskReject::DuplicateStep)
    ));
    for bad in [
        step("s", TaskStatus::NeedsMe),
        TaskStep { needs_me: Some(approval()), ..step("s", TaskStatus::Running) },
    ] {
        assert!(matches!(
            a.event(update(2, TaskStatus::NeedsMe, vec![bad])),
            Err(TaskReject::NeedsMeMismatch)
        ));
    }
    assert!(matches!(
        a.event(update(
            2,
            TaskStatus::NeedsMe,
            vec![
                blocked("s", approval()),
                blocked("t", NeedsMe::Choice { surface_id: "surface".into() })
            ]
        )),
        Err(TaskReject::MultipleNeedsMe)
    ));
    let mut state = running()?;
    for body in [
        update(2, TaskStatus::NeedsMe, vec![]),
        update(2, TaskStatus::Running, vec![blocked("s", approval())]),
    ] {
        reject(&mut state, &a.event(body)?, &a.signer(), &TaskReject::NeedsMeMismatch)?;
    }
    Ok(())
}
#[test]
fn revisions_are_safe_json_integers_and_replay_keys_are_conversation_scoped() -> Result {
    let a = Actor::agent();
    for version in [0, MAX_TASK_VERSION + 1, u64::MAX] {
        assert!(matches!(
            a.event(update(version, TaskStatus::Running, vec![])),
            Err(TaskReject::InvalidVersion)
        ));
    }
    a.event(update(MAX_TASK_VERSION, TaskStatus::Running, vec![]))?.validate()?;
    let event = a.event(update(2, TaskStatus::Running, vec![]))?;
    let other = changed(&event, "/conversation_id", json!("other"))?;
    assert_ne!(event.replay_key(), other.replay_key());
    for version in [json!(-1), json!(1.5)] {
        let mut wire = serde_json::to_value(&event)?;
        wire["event"]["body"]["version"] = version;
        assert!(decode(&wire).is_err());
    }
    Ok(())
}
#[test]
fn fallback_is_plain_text_and_canonicalization_does_not_normalize_unicode() -> Result {
    let h = Actor::human();
    let mut body = start();
    if let TaskEventBody::Start(v) = &mut body {
        v.text = "\u{1b}[31mvisible".into();
    }
    assert!(matches!(h.event(body), Err(TaskReject::InvalidField("text"))));
    let composed = changed(&h.event(start())?, "/event/body/text", json!("é"))?;
    let decomposed = changed(&composed, "/event/body/text", json!("e\u{301}"))?;
    assert_ne!(composed.signing_bytes()?, decomposed.signing_bytes()?);
    Ok(())
}
