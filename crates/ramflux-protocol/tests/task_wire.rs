// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
mod task_support;
use ramflux_protocol::*;
use serde_json::{Value, json};
use task_support::*;

#[test]
fn every_event_round_trips_and_rejects_unknown_fields_at_each_wire_layer() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    let cases = vec![
        h.event(start())?,
        a.event(proposal())?,
        h.event(TaskEventBody::Accept(TaskAccept { task_id: "task".to_owned(), version: 2 }))?,
        h.event(TaskEventBody::Decline(TaskDecline { task_id: "task".to_owned(), version: 2 }))?,
        a.event(update(2, TaskStatus::NeedsMe, vec![blocked("s", approval())]))?,
        h.event(TaskEventBody::Cancel(TaskCancel { task_id: "task".to_owned(), version: 2 }))?,
        h.event(resolve(3, approval(), TaskDecision::Resume))?,
    ];
    for event in cases {
        let wire = serde_json::to_value(&event)?;
        let parsed: TaskEvent = serde_json::from_value(wire.clone())?;
        assert_eq!(parsed, event);
        for path in ["", "/event", "/event/body"] {
            let mut bad = wire.clone();
            bad.pointer_mut(path)
                .and_then(Value::as_object_mut)
                .ok_or("object")?
                .insert("unknown".to_owned(), json!(true));
            assert!(serde_json::from_value::<TaskEvent>(bad).is_err(), "unknown field at {path}");
        }
        assert_ne!(event.fallback_text(), "");
    }
    let mut nested = serde_json::to_value(a.event(update(
        2,
        TaskStatus::NeedsMe,
        vec![blocked("s", approval())],
    ))?)?;
    nested["event"]["body"]["steps"][0]["unknown"] = json!(0);
    assert!(serde_json::from_value::<TaskEvent>(nested).is_err());
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
    let h = Actor::human();
    let valid = h.event(start())?;
    let mut bad = valid.clone();
    bad.schema = "other".to_owned();
    reject(&mut TaskState::default(), &bad, &h.signer(), &TaskReject::InvalidSchema)?;
    bad = valid.clone();
    bad.version = 2;
    reject(&mut TaskState::default(), &bad, &h.signer(), &TaskReject::InvalidSchema)?;
    bad = valid.clone();
    bad.domain = domain::MCP_GRANT.to_owned();
    reject(&mut TaskState::default(), &bad, &h.signer(), &TaskReject::InvalidDomain)?;
    bad = valid.clone();
    bad.ext.ext.insert("critical.unknown".to_owned(), json!(true));
    reject(
        &mut TaskState::default(),
        &bad,
        &h.signer(),
        &TaskReject::Protocol(ProtocolError::UnknownCriticalExtension(
            "critical.unknown".to_owned(),
        )),
    )?;
    bad = valid;
    bad.conversation_id = "elsewhere".to_owned();
    reject(&mut TaskState::default(), &bad, &h.signer(), &TaskReject::ContextMismatch)?;
    Ok(())
}
#[test]
fn signatures_bind_context_payload_extensions_and_the_pinned_signing_identity() -> Result {
    let a = Actor::agent();
    let h = Actor::human();
    let other = Actor::other();
    let valid = a.event(update(2, TaskStatus::Running, vec![]))?;
    valid.verify(&a.signer())?;
    let mut context_tamper = valid.clone();
    context_tamper.conversation_id = "other-chat".to_owned();
    assert!(matches!(context_tamper.verify(&a.signer()), Err(TaskReject::InvalidSignature)));
    let mut bad = valid.clone();
    bad.ext.ext.insert("label".to_owned(), json!("altered"));
    assert!(matches!(bad.verify(&a.signer()), Err(TaskReject::InvalidSignature)));
    bad = valid.clone();
    bad.signed.signature = "invalid".to_owned();
    assert!(matches!(bad.verify(&a.signer()), Err(TaskReject::InvalidSignature)));
    assert!(matches!(valid.verify(&other.signer()), Err(TaskReject::WrongSigner)));
    let forged = TaskSigner { signing_key_id: a.key_id, ..h.signer() };
    assert!(matches!(valid.verify(&forged), Err(TaskReject::InvalidSignature)));
    let empty = TaskSigner { principal_id: "", ..a.signer() };
    assert!(matches!(valid.verify(&empty), Err(TaskReject::WrongSigner)));
    bad = valid.clone();
    bad.signed.signing_key_id = "unbound-key".to_owned();
    assert!(matches!(bad.verify(&a.signer()), Err(TaskReject::WrongSigner)));
    bad = valid;
    if let TaskEventBody::Update(v) = &mut bad.event {
        v.version = 3;
    }
    assert!(matches!(bad.verify(&a.signer()), Err(TaskReject::InvalidSignature)));
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
    assert!(matches!(h.event(body)?.validate(), Err(TaskReject::InvalidField("text"))));
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
    assert!(matches!(a.event(body)?.validate(), Err(TaskReject::InvalidField("title"))));
    let too_many = update(
        2,
        TaskStatus::Running,
        (0..=MAX_TASK_STEPS).map(|i| step(&format!("s{i}"), TaskStatus::Running)).collect(),
    );
    assert!(matches!(a.event(too_many)?.validate(), Err(TaskReject::TooManySteps)));
    let mut event = h.event(start())?;
    event.ext.ext.insert("padding".to_owned(), json!(""));
    let overhead = canonical_json_bytes(&event)?.len();
    event.ext.ext.insert("padding".to_owned(), json!("x".repeat(MAX_TASK_EVENT_BYTES - overhead)));
    event = h.sign(event)?;
    assert_eq!(canonical_json_bytes(&event)?.len(), MAX_TASK_EVENT_BYTES);
    event.validate()?;
    event
        .ext
        .ext
        .insert("padding".to_owned(), json!("x".repeat(MAX_TASK_EVENT_BYTES - overhead + 1)));
    assert!(matches!(event.validate(), Err(TaskReject::EventTooLarge)));
    Ok(())
}
#[test]
fn identifiers_optional_fields_and_intervention_consistency_have_typed_rejections() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    let mut bad = h.event(start())?;
    bad.conversation_id.clear();
    assert!(matches!(bad.validate(), Err(TaskReject::InvalidField("conversation_id"))));
    let mut body = start();
    if let TaskEventBody::Start(v) = &mut body {
        v.task_id.clear();
    }
    assert!(matches!(h.event(body)?.validate(), Err(TaskReject::InvalidField("task_id"))));
    for field in ["requester", "assignee", "text", "constraints"] {
        let mut wire = serde_json::to_value(h.event(start())?)?;
        wire["event"]["body"][field] = json!("");
        let event: TaskEvent = serde_json::from_value(wire)?;
        assert!(matches!(event.validate(), Err(TaskReject::InvalidField(_))));
    }
    for bad_step in [
        TaskStep { id: String::new(), ..step("s", TaskStatus::Running) },
        TaskStep { title: "x".repeat(257), ..step("s", TaskStatus::Running) },
        blocked("s", NeedsMe::Input { surface_id: String::new() }),
    ] {
        assert!(matches!(
            a.event(update(2, TaskStatus::Running, vec![bad_step]))?.validate(),
            Err(TaskReject::InvalidField(_))
        ));
    }
    let duplicate = vec![step("s", TaskStatus::Running), step("s", TaskStatus::Running)];
    assert!(matches!(
        a.event(update(2, TaskStatus::Running, duplicate))?.validate(),
        Err(TaskReject::DuplicateStep)
    ));
    for inconsistent in [
        step("s", TaskStatus::NeedsMe),
        TaskStep { needs_me: Some(approval()), ..step("s", TaskStatus::Running) },
    ] {
        assert!(matches!(
            a.event(update(2, TaskStatus::NeedsMe, vec![inconsistent]))?.validate(),
            Err(TaskReject::NeedsMeMismatch)
        ));
    }
    let twice = vec![
        blocked("s", approval()),
        blocked("t", NeedsMe::Choice { surface_id: "surface".to_owned() }),
    ];
    assert!(matches!(
        a.event(update(2, TaskStatus::NeedsMe, twice))?.validate(),
        Err(TaskReject::MultipleNeedsMe)
    ));
    let mut state = running()?;
    reject(
        &mut state,
        &a.event(update(2, TaskStatus::NeedsMe, vec![]))?,
        &a.signer(),
        &TaskReject::NeedsMeMismatch,
    )?;
    reject(
        &mut state,
        &a.event(update(2, TaskStatus::Running, vec![blocked("s", approval())]))?,
        &a.signer(),
        &TaskReject::NeedsMeMismatch,
    )?;
    Ok(())
}
#[test]
fn revisions_are_safe_json_integers_and_replay_keys_are_conversation_scoped() -> Result {
    let a = Actor::agent();
    for version in [0, MAX_TASK_VERSION + 1, u64::MAX] {
        assert!(matches!(
            a.event(update(version, TaskStatus::Running, vec![]))?.validate(),
            Err(TaskReject::InvalidVersion)
        ));
    }
    a.event(update(MAX_TASK_VERSION, TaskStatus::Running, vec![]))?.validate()?;
    let mut event = a.event(update(2, TaskStatus::Running, vec![]))?;
    let key = event.replay_key();
    event.conversation_id = "other".to_owned();
    assert_ne!(event.replay_key(), key);
    for version in [json!(-1), json!(1.5)] {
        let mut wire = serde_json::to_value(&event)?;
        wire["event"]["body"]["version"] = version;
        assert!(serde_json::from_value::<TaskEvent>(wire).is_err());
    }
    Ok(())
}
#[test]
fn fallback_is_plain_text_and_canonicalization_does_not_normalize_unicode() -> Result {
    let h = Actor::human();
    let mut body = start();
    if let TaskEventBody::Start(v) = &mut body {
        v.text = "\u{1b}[31mvisible".to_owned();
    }
    let event = h.event(body)?;
    assert!(!event.fallback_text().contains('\u{1b}'));
    assert!(event.fallback_text().contains("visible"));
    let mut composed = h.event(start())?;
    if let TaskEventBody::Start(v) = &mut composed.event {
        v.text = "é".to_owned();
    }
    let mut decomposed = composed.clone();
    if let TaskEventBody::Start(v) = &mut decomposed.event {
        v.text = "e\u{301}".to_owned();
    }
    assert_ne!(composed.signing_bytes()?, decomposed.signing_bytes()?);
    Ok(())
}

#[test]
fn remaining_identity_reference_and_resolution_fields_reject_empty_values() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    let mut header = h.event(start())?;
    header.signed.signing_key_id.clear();
    assert!(matches!(header.validate(), Err(TaskReject::InvalidField("signing_key_id"))));
    for field in ["proposer", "assignee"] {
        let mut wire = serde_json::to_value(a.event(proposal())?)?;
        wire["event"]["body"][field] = json!("");
        let event: TaskEvent = serde_json::from_value(wire)?;
        assert!(matches!(event.validate(), Err(TaskReject::InvalidField(_))));
    }
    let mut body = update(2, TaskStatus::Done, vec![]);
    if let TaskEventBody::Update(v) = &mut body {
        v.result_ref = Some(String::new());
    }
    assert!(matches!(a.event(body)?.validate(), Err(TaskReject::InvalidField("result_ref"))));
    for path in ["/event/body/step_id", "/event/body/decision_id", "/event/body/target/grant_id"] {
        let mut wire =
            serde_json::to_value(h.event(resolve(3, approval(), TaskDecision::Resume))?)?;
        *wire.pointer_mut(path).ok_or("field")? = json!("");
        let event: TaskEvent = serde_json::from_value(wire)?;
        assert!(matches!(event.validate(), Err(TaskReject::InvalidField(_))));
    }
    Ok(())
}
