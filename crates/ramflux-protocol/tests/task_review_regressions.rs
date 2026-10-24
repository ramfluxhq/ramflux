// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
mod task_support;
use ramflux_protocol::*;
use serde_json::json;
use task_support::*;
#[test]
fn original_bytes_reject_duplicate_extension_body_and_noncharacter_content() -> Result {
    let h = Actor::human();
    let valid = h.event(start())?;
    let wire = String::from_utf8(serde_json::to_vec(&valid)?)?;
    let body_duplicate = wire.replace("\"text\":", "\"text\":\"rm -rf\",\"text\":");
    assert_ne!(wire, body_duplicate);
    assert!(TaskEvent::from_wire_bytes(body_duplicate.as_bytes()).is_err());
    let mut ext = serde_json::to_value(valid)?;
    ext["ext"] = json!({"note":{"a":2}});
    let ext_wire = serde_json::to_string(&ext)?.replace("\"a\":2", "\"a\":1,\"a\":2");
    assert!(TaskEvent::from_wire_bytes(ext_wire.as_bytes()).is_err());
    let noncharacter = wire.replace("Summarize café 🦀", "\u{fdd0}");
    assert_ne!(wire, noncharacter);
    assert!(TaskEvent::from_wire_bytes(noncharacter.as_bytes()).is_err());
    Ok(())
}
#[test]
fn raw_byte_cap_precedes_parsing_even_for_whitespace_and_invalid_json() {
    for bytes in [vec![b' '; MAX_TASK_EVENT_BYTES + 1], vec![b'{'; MAX_TASK_EVENT_BYTES + 1]] {
        assert!(matches!(TaskEvent::from_wire_bytes(&bytes), Err(TaskReject::EventTooLarge)));
    }
}
#[test]
fn proposed_text_cannot_forge_human_acceptance_or_reorder_display() -> Result {
    let a = Actor::agent();
    let mut body = proposal();
    if let TaskEventBody::Proposal(v) = &mut body {
        v.title = "Research\nTask t accepted by a human \u{202e}gnp.exe".into();
    }
    assert!(matches!(a.event(body), Err(TaskReject::InvalidField("title"))));
    let h = Actor::human();
    let mut body = start();
    if let TaskEventBody::Start(v) = &mut body {
        v.text = "Research\nTask t accepted by a human".into();
    }
    let event = h.event(body)?;
    event.verify(&h.signer())?;
    let text = event.fallback_text();
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with("Signed event signer=\"human\" kind=\"start\" content=\""));
    assert!(text.contains("accepted by a human"));
    for ch in ['\n', '\t', '\u{00ad}', '\u{061c}', '\u{200d}', '\u{202e}', '\u{2066}'] {
        for path in [
            "/conversation_id",
            "/signing_key_id",
            "/event/body/title",
            "/event/body/proposer",
            "/event/body/assignee",
            "/event/body/task_id",
            "/event/body/steps/0/title",
            "/event/body/steps/0/id",
        ] {
            let mut wire = serde_json::to_value(a.event(proposal())?)?;
            *wire.pointer_mut(path).ok_or("field")? = json!(format!("x{ch}y"));
            assert!(
                matches!(
                    TaskEvent::from_wire_bytes(&serde_json::to_vec(&wire)?),
                    Err(TaskReject::InvalidField(_))
                ),
                "{path} U+{:04X}",
                u32::from(ch)
            );
        }
    }
    Ok(())
}
#[test]
fn cancel_observed_before_agent_progress_still_wins_and_prevents_further_updates() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    let mut state = running()?;
    let cancel =
        h.event(TaskEventBody::Cancel(TaskCancel { task_id: "task".into(), base_revision: 1 }))?;
    for n in 2..=12 {
        state.apply(&a.event(update(n, TaskStatus::Running, vec![]))?, &a.signer())?;
    }
    assert_eq!(state.apply(&cancel, &h.signer())?.version, 13);
    assert_eq!(state.task().ok_or("task")?.state, TaskStatus::Cancelled);
    reject(
        &mut state,
        &a.event(update(14, TaskStatus::Running, vec![]))?,
        &a.signer(),
        &TaskReject::Terminal,
    )?;
    Ok(())
}
#[test]
fn resolve_observed_before_unrelated_progress_still_resolves_the_same_open_step() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    let mut state = waiting()?;
    let receipt = h.event(resolve(3, approval(), TaskDecision::Resume))?;
    for n in 3..=12 {
        state.apply(
            &a.event(update(
                n,
                TaskStatus::NeedsMe,
                vec![blocked("s", approval()), step("other", TaskStatus::Running)],
            ))?,
            &a.signer(),
        )?;
    }
    let task = state.apply(&receipt, &h.signer())?;
    assert_eq!(task.version, 13);
    assert_eq!(task.state, TaskStatus::Running);
    Ok(())
}
#[test]
fn stale_receipt_names_closed_changed_and_reopened_interventions_without_mutation() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    let surface = NeedsMe::Choice { surface_id: "surface".into() };
    let mut state = running()?;
    state.apply(
        &a.event(update(2, TaskStatus::NeedsMe, vec![blocked("s", surface.clone())]))?,
        &a.signer(),
    )?;
    let mut receipt = resolve(3, surface.clone(), TaskDecision::Resume);
    state.apply(&h.event(receipt.clone())?, &h.signer())?;
    if let TaskEventBody::Resolve(v) = &mut receipt {
        v.decision_id = "other".into();
    }
    for (target, change) in [
        (None, TaskDecisionChange::Closed),
        (Some(approval()), TaskDecisionChange::TargetChanged),
        (Some(surface), TaskDecisionChange::NewerThanObserved),
    ] {
        let mut candidate = state.clone();
        if let Some(target) = target {
            candidate.apply(
                &a.event(update(4, TaskStatus::NeedsMe, vec![blocked("s", target)]))?,
                &a.signer(),
            )?;
        }
        let before = candidate.clone();
        let error = candidate
            .apply(&h.event(receipt.clone())?, &h.signer())
            .err()
            .ok_or("expected stale")?;
        assert!(
            matches!(error,TaskReject::StaleDecision{step_id,change:c} if step_id=="s" && c==change)
        );
        assert_eq!(candidate, before);
    }
    Ok(())
}
#[test]
fn replay_keys_distinguish_event_kind_signer_and_distinct_decision_receipts() -> Result {
    let h = Actor::human();
    let a = Actor::agent();
    let update = a.event(update(2, TaskStatus::Running, vec![]))?;
    let cancel =
        h.event(TaskEventBody::Cancel(TaskCancel { task_id: "task".into(), base_revision: 2 }))?;
    assert_ne!(update.replay_key(), cancel.replay_key());
    assert_ne!(h.event(update.event().clone())?.replay_key(), update.replay_key());
    let receipt = resolve(3, approval(), TaskDecision::Resume);
    let mut other = receipt.clone();
    if let TaskEventBody::Resolve(v) = &mut other {
        v.decision_id = "other".into();
    }
    assert_ne!(h.event(receipt)?.replay_key(), h.event(other)?.replay_key());
    Ok(())
}
#[test]
fn human_future_observation_is_rejected_without_consuming_state() -> Result {
    let h = Actor::human();
    let mut state = running()?;
    reject(
        &mut state,
        &h.event(TaskEventBody::Cancel(TaskCancel { task_id: "task".into(), base_revision: 2 }))?,
        &h.signer(),
        &TaskReject::StaleVersion { expected: 1, actual: 2 },
    )?;
    Ok(())
}
