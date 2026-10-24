// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
mod task_support;
use ramflux_protocol::*;
use task_support::*;

#[test]
fn proposals_cannot_execute_until_a_human_accepts_and_declines_are_terminal() -> Result {
    let human = Actor::human();
    let agent = Actor::agent();
    let mut state = TaskState::default();
    state.apply(&agent.event(proposal())?, &agent.signer())?;
    assert!(!state.task().ok_or("task")?.accepted);
    reject(
        &mut state,
        &agent.event(update(2, TaskStatus::Running, vec![step("s", TaskStatus::Running)]))?,
        &agent.signer(),
        &TaskReject::IllegalTransition,
    )?;
    reject(
        &mut state,
        &agent
            .event(TaskEventBody::Accept(TaskAccept { task_id: "task".to_owned(), version: 2 }))?,
        &agent.signer(),
        &TaskReject::HumanRequired,
    )?;
    let mut declined = state.clone();
    declined.apply(
        &human.event(TaskEventBody::Decline(TaskDecline {
            task_id: "task".to_owned(),
            version: 2,
        }))?,
        &human.signer(),
    )?;
    assert_eq!(declined.task().ok_or("task")?.state, TaskStatus::Cancelled);
    reject(
        &mut declined,
        &agent.event(update(3, TaskStatus::Running, vec![]))?,
        &agent.signer(),
        &TaskReject::Terminal,
    )?;
    state.apply(
        &human
            .event(TaskEventBody::Accept(TaskAccept { task_id: "task".to_owned(), version: 2 }))?,
        &human.signer(),
    )?;
    assert!(state.task().ok_or("task")?.accepted);
    assert_eq!(state.task().ok_or("task")?.requester.as_deref(), Some("human"));
    Ok(())
}
#[test]
fn only_the_assignee_updates_and_only_the_human_requester_cancels() -> Result {
    let human = Actor::human();
    let agent = Actor::agent();
    let other = Actor::other();
    let mut state = running()?;
    reject(
        &mut state,
        &other.event(update(2, TaskStatus::Running, vec![]))?,
        &other.signer(),
        &TaskReject::WrongSigner,
    )?;
    let cancel = TaskEventBody::Cancel(TaskCancel { task_id: "task".to_owned(), base_revision: 1 });
    reject(&mut state, &agent.event(cancel.clone())?, &agent.signer(), &TaskReject::HumanRequired)?;
    reject(&mut state, &other.event(cancel.clone())?, &other.signer(), &TaskReject::WrongSigner)?;
    reject(
        &mut state,
        &agent.event(update(2, TaskStatus::Cancelled, vec![]))?,
        &agent.signer(),
        &TaskReject::IllegalTransition,
    )?;
    state.apply(&human.event(cancel)?, &human.signer())?;
    assert_eq!(state.task().ok_or("task")?.state, TaskStatus::Cancelled);
    Ok(())
}
#[test]
fn starts_and_proposals_require_their_named_authenticated_actor_roles() -> Result {
    let human = Actor::human();
    let agent = Actor::agent();
    let other = Actor::other();
    let mut state = TaskState::default();
    reject(&mut state, &agent.event(start())?, &agent.signer(), &TaskReject::HumanRequired)?;
    reject(&mut state, &other.event(start())?, &other.signer(), &TaskReject::WrongSigner)?;
    reject(&mut state, &human.event(proposal())?, &human.signer(), &TaskReject::AgentRequired)?;
    let automated = Actor::new("other", ActorType::Workflow, 51);
    reject(
        &mut state,
        &automated.event(proposal())?,
        &automated.signer(),
        &TaskReject::WrongSigner,
    )?;
    let mut invalid = proposal();
    if let TaskEventBody::Proposal(v) = &mut invalid {
        v.steps[0].state = TaskStatus::Done;
    }
    reject(&mut state, &agent.event(invalid)?, &agent.signer(), &TaskReject::IllegalTransition)?;
    state.apply(&agent.event(proposal())?, &agent.signer())?;
    let impersonated =
        TaskSigner { principal_id: "agent", actor_type: ActorType::Human, ..agent.signer() };
    reject(
        &mut state,
        &agent
            .event(TaskEventBody::Accept(TaskAccept { task_id: "task".to_owned(), version: 2 }))?,
        &impersonated,
        &TaskReject::WrongSigner,
    )?;
    Ok(())
}
#[test]
fn task_and_conversation_binding_and_exact_revisions_reject_replays_and_gaps() -> Result {
    let agent = Actor::agent();
    let human = Actor::human();
    let mut state = running()?;
    reject(&mut state, &human.event(start())?, &human.signer(), &TaskReject::AlreadyExists)?;
    reject(
        &mut TaskState::default(),
        &agent.event(update(2, TaskStatus::Running, vec![]))?,
        &agent.signer(),
        &TaskReject::NotFound,
    )?;
    for version in [1, 3, MAX_TASK_VERSION] {
        reject(
            &mut state,
            &agent.event(update(version, TaskStatus::Running, vec![]))?,
            &agent.signer(),
            &TaskReject::StaleVersion { expected: 2, actual: version },
        )?;
    }
    let mut mismatch = update(2, TaskStatus::Running, vec![]);
    if let TaskEventBody::Update(v) = &mut mismatch {
        v.task_id = "other".to_owned();
    }
    reject(&mut state, &agent.event(mismatch)?, &agent.signer(), &TaskReject::ContextMismatch)?;
    let mut event = agent.event(update(2, TaskStatus::Running, vec![]))?;
    event = TaskEvent::new("elsewhere".to_owned(), event.event().clone(), event.signed().clone())?;
    event = agent.sign(event)?;
    reject(&mut state, &event, &agent.signer(), &TaskReject::ContextMismatch)?;
    state.apply(&agent.event(update(2, TaskStatus::Running, vec![]))?, &agent.signer())?;
    reject(
        &mut state,
        &agent.event(update(2, TaskStatus::Running, vec![]))?,
        &agent.signer(),
        &TaskReject::StaleVersion { expected: 3, actual: 2 },
    )?;
    Ok(())
}
#[test]
fn an_assignee_cannot_drop_retarget_rename_or_resolve_its_open_intervention() -> Result {
    let agent = Actor::agent();
    let mut state = waiting()?;
    for steps in [
        vec![],
        vec![step("s", TaskStatus::Running)],
        vec![blocked("s", NeedsMe::Input { surface_id: "surface".to_owned() })],
        vec![TaskStep { title: "different operation".to_owned(), ..blocked("s", approval()) }],
    ] {
        let status = if steps.iter().any(|s| s.needs_me.is_some()) {
            TaskStatus::NeedsMe
        } else {
            TaskStatus::Running
        };
        reject(
            &mut state,
            &agent.event(update(3, status, steps))?,
            &agent.signer(),
            &TaskReject::HumanDecisionPending,
        )?;
    }
    reject(
        &mut state,
        &agent.event(resolve(3, approval(), TaskDecision::Resume))?,
        &agent.signer(),
        &TaskReject::HumanRequired,
    )?;
    let steps = vec![blocked("s", approval()), step("parallel", TaskStatus::Done)];
    state.apply(&agent.event(update(3, TaskStatus::NeedsMe, steps))?, &agent.signer())?;
    Ok(())
}
#[test]
fn human_resolution_is_bound_to_requester_step_target_and_single_use_decision() -> Result {
    let human = Actor::human();
    let other = Actor::other();
    let agent = Actor::agent();
    let mut state = waiting()?;
    reject(
        &mut state,
        &other.event(resolve(3, approval(), TaskDecision::Resume))?,
        &other.signer(),
        &TaskReject::WrongSigner,
    )?;
    reject(
        &mut state,
        &human.event(resolve(
            3,
            NeedsMe::Choice { surface_id: "wrong".to_owned() },
            TaskDecision::Resume,
        ))?,
        &human.signer(),
        &TaskReject::StaleDecision {
            step_id: "s".into(),
            change: TaskDecisionChange::TargetChanged,
        },
    )?;
    let mut wrong_step = resolve(3, approval(), TaskDecision::Resume);
    if let TaskEventBody::Resolve(v) = &mut wrong_step {
        v.step_id = "else".to_owned();
    }
    reject(&mut state, &human.event(wrong_step)?, &human.signer(), &TaskReject::DecisionMismatch)?;
    state.apply(&human.event(resolve(3, approval(), TaskDecision::Resume))?, &human.signer())?;
    reject(
        &mut state,
        &human.event(resolve(4, approval(), TaskDecision::Resume))?,
        &human.signer(),
        &TaskReject::DecisionReplay,
    )?;
    let mut different = resolve(4, approval(), TaskDecision::Resume);
    if let TaskEventBody::Resolve(v) = &mut different {
        v.decision_id = "new".to_owned();
    }
    reject(
        &mut state,
        &human.event(different)?,
        &human.signer(),
        &TaskReject::StaleDecision { step_id: "s".into(), change: TaskDecisionChange::Closed },
    )?;
    reject(
        &mut state,
        &agent.event(update(4, TaskStatus::NeedsMe, vec![blocked("s", approval())]))?,
        &agent.signer(),
        &TaskReject::DecisionReplay,
    )?;
    state.apply(
        &agent.event(update(4, TaskStatus::Done, vec![step("s", TaskStatus::Done)]))?,
        &agent.signer(),
    )?;
    Ok(())
}
#[test]
fn denied_decisions_and_requester_cancellation_close_interventions() -> Result {
    let human = Actor::human();
    let mut denied = waiting()?;
    denied.apply(&human.event(resolve(3, approval(), TaskDecision::Deny))?, &human.signer())?;
    let task = denied.task().ok_or("task")?;
    assert_eq!(task.state, TaskStatus::Failed);
    assert!(task.steps.iter().all(|s| s.needs_me.is_none()));
    let agent = Actor::agent();
    reject(
        &mut denied,
        &agent.event(update(4, TaskStatus::Running, vec![]))?,
        &agent.signer(),
        &TaskReject::Terminal,
    )?;
    let mut cancelled = waiting()?;
    cancelled.apply(
        &human.event(TaskEventBody::Cancel(TaskCancel {
            task_id: "task".to_owned(),
            base_revision: 2,
        }))?,
        &human.signer(),
    )?;
    assert!(
        cancelled
            .task()
            .ok_or("task")?
            .steps
            .iter()
            .all(|s| s.state == TaskStatus::Cancelled && s.needs_me.is_none())
    );
    Ok(())
}
#[test]
fn step_history_cannot_be_deleted_reopened_or_relabelled_after_completion() -> Result {
    let agent = Actor::agent();
    let human = Actor::human();
    let mut state = running()?;
    state.apply(
        &agent.event(update(2, TaskStatus::Running, vec![step("s", TaskStatus::Running)]))?,
        &agent.signer(),
    )?;
    reject(
        &mut state,
        &agent.event(update(3, TaskStatus::Running, vec![]))?,
        &agent.signer(),
        &TaskReject::IllegalTransition,
    )?;
    reject(
        &mut state,
        &agent.event(update(3, TaskStatus::Running, vec![step("s", TaskStatus::Proposed)]))?,
        &agent.signer(),
        &TaskReject::IllegalTransition,
    )?;
    for status in
        [TaskStatus::Proposed, TaskStatus::Cancelled, TaskStatus::Done, TaskStatus::Failed]
    {
        reject(
            &mut state,
            &agent.event(update(3, status, vec![step("s", TaskStatus::Running)]))?,
            &agent.signer(),
            &TaskReject::IllegalTransition,
        )?;
    }
    let mut premature = update(3, TaskStatus::Running, vec![step("s", TaskStatus::Running)]);
    if let TaskEventBody::Update(v) = &mut premature {
        v.result_ref = Some("object".to_owned());
    }
    reject(&mut state, &agent.event(premature)?, &agent.signer(), &TaskReject::IllegalTransition)?;
    state.apply(
        &agent.event(update(3, TaskStatus::Running, vec![step("s", TaskStatus::Done)]))?,
        &agent.signer(),
    )?;
    reject(
        &mut state,
        &agent.event(update(4, TaskStatus::Running, vec![step("s", TaskStatus::Running)]))?,
        &agent.signer(),
        &TaskReject::IllegalTransition,
    )?;
    reject(
        &mut state,
        &human
            .event(TaskEventBody::Accept(TaskAccept { task_id: "task".to_owned(), version: 4 }))?,
        &human.signer(),
        &TaskReject::IllegalTransition,
    )?;
    state.apply(
        &agent.event(update(4, TaskStatus::Done, vec![step("s", TaskStatus::Done)]))?,
        &agent.signer(),
    )?;
    reject(
        &mut state,
        &agent.event(update(5, TaskStatus::Running, vec![]))?,
        &agent.signer(),
        &TaskReject::Terminal,
    )?;
    Ok(())
}
#[test]
fn bounded_transition_chains_preserve_invariants_across_all_intervention_kinds() -> Result {
    let human = Actor::human();
    let agent = Actor::agent();
    for target in [
        approval(),
        NeedsMe::Choice { surface_id: "surface".to_owned() },
        NeedsMe::Input { surface_id: "surface".to_owned() },
    ] {
        for length in 1..=8 {
            let mut state = running()?;
            let mut steps = vec![];
            for n in 0..length {
                let id = format!("p{n}");
                steps.push(step(&id, TaskStatus::Running));
                let version = state.task().ok_or("task")?.version + 1;
                state.apply(
                    &agent.event(update(version, TaskStatus::Running, steps.clone()))?,
                    &agent.signer(),
                )?;
            }
            steps.push(blocked("s", target.clone()));
            let version = state.task().ok_or("task")?.version + 1;
            state.apply(
                &agent.event(update(version, TaskStatus::NeedsMe, steps.clone()))?,
                &agent.signer(),
            )?;
            assert_eq!(
                state.task().ok_or("task")?.steps.iter().filter(|s| s.needs_me.is_some()).count(),
                1
            );
            state.apply(
                &human.event(resolve(version + 1, target.clone(), TaskDecision::Resume))?,
                &human.signer(),
            )?;
            let done = state
                .task()
                .ok_or("task")?
                .steps
                .iter()
                .map(|s| step(&s.id, TaskStatus::Done))
                .collect();
            state.apply(
                &agent.event(update(version + 2, TaskStatus::Done, done))?,
                &agent.signer(),
            )?;
            assert_eq!(state.task().ok_or("task")?.state, TaskStatus::Done);
            reject(
                &mut state,
                &agent.event(update(version + 3, TaskStatus::Running, vec![]))?,
                &agent.signer(),
                &TaskReject::Terminal,
            )?;
        }
    }
    Ok(())
}
