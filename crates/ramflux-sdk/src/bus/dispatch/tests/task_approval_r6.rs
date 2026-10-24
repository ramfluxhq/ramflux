// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Saturated requesters and retryable failures cannot strand another valid approval.
use super::*;

#[test]
fn r6_one_requesters_sixteen_unanswered_sources_do_not_block_another_requesters_grant() -> Case {
    let (root, mut agent, human) = pair("peer-admission-r6")?;
    let bob =
        runtime_tests::account(&root.join("bob"), "bob", None, Arc::new(AtomicBool::new(false)))?;
    let bkey = crate::client::task::scoped("view", "other", "b")?;
    let a = (0..256)
        .map(|n| format!("a-{n}"))
        .find(|id| crate::client::task::scoped("view", "thread", id).is_ok_and(|key| key < bkey))
        .ok_or("ordered fixture")?;
    open_named(&human, &agent, &a, "grant-a")?;
    pending(&mut agent, "original", "grant-a")?;
    let original = request_job(&agent, &a)?.packet;
    for n in 0..15 {
        let mut request = original.request().clone();
        request.approval.approval_id = format!("unanswered-{n}");
        request.grant_body.approval_id = request.approval.approval_id.clone();
        let packet =
            agent.client.sign_task_approval(Payload::Request { request: Box::new(request) })?;
        agent.client.queue_task_approval(&packet)?;
        agent.client.remember_task_approval_source(&packet)?;
    }
    assert_eq!(agent.client.account_db()?.task_state_usage("task/approval_source/")?.0, 16);
    agent.mcp_pending_approvals.remove("original");
    insert_pending(&mut agent, "blocked-a", "grant-a")?;
    open_for(&bob, &agent, "b", "grant-b", "other")?;
    insert_pending(&mut agent, "approval-b", "grant-b")?;
    queue_requests(&mut agent)?;
    let request = request_job(&agent, "b")?;
    let decision = decide(&bob, &request.packet, true)?;
    agent.client.accept_task_approval(&decision.packet)?;
    apply_decisions(&mut agent)?;
    assert!(agent.mcp_grants.contains_key("grant-b"));
    drop(bob);
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn r6_transient_application_errors_preserve_the_decision_until_a_later_successful_retry() -> Case {
    use crate::bus::dispatch::task_approval::apply::{apply_one, apply_using};
    let (root, mut agent, human) = pair("approval-transient-r6")?;
    open_named(&human, &agent, "task", "grant")?;
    pending(&mut agent, "approval", "grant")?;
    let request = request_job(&agent, "task")?;
    let decision = decide(&human, &request.packet, true)?;
    agent.client.accept_task_approval(&decision.packet)?;
    let storage = key("approval_decision_in", &decision.packet.id()?);
    for error in [
        SdkError::InboundPending("dependency restoring".into()),
        SdkError::GatewaySessionNotEstablished,
        SdkError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "worker temporarily unavailable",
        )),
    ] {
        let mut error = Some(error);
        apply_using(&mut agent, |_, _| {
            Err(error.take().ok_or_else(|| invalid("fault consumed"))?)
        })?;
        assert!(agent.client.account_db()?.actor_state_exists(&storage)?);
        assert!(agent.client.task_approval_receipt(&decision.packet.id()?)?.is_none());
    }
    apply_using(&mut agent, apply_one)?;
    assert!(agent.mcp_grants.contains_key("grant"));
    assert!(!agent.client.account_db()?.actor_state_exists(&storage)?);
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
