// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Task-local faults cannot monopolize approval admission or survive as retryable decisions.
use super::*;

#[test]
fn r7_a_bad_task_history_does_not_block_another_tasks_approval_request() -> Case {
    let (root, mut agent, human) = pair("queue-isolation-r7")?;
    let good_key = crate::client::task::scoped("view", "thread", "good")?;
    let bad = (0..256)
        .map(|n| format!("bad-{n}"))
        .find(|id| {
            crate::client::task::scoped("view", "thread", id).is_ok_and(|key| key < good_key)
        })
        .ok_or("ordered fixture")?;
    open_named(&human, &agent, &bad, "bad-grant")?;
    open_named(&human, &agent, "good", "good-grant")?;
    insert_pending(&mut agent, "bad-approval", "bad-grant")?;
    insert_pending(&mut agent, "good-approval", "good-grant")?;
    corrupt_history(&agent, &bad)?;
    queue_requests(&mut agent)?;
    let job = request_job(&agent, "good")?;
    let decision = decide(&human, &job.packet, true)?;
    agent.client.accept_task_approval(&decision.packet)?;
    apply_decisions(&mut agent)?;
    assert!(agent.mcp_grants.contains_key("good-grant"));
    assert!(!agent.mcp_grants.contains_key("bad-grant"));
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn corrupt_history(account: &LocalBusAccountState, task: &str) -> Case {
    let storage = crate::client::task::scoped("history", "thread", task)?;
    let mut history = account.client.task_history("thread", task)?;
    history.events.first_mut().ok_or("history")?.carrier.signature = "invalid".into();
    account.client.account_db()?.persist_actor_state(&storage, &history)?;
    Ok(())
}
#[test]
fn r7_a_bad_task_does_not_prevent_expired_approval_receipt_cleanup() -> Case {
    let (root, mut agent, human) = pair("cleanup-isolation-r7")?;
    open_named(&human, &agent, "bad", "grant")?;
    pending(&mut agent, "approval", "grant")?;
    let request = request_job(&agent, "bad")?;
    let decision = decide(&human, &request.packet, true)?;
    let id = decision.packet.id()?;
    let storage = key("approval_receipt", &id);
    agent.client.record_task_approval_delivery(
        &decision.packet,
        crate::client::task::approval_retention::DeliveryState::Submitted,
        None,
    )?;
    let mut receipt: Value =
        agent.client.account_db()?.load_actor_state(&storage)?.ok_or("receipt")?;
    receipt["expires_at"] = json!(now_unix_timestamp() - 1);
    agent.client.account_db()?.persist_actor_state(&storage, &receipt)?;
    // The executor still owns live source/outgoing rows whose task history is now broken.
    assert!(agent.client.account_db()?.actor_state_exists(&key("approval_source", &id))?);
    corrupt_history(&agent, "bad")?;
    cleanup(&agent)?;
    assert!(!agent.client.account_db()?.actor_state_exists(&storage)?);
    assert!(!agent.mcp_grants.contains_key("grant"));
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn r7_deterministic_application_errors_reject_decisions_instead_of_retrying_forever() -> Case {
    use crate::bus::dispatch::task_approval::apply::apply_using;
    use ramflux_transport::TransportError as T;
    let (root, mut agent, human) = pair("retry-allowlist-r7")?;
    open_named(&human, &agent, "task", "grant")?;
    pending(&mut agent, "approval", "grant")?;
    let request = request_job(&agent, "task")?;
    let decision = decide(&human, &request.packet, true)?;
    let id = decision.packet.id()?;
    let storage = key("approval_decision_in", &id);
    let rejected = key("approval_rejected", &id);
    for error in [
        SdkError::LocalBus("deterministic local invariant failure".into()),
        SdkError::IdentityRootMissing,
        SdkError::AccountDbNotUnlocked,
        SdkError::PairRecoveryRequired,
        SdkError::RemoteAppApprovalRequired,
        SdkError::Transport(T::NotAuthenticated),
        SdkError::Transport(T::Tls("certificate pin mismatch".into())),
        SdkError::Transport(T::Http("HTTP 403: denied".into())),
        crate::task_refusal::refused(crate::TaskRefusalCode::StaleRevision, "stale"),
    ] {
        agent.client.account_db()?.delete_task_state(&rejected)?;
        agent.client.account_db()?.persist_actor_state(&storage, &decision.packet)?;
        let mut error = Some(error);
        apply_using(&mut agent, |_, _| {
            Err(error.take().ok_or_else(|| invalid("fault consumed"))?)
        })?;
        assert!(!agent.client.account_db()?.actor_state_exists(&storage)?);
        assert!(agent.client.account_db()?.actor_state_exists(&rejected)?);
        assert!(!agent.mcp_grants.contains_key("grant"));
    }
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn r7_a_malformed_job_does_not_block_the_next_approval_delivery_attempt() -> Case {
    let (root, mut agent, human) = pair("courier-isolation-r7")?;
    open_named(&human, &agent, "task", "grant")?;
    pending(&mut agent, "approval", "grant")?;
    let request = request_job(&agent, "task")?;
    // Its packet is valid, but a broken local job omits its retry metadata.
    agent.client.account_db()?.persist_actor_state(
        "task/approval_out/000000-malformed",
        &json!({"packet":request.packet}),
    )?;
    assert_eq!(drive(&mut agent).await?, 0);
    let retried: Job = agent
        .client
        .account_db()?
        .load_actor_state(&key("approval_out", &request.packet.id()?))?
        .ok_or("delivery job")?;
    assert_eq!(retried.attempts, 1);
    assert!(!agent.mcp_grants.contains_key("grant"));
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
