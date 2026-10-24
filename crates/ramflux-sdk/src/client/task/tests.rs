// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated task runtime fixtures and behavioral authority/projection tests.
use super::*;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{
    TaskAccept, TaskEvent, TaskEventBody, TaskProposal, TaskStart, TaskStatus, TaskStep, TaskUpdate,
};
use serde_json::json;
use std::path::PathBuf;
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture {
    root: PathBuf,
    human: RamfluxClient,
    agent: RamfluxClient,
}
fn client(root: &std::path::Path, id: &str, seed: u8) -> Result<RamfluxClient, SdkError> {
    let mut c = RamfluxClient::new();
    c.create_identity_root(id, [seed; 32]);
    c.create_device_branch(id, &format!("{id}-device"), 1, [seed + 1; 32]);
    c.open_account_index(root)?;
    c.create_account(id, id)?;
    c.unlock_account(id, b"task-test-secret")?;
    Ok(c)
}
impl Fixture {
    fn new() -> Result<Self, SdkError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rf-task-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let human = client(&root.join("human"), "human", 61)?;
        let agent = client(&root.join("agent"), "agent", 71)?;
        for (local, remote) in [(&human, &agent), (&agent, &human)] {
            let d = remote.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            let r = remote.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            let commitment = crate::identity_root_public_key_commitment(
                &ramflux_protocol::encode_base64url(r.signing_key.verifying_key().to_bytes()),
            )?;
            local.account_db()?.persist_client_record("device",&d.device_id,&json!({"principal_id":d.principal_id,"principal_commitment":commitment,"signing_public_key":ramflux_protocol::encode_base64url(d.signing_key.verifying_key().to_bytes())}))?;
            local.account_db()?.persist_client_record(
                "conversation",
                "thread",
                &json!({"kind":"direct","participants":["human","agent"]}),
            )?;
        }
        Ok(Self { root, human, agent })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.human = RamfluxClient::new();
        self.agent = RamfluxClient::new();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn sign(
    client: &RamfluxClient,
    conversation: &str,
    id: &str,
    body: TaskEventBody,
) -> Result<carrier::Carrier, SdkError> {
    let d = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let e = TaskEvent::new(
        conversation.into(),
        body,
        crate::prelude::sdk_device_signed_fields(&d.device_id, ""),
    )
    .map_err(|e| invalid(e.to_string()))?;
    client.sign_task_event(e, id.into(), None)
}
fn project(
    client: &RamfluxClient,
    carrier: &carrier::Carrier,
) -> Result<projection::Outcome, SdkError> {
    client
        .project_task_message(
            &Delivery {
                conversation: &carrier.conversation_id,
                message: &carrier.message_id,
                principal: &carrier.principal_id,
                device: &carrier.device_id,
                at: crate::time::now_unix_timestamp(),
            },
            &carrier.bytes()?,
        )?
        .ok_or_else(|| invalid("task projection missing"))
}
fn start(id: &str, conversation: &str) -> TaskEventBody {
    TaskEventBody::Start(TaskStart {
        task_id: id.into(),
        conversation_id: conversation.into(),
        requester: "human".into(),
        assignee: "agent".into(),
        text: "Find the answer".into(),
        constraints: Some("Use trusted sources".into()),
    })
}
fn proposal() -> TaskEventBody {
    TaskEventBody::Proposal(TaskProposal {
        task_id: "proposal".into(),
        conversation_id: "thread".into(),
        proposer: "agent".into(),
        assignee: "agent".into(),
        title: "Find the answer".into(),
        steps: vec![TaskStep {
            id: "step".into(),
            title: "Research".into(),
            state: TaskStatus::Proposed,
            needs_me: None,
        }],
    })
}
#[test]
fn task_carriers_preserve_exact_event_bytes_and_reject_duplicate_json_members() -> TestResult {
    let f = Fixture::new()?;
    let c = sign(&f.human, "thread", "start", start("task", "thread"))?;
    let original = ramflux_protocol::decode_base64url(&c.wire_base64)?;
    let decoded = carrier::Carrier::decode(&c.bytes()?)?.ok_or("carrier missing")?;
    assert_eq!(ramflux_protocol::decode_base64url(&decoded.wire_base64)?, original);
    decoded.verify(&f.agent.task_signer_key("human", "human-device")?)?;
    let mut duplicate = c;
    let raw = String::from_utf8(original)?.replacen('{', "{\"conversation_id\":\"other\",", 1);
    duplicate.wire_base64 = ramflux_protocol::encode_base64url(raw);
    assert!(duplicate.event().is_err());
    Ok(())
}
#[test]
fn headless_accounts_cannot_sign_human_actions_by_changing_their_kind() -> TestResult {
    use crate::LocalBusClientMode::{AttendedCli, HeadlessAi};
    assert!(require_local_human(&HeadlessAi, Some("human")).is_err());
    assert!(require_local_human(&AttendedCli, Some("headless_ai")).is_err());
    require_local_human(&AttendedCli, Some("human"))?;
    Ok(())
}
#[test]
fn task_actor_kind_is_unverified_and_agent_cannot_accept_its_own_proposal() -> TestResult {
    let f = Fixture::new()?;
    let proposal = sign(&f.agent, "thread", "proposal", proposal())?;
    assert!(project(&f.human, &proposal)?.accepted);
    let self_accept = sign(
        &f.agent,
        "thread",
        "bad-accept",
        TaskEventBody::Accept(TaskAccept { task_id: "proposal".into(), version: 2 }),
    )?;
    assert!(!project(&f.human, &self_accept)?.accepted);
    assert_eq!(f.human.task_get(Some("thread"), "proposal")?["version"], 1);
    let accepted = sign(
        &f.human,
        "thread",
        "accept",
        TaskEventBody::Accept(TaskAccept { task_id: "proposal".into(), version: 2 }),
    )?;
    assert!(project(&f.human, &accepted)?.accepted);
    let row = f.human.task_get(Some("thread"), "proposal")?;
    assert_eq!(row["requester"], "human");
    assert_eq!(row["actor_kind_verified"], false);
    Ok(())
}
#[test]
fn task_ids_in_different_conversations_do_not_share_state() -> TestResult {
    let f = Fixture::new()?;
    f.agent.account_db()?.persist_client_record(
        "conversation",
        "other",
        &json!({"kind":"direct","participants":["human","agent"]}),
    )?;
    for conversation in ["thread", "other"] {
        assert!(
            project(
                &f.agent,
                &sign(&f.human, conversation, conversation, start("same-id", conversation))?
            )?
            .accepted
        );
    }
    assert_eq!(f.agent.task_get(Some("thread"), "same-id")?["version"], 1);
    assert_eq!(f.agent.task_get(Some("other"), "same-id")?["version"], 1);
    assert!(f.agent.task_get(None, "same-id").is_err());
    Ok(())
}
#[test]
fn a_nonmember_cannot_start_or_be_assigned_a_conversation_task() -> TestResult {
    let f = Fixture::new()?;
    let mut event = start("outside", "thread");
    if let TaskEventBody::Start(v) = &mut event {
        v.assignee = "outsider".into();
    }
    assert!(!project(&f.agent, &sign(&f.human, "thread", "bad", event)?)?.accepted);
    assert_eq!(f.agent.task_get(Some("thread"), "outside")?, serde_json::Value::Null);
    Ok(())
}
#[test]
fn rejected_updates_leave_task_revision_and_steps_unchanged_and_replays_are_idempotent()
-> TestResult {
    let f = Fixture::new()?;
    let c = sign(&f.human, "thread", "start", start("task", "thread"))?;
    assert!(project(&f.agent, &c)?.accepted);
    assert!(project(&f.agent, &c)?.accepted);
    let before = f.agent.task_get(Some("thread"), "task")?;
    let wrong = sign(
        &f.human,
        "thread",
        "bad-update",
        TaskEventBody::Update(TaskUpdate {
            task_id: "task".into(),
            version: 2,
            state: TaskStatus::Done,
            steps: Vec::new(),
            result_ref: None,
        }),
    )?;
    assert!(!project(&f.agent, &wrong)?.accepted);
    assert_eq!(f.agent.task_get(Some("thread"), "task")?, before);
    assert_eq!(f.agent.task_history("thread", "task")?.events.len(), 1);
    Ok(())
}
#[test]
fn task_journal_contains_metadata_and_survives_a_reader_restart() -> TestResult {
    let f = Fixture::new()?;
    let c = sign(&f.human, "thread", "start", start("task", "thread"))?;
    assert!(project(&f.agent, &c)?.accepted);
    let journal = f.agent.account_db()?.journal_after(0, 128)?;
    let text = serde_json::to_string(&journal)?;
    assert!(!text.contains("Find the answer"));
    assert!(!text.contains("Use trusted sources"));
    assert!(text.contains("task.changed"));
    let mut reader = RamfluxClient::new();
    reader.active_account_db = Some(f.agent.account_db()?.open_reader()?);
    assert_eq!(reader.task_get(Some("thread"), "task")?["version"], 1);
    Ok(())
}

#[path = "decision_tests.rs"]
mod decisions;

#[test]
fn out_of_order_task_revisions_wait_durably_and_apply_after_the_missing_start() -> TestResult {
    let f = Fixture::new()?;
    let update = sign(
        &f.agent,
        "thread",
        "early-update",
        TaskEventBody::Update(TaskUpdate {
            task_id: "task".into(),
            version: 2,
            state: TaskStatus::Running,
            steps: Vec::new(),
            result_ref: None,
        }),
    )?;
    assert!(project(&f.human, &update)?.pending);
    assert_eq!(f.human.task_get(Some("thread"), "task")?, serde_json::Value::Null);
    let start = sign(&f.human, "thread", "start", start("task", "thread"))?;
    assert!(project(&f.human, &start)?.accepted);
    assert_eq!(f.human.retry_pending_tasks(crate::time::now_unix_timestamp())?, 1);
    assert_eq!(f.human.task_get(Some("thread"), "task")?["version"], 2);
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 0);
    Ok(())
}
#[test]
fn task_holdback_is_bounded_and_one_expired_task_does_not_block_another_conversation() -> TestResult
{
    let f = Fixture::new()?;
    for index in 0..8 {
        let c = sign(
            &f.agent,
            "thread",
            &format!("early-{index}"),
            TaskEventBody::Update(TaskUpdate {
                task_id: format!("missing-{index}"),
                version: 2,
                state: TaskStatus::Running,
                steps: Vec::new(),
                result_ref: None,
            }),
        )?;
        assert!(project(&f.human, &c)?.pending);
    }
    let overflow = sign(
        &f.agent,
        "thread",
        "overflow",
        TaskEventBody::Update(TaskUpdate {
            task_id: "overflow".into(),
            version: 2,
            state: TaskStatus::Running,
            steps: Vec::new(),
            result_ref: None,
        }),
    )?;
    assert!(project(&f.human, &overflow).is_err());
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 8);
    f.human.account_db()?.persist_client_record(
        "conversation",
        "other",
        &json!({"kind":"direct","participants":["human","agent"]}),
    )?;
    let c = sign(&f.human, "other", "valid-start", start("valid", "other"))?;
    assert!(project(&f.human, &c)?.accepted);
    f.human.retry_pending_tasks(crate::time::now_unix_timestamp() + 601)?;
    assert_eq!(f.human.account_db()?.task_state_usage("task/pending/")?.0, 0);
    assert_eq!(f.human.task_get(Some("other"), "valid")?["version"], 1);
    Ok(())
}
#[test]
fn an_envelope_clock_or_random_task_ids_cannot_bypass_principal_admission_limits() -> TestResult {
    let f = Fixture::new()?;
    for index in 0..128 {
        // Invalid assignee still consumes the principal budget, without creating task histories.
        let mut body = start(&format!("invalid-{index}"), "thread");
        if let TaskEventBody::Start(s) = &mut body {
            s.assignee = "outsider".into();
        }
        let c = sign(&f.human, "thread", &format!("invalid-{index}"), body)?;
        let result = f.agent.project_task_message(
            &Delivery {
                conversation: "thread",
                message: &c.message_id,
                principal: "human",
                device: "human-device",
                at: i64::MAX - i64::from(index),
            },
            &c.bytes()?,
        )?;
        assert!(!result.ok_or("task missing")?.accepted);
    }
    assert_eq!(f.agent.account_db()?.task_state_usage("task/history/")?.0, 0);
    assert!(
        project(
            &f.agent,
            &sign(&f.human, "thread", "over-budget", start("over-budget", "thread"))?
        )
        .is_err()
    );
    assert!(f.agent.account_db()?.task_state_usage("task/rejected/")?.0 <= 256);
    Ok(())
}

#[test]
fn proposal_acceptance_requires_a_member_distinct_from_both_proposer_and_assignee() -> TestResult {
    let f = Fixture::new()?;
    let third = client(&f.root.join("third"), "third", 81)?;
    for remote in [&f.human, &f.agent] {
        let d = remote.device_branch.as_ref().ok_or("device")?;
        let root = remote.identity_root.as_ref().ok_or("root")?;
        let commitment = crate::identity_root_public_key_commitment(
            &ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes()),
        )?;
        third.account_db()?.persist_client_record("device",&d.device_id,&json!({"principal_id":d.principal_id,"principal_commitment":commitment,"signing_public_key":ramflux_protocol::encode_base64url(d.signing_key.verifying_key().to_bytes())}))?;
    }
    third.create_group("group", "third-device")?;
    third.add_group_member("group", "human-device", "member")?;
    third.add_group_member("group", "agent-device", "member")?;
    third.account_db()?.persist_client_record(
        "conversation",
        "group-thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let TaskEventBody::Proposal(mut proposal) = proposal() else { return Err("proposal".into()) };
    proposal.conversation_id = "group-thread".into();
    proposal.assignee = "human".into();
    let proposed = sign(&f.agent, "group-thread", "proposed", TaskEventBody::Proposal(proposal))?;
    assert!(project(&third, &proposed)?.accepted);
    for actor in [&f.agent, &f.human] {
        let accept = sign(
            actor,
            "group-thread",
            &format!("accept-{}", actor.device_branch.as_ref().ok_or("device")?.principal_id),
            TaskEventBody::Accept(TaskAccept { task_id: "proposal".into(), version: 2 }),
        )?;
        assert!(!project(&third, &accept)?.accepted);
    }
    let accept = sign(
        &third,
        "group-thread",
        "third-accept",
        TaskEventBody::Accept(TaskAccept { task_id: "proposal".into(), version: 2 }),
    )?;
    assert!(project(&third, &accept)?.accepted);
    assert_eq!(third.task_get(Some("group-thread"), "proposal")?["requester"], "third");
    drop(third);
    Ok(())
}

#[path = "surface_tests.rs"]
mod surfaces;

#[path = "own_tests.rs"]
mod own;

#[path = "control_tests.rs"]
mod controls;

#[path = "holdback_tests.rs"]
mod holdback_regressions;
#[path = "lifecycle_tests.rs"]
mod lifecycle_regressions;
