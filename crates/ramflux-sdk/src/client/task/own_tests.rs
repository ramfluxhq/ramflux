// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root task replicas retain exact carriers, pins, and committed single-use decisions.
use super::*;
use crate::prekey::SdkDeviceManifestResponse;
pub(crate) fn manifest(c: &RamfluxClient) -> Result<SdkDeviceManifestResponse, SdkError> {
    crate::client::identity_authority::test_support::public_manifest(c)
}
pub(super) fn manifests(f: &Fixture) -> Result<(), SdkError> {
    for owner in [&f.human, &f.agent] {
        let m = manifest(owner)?;
        for local in [&f.human, &f.agent] {
            local.persist_identity_directory(&m)?;
        }
    }
    Ok(())
}
#[test]
fn own_device_task_history_replays_verified_carriers_and_committed_decisions_idempotently()
-> TestResult {
    let f = Fixture::new()?;
    manifests(&f)?;
    decisions::open(&f, "task")?;
    decisions::store(&f, &decisions::grant(&f)?)?;
    let intent = sign(
        &f.human,
        "thread",
        "intent",
        TaskEventBody::Resolve(decisions::resolution(
            "task",
            ramflux_protocol::TaskDecision::Resume,
        )),
    )?;
    assert!(project(&f.agent, &intent)?.accepted);
    let mut sibling = client(&f.root.join("agent2"), "agent", 71)?;
    sibling.create_device_branch("agent", "agent2-device", 1, [75; 32]);
    let packets = f.agent.own_task_packets("agent2-device")?;
    assert_eq!(packets.len(), 1);
    sibling.import_own_task_packets(&packets, "agent-device")?;
    assert_eq!(sibling.task_get(Some("thread"), "task")?["version"], 3);
    assert_eq!(sibling.task_history("thread", "task")?.events.len(), 3);
    for accepted in &sibling.task_history("thread", "task")?.events {
        let message = super::super::timeline_id(&accepted.carrier)?;
        let metadata =
            sibling.task_message_metadata("thread", &message)?.ok_or("task row metadata")?;
        assert_eq!(metadata["content_type"], "task");
        assert_eq!(metadata["task_id"], "task");
        assert!(sibling.direct_message_by_id(&message)?.is_some());
    }

    sibling.import_own_task_packets(&packets, "agent-device")?;
    assert_eq!(sibling.task_history("thread", "task")?.events.len(), 3);
    let key = f
        .agent
        .task_history("thread", "task")?
        .events
        .last()
        .and_then(|e| e.decision_certificate.as_ref())
        .ok_or("certificate")?
        .decision_key
        .clone();
    assert!(sibling.account_db()?.load_actor_state::<serde_json::Value>(&key)?.is_some());
    assert_eq!(
        sibling.account_db()?.task_state_usage("task/forward/")?.0,
        0,
        "imported snapshots must not echo"
    );
    drop(sibling);
    Ok(())
}
#[test]
fn own_device_history_pages_fit_the_transport_budget_and_require_the_causal_prefix() -> TestResult {
    let f = Fixture::new()?;
    manifests(&f)?;
    assert!(
        project(&f.agent, &sign(&f.human, "thread", "start", start("task", "thread"))?)?.accepted
    );
    for version in 2..=10 {
        let c = sign(
            &f.agent,
            "thread",
            &format!("update-{version}"),
            TaskEventBody::Update(TaskUpdate {
                result_summary: None,
                task_id: "task".into(),
                version,
                state: TaskStatus::Running,
                steps: (0..64)
                    .map(|i| TaskStep {
                        id: format!("step-{i}"),
                        title: "x".repeat(128),
                        state: TaskStatus::Running,
                        needs_me: None,
                    })
                    .collect(),
                result_ref: None,
            }),
        )?;
        assert!(project(&f.agent, &c)?.accepted);
    }
    let history = f.agent.task_history("thread", "task")?;
    let last = &history.events.last().ok_or("history")?.carrier;
    let pages = f.agent.task_own_packets(last)?;
    assert!(pages.len() > 1);
    assert!(pages.iter().all(|p| p.len() <= super::super::MAX_DELIVERY_BYTES));
    let packets = f.agent.own_task_packets("agent2-device")?;
    let mut sibling = client(&f.root.join("agent2"), "agent", 71)?;
    sibling.create_device_branch("agent", "agent2-device", 1, [75; 32]);
    sibling.import_own_task_packets(&packets[1..], "agent-device")?;
    assert_ne!(sibling.account_db()?.task_state_usage("task/import_skip/")?.0, 0);
    assert!(sibling.task_get(Some("thread"), "task")?.is_null());
    sibling.import_own_task_packets(&packets, "agent-device")?;
    assert_eq!(sibling.task_get(Some("thread"), "task")?["version"], 10);
    drop(sibling);
    Ok(())
}

#[test]
fn importing_old_verified_history_does_not_charge_eighty_events_as_new_peer_traffic() -> TestResult
{
    let f = Fixture::new()?;
    manifests(&f)?;
    let first = sign(&f.human, "thread", "start", start("task", "thread"))?;
    let mut history =
        TaskHistory { events: Vec::new(), created_at: 1, updated_at: 80, ..TaskHistory::default() };
    for version in 1..=80 {
        let c = if version == 1 {
            first.clone()
        } else {
            sign(
                &f.agent,
                "thread",
                &format!("update-{version}"),
                TaskEventBody::Update(TaskUpdate {
                    result_summary: None,
                    task_id: "task".into(),
                    version,
                    state: TaskStatus::Running,
                    steps: Vec::new(),
                    result_ref: None,
                }),
            )?
        };
        let public = f.agent.task_signer_key(&c.principal_id, &c.device_id)?;
        history.events.push(AcceptedEvent {
            carrier: c,
            public_key: public,
            actor_kind_verified: actor_kind_verified(&f.agent, "human", "human-device"),
            received_at: i64::try_from(version)?,
            decision_certificate: None,
            membership: None,
        });
    }
    assert_eq!(history.state()?.task().ok_or("task")?.version, 80);
    f.agent.account_db()?.persist_actor_state(&scoped("history", "thread", "task")?, &history)?;
    let packets = f.agent.own_task_packets("agent2-device")?;
    let mut sibling = client(&f.root.join("agent2"), "agent", 71)?;
    sibling.create_device_branch("agent", "agent2-device", 1, [75; 32]);
    sibling.import_own_task_packets(&packets, "agent-device")?;
    assert_eq!(sibling.task_get(Some("thread"), "task")?["version"], 80);
    assert_eq!(sibling.account_db()?.task_state_usage("task/rate/")?.0, 0);
    drop(sibling);
    Ok(())
}

#[test]
fn own_device_snapshot_exports_task_packets_without_duplicate_transport_message_rows() -> TestResult
{
    let f = Fixture::new()?;
    manifests(&f)?;
    let c = sign(&f.human, "thread", "task-logical", start("task", "thread"))?;
    f.agent.send_direct_message("thread", "transport-row", "human-device", b"ciphertext")?;
    let outcome = f
        .agent
        .project_task_message(
            &Delivery {
                conversation: "thread",
                message: "transport-row",
                principal: "human",
                device: "human-device",
                at: 1,
            },
            &c.bytes()?,
        )?
        .ok_or("projection")?;
    assert!(outcome.accepted);
    f.agent.send_direct_message("thread", "ordinary-row", "human-device", b"ordinary")?;
    let commitment = manifest(&f.agent)?.principal_commitment;
    let bundle = f.agent.own_device_history_bundle(
        &commitment,
        "agent-device",
        "agent2-device",
        "snapshot",
    )?;
    assert_eq!(bundle.messages.len(), 1);
    assert_eq!(bundle.messages[0].message_id, "ordinary-row");
    assert_eq!(bundle.task_packets.len(), 1);
    assert!(!bundle.contents.contains_key("transport-row"));
    Ok(())
}

#[test]
fn later_blocking_a_contact_does_not_reject_its_previously_committed_task_history() -> TestResult {
    let f = Fixture::new()?;
    manifests(&f)?;
    assert!(
        project(&f.agent, &sign(&f.human, "thread", "start", start("task", "thread"))?)?.accepted
    );
    f.agent.account_db()?.establish_friend_link("link", "agent", "human")?;
    f.agent.account_db()?.block_friend_link("link", crate::time::now_unix_timestamp())?;
    let packets = f.agent.own_task_packets("agent2-device")?;
    let mut sibling = client(&f.root.join("agent2"), "agent", 71)?;
    sibling.create_device_branch("agent", "agent2-device", 1, [75; 32]);
    sibling.account_db()?.establish_friend_link("link", "agent", "human")?;
    sibling.account_db()?.block_friend_link("link", crate::time::now_unix_timestamp())?;
    sibling.import_own_task_packets(&packets, "agent-device")?;
    assert_eq!(sibling.task_get(Some("thread"), "task")?["requester"], "human");
    assert_eq!(sibling.account_db()?.friend_link("link")?.state, "blocked");
    let live = sign(&f.human, "thread", "new-task", start("new-task", "thread"))?;
    assert!(project(&sibling, &live).is_err());
    drop(sibling);
    Ok(())
}
#[test]
fn departed_group_participants_remain_valid_in_witnessed_history_without_regaining_membership()
-> TestResult {
    let f = Fixture::new()?;
    manifests(&f)?;
    f.agent.create_group("group", "agent-device")?;
    f.agent.add_group_member("group", &member(&f.agent, "human-device")?, "member")?;
    f.agent.account_db()?.persist_client_record(
        "conversation",
        "group-thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let event = sign(&f.human, "group-thread", "start", start("task", "group-thread"))?;
    assert!(project(&f.agent, &event)?.accepted);
    f.agent.remove_group_member("group", "agent-device", "human-device")?;
    let packets = f.agent.own_task_packets("agent2-device")?;
    assert_eq!(packets.len(), 1);
    let mut sibling = client(&f.root.join("agent2"), "agent", 71)?;
    sibling.create_device_branch("agent", "agent2-device", 1, [75; 32]);
    sibling.import_own_task_packets(&packets, "agent-device")?;
    assert_eq!(sibling.task_get(Some("group-thread"), "task")?["requester"], "human");
    assert!(
        sibling
            .account_db()?
            .group_member_role("group", &f.human.owned_device_identity()?)?
            .is_none()
    );
    assert!(
        sibling
            .account_db()?
            .group_member_key_binding("group", &f.human.owned_device_identity()?)?
            .is_none()
    );
    assert!(
        project(
            &sibling,
            &sign(&f.human, "group-thread", "new-task", start("new-task", "group-thread"))?
        )
        .is_err()
    );
    drop(sibling);
    Ok(())
}
#[test]
fn a_bad_own_task_item_is_recorded_and_does_not_block_other_histories() -> TestResult {
    let f = Fixture::new()?;
    manifests(&f)?;
    assert!(
        project(&f.agent, &sign(&f.human, "thread", "start", start("task", "thread"))?)?.accepted
    );
    let packets = f.agent.own_task_packets("agent2-device")?;
    let mut bad = serde_json::to_value(&packets[0])?;
    bad["history"]["events"][0]["carrier"]["signature"] = json!("invalid");
    let bad = serde_json::from_value(bad)?;
    let mut sibling = client(&f.root.join("agent2"), "agent", 71)?;
    sibling.create_device_branch("agent", "agent2-device", 1, [75; 32]);
    sibling.import_own_task_packets(&[bad, packets[0].clone()], "agent-device")?;
    assert_eq!(sibling.task_get(Some("thread"), "task")?["version"], 1);
    assert_eq!(sibling.account_db()?.task_state_usage("task/import_skip/")?.0, 1);
    drop(sibling);
    Ok(())
}
fn seed_legacy_terminal_histories(f: &Fixture, total: usize) -> Result<(), SdkError> {
    f.agent.account_db()?.write_transaction(|| {
        for index in 0..total {
            let id = format!("legacy-{index}");
            let events = [
                sign(&f.human, "thread", &format!("start-{index}"), start(&id, "thread"))?,
                sign(
                    &f.human,
                    "thread",
                    &format!("cancel-{index}"),
                    TaskEventBody::Cancel(ramflux_protocol::TaskCancel {
                        task_id: id.clone(),
                        base_revision: 1,
                    }),
                )?,
            ]
            .into_iter()
            .map(|c| {
                Ok(AcceptedEvent {
                    public_key: f.agent.task_signer_key(&c.principal_id, &c.device_id)?,
                    carrier: c,
                    actor_kind_verified: actor_kind_verified(&f.human, "human", "human-device"),
                    received_at: crate::time::now_unix_timestamp(),
                    decision_certificate: None,
                    membership: None,
                })
            })
            .collect::<Result<Vec<_>, SdkError>>()?;
            let history = TaskHistory {
                events,
                checkpoint: None,
                created_at: 1,
                updated_at: crate::time::now_unix_timestamp(),
            };
            f.agent
                .account_db()?
                .persist_actor_state(&scoped("history", "thread", &id)?, &history)?;
        }
        Ok(())
    })
}
#[test]
fn accounts_with_over_one_hundred_and_one_thousand_tasks_still_export_bounded_new_device_snapshots()
-> TestResult {
    for total in [101, 1001] {
        let f = Fixture::new()?;
        manifests(&f)?;
        seed_legacy_terminal_histories(&f, total)?;
        f.agent.send_direct_message("thread", "ordinary", "human-device", b"ordinary history")?;
        let commitment = manifest(&f.agent)?.principal_commitment;
        let bundle = f.agent.own_device_history_bundle(
            &commitment,
            "agent-device",
            "agent2-device",
            "snapshot",
        )?;
        assert_eq!(bundle.messages.len(), 1);
        assert_eq!(bundle.messages[0].message_id, "ordinary");
        assert!(!bundle.task_packets.is_empty());
        assert!(bundle.task_packets.len() <= 100);
        assert!(serde_json::to_vec(&bundle.task_packets)?.len() <= 4 * 1024 * 1024);
        let mut sibling = client(&f.root.join("agent2"), "agent", 71)?;
        sibling.create_device_branch("agent", "agent2-device", 1, [75; 32]);
        sibling.import_own_task_packets(&bundle.task_packets, "agent-device")?;
        assert_ne!(sibling.account_db()?.task_state_usage("task/view/")?.0, 0);
        if total == 1001 {
            assert!(bundle.task_export_metadata.truncated);
            assert!(bundle.task_export_metadata.next_cursor.is_some());
        }
        drop(sibling);
    }
    Ok(())
}

#[test]
fn task_export_pages_advance_independently_for_each_target_device() -> TestResult {
    let f = Fixture::new()?;
    manifests(&f)?;
    f.agent.account_db()?.write_transaction(|| {
        for index in 0..101 {
            let id = format!("export-{index}");
            let c = sign(&f.human, "thread", &id, start(&id, "thread"))?;
            let history = TaskHistory {
                events: vec![AcceptedEvent {
                    public_key: f.agent.task_signer_key(&c.principal_id, &c.device_id)?,
                    carrier: c,
                    actor_kind_verified: false,
                    received_at: 1,
                    decision_certificate: None,
                    membership: None,
                }],
                created_at: 1,
                updated_at: 1,
                ..TaskHistory::default()
            };
            f.agent
                .account_db()?
                .persist_actor_state(&scoped("history", "thread", &id)?, &history)?;
        }
        Ok::<_, SdkError>(())
    })?;
    let first_a = f.agent.own_task_packets("target-a")?;
    let first_b = f.agent.own_task_packets("target-b")?;
    assert_eq!(first_a.len(), 100);
    assert_eq!(serde_json::to_value(&first_a)?, serde_json::to_value(&first_b)?);
    let second_a = f.agent.own_task_packets("target-a")?;
    assert_eq!(second_a.len(), 1);
    assert_ne!(serde_json::to_value(&first_a[0])?, serde_json::to_value(&second_a[0])?);
    Ok(())
}
#[test]
fn a_bundle_cannot_claim_membership_at_an_epoch_the_receiver_validated_without_that_actor()
-> TestResult {
    let f = Fixture::new()?;
    manifests(&f)?;
    let excluded = client(&f.root.join("excluded"), "excluded", 81)?;
    f.agent.persist_identity_directory(&manifest(&excluded)?)?;
    f.agent.create_group("group", "agent-device")?;
    f.agent.add_group_member("group", &member(&f.agent, "excluded-device")?, "member")?;
    f.agent.create_signed_group_member_kick(
        "group",
        "agent-device",
        "excluded-device",
        "leave before human",
    )?;
    f.agent.add_group_member("group", &member(&f.agent, "human-device")?, "member")?;
    f.agent.account_db()?.persist_client_record(
        "conversation",
        "group-thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    assert!(
        project(
            &f.agent,
            &sign(&f.human, "group-thread", "start", start("task", "group-thread"))?
        )?
        .accepted
    );
    let packets = f.agent.own_task_packets("agent2-device")?;
    let mut raw = serde_json::to_value(&packets[0])?;
    raw["history"]["events"][0]["membership"]["epoch"] = json!(3);
    let packet: own_history::TaskOwnPacket = serde_json::from_value(raw)?;
    let mut sibling = client(&f.root.join("agent2"), "agent", 71)?;
    sibling.create_device_branch("agent", "agent2-device", 1, [75; 32]);
    sibling.persist_identity_directory(&manifest(&f.human)?)?;
    sibling.persist_identity_directory(&manifest(&excluded)?)?;
    sibling.create_group("group", "agent2-device")?;
    sibling.add_group_member("group", &member(&sibling, "excluded-device")?, "member")?;
    sibling.create_signed_group_member_kick(
        "group",
        "agent2-device",
        "excluded-device",
        "leave before human",
    )?;
    sibling.add_group_member("group", &member(&sibling, "human-device")?, "member")?;
    sibling.import_own_task_packets(&[packet], "agent-device")?;
    assert!(sibling.task_get(Some("group-thread"), "task")?.is_null());
    assert_eq!(sibling.account_db()?.task_state_usage("task/import_skip/")?.0, 1);
    // The same real signed task is valid at epoch 4; the original unmodified packet still imports.
    sibling.import_own_task_packets(&packets, "agent-device")?;
    assert_eq!(sibling.task_get(Some("group-thread"), "task")?["requester"], "human");
    drop(sibling);
    Ok(())
}
