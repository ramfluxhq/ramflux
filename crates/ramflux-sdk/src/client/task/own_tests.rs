// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root task replicas retain exact carriers, pins, and committed single-use decisions.
use super::*;
use crate::prekey::{SdkDeviceManifestEntry, SdkDeviceManifestResponse};
fn manifest(c: &RamfluxClient) -> Result<SdkDeviceManifestResponse, SdkError> {
    let root = c.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let d = c.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let public = ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let commitment = crate::identity_root_public_key_commitment(&public)?;
    Ok(SdkDeviceManifestResponse {
        principal_id: d.principal_id.clone(),
        principal_commitment: commitment.clone(),
        root_public_key: public,
        devices: vec![SdkDeviceManifestEntry {
            principal_id: d.principal_id.clone(),
            principal_commitment: commitment,
            device_id: d.device_id.clone(),
            device_epoch: d.device_epoch,
            branch_public_key: ramflux_protocol::encode_base64url(
                d.signing_key.verifying_key().to_bytes(),
            ),
            target_delivery_id: d.device_id.clone(),
            branch_proof: ramflux_crypto::authorize_device_branch(
                root,
                d,
                "ramflux-node",
                vec!["device.delivery.bind".into()],
                1_700_000_000,
                4_000_000_000,
            )?,
            prekey_bundle: ramflux_crypto::create_prekey_bundle(
                d,
                &ramflux_crypto::X25519KeyPair::from_seed([21; 32]),
                "signed",
                &ramflux_crypto::X25519KeyPair::from_seed([22; 32]),
                None,
                None,
            )?,
            branch_authorized_event_id: "authorized".into(),
        }],
    })
}
fn manifests(f: &Fixture) -> Result<(), SdkError> {
    for owner in [&f.human, &f.agent] {
        let m = manifest(owner)?;
        for local in [&f.human, &f.agent] {
            local
                .account_db()?
                .persist_actor_state(&format!("identity/manifest/{}", m.principal_id), &m)?;
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
    let packets = f.agent.own_task_packets()?;
    assert_eq!(packets.len(), 1);
    sibling.import_own_task_packets(&packets, "agent-device")?;
    assert_eq!(sibling.task_get(Some("thread"), "task")?["version"], 3);
    assert_eq!(sibling.task_history("thread", "task")?.events.len(), 3);
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
    let packets = f.agent.own_task_packets()?;
    let mut sibling = client(&f.root.join("agent2"), "agent", 71)?;
    sibling.create_device_branch("agent", "agent2-device", 1, [75; 32]);
    assert!(sibling.import_own_task_packets(&packets[1..], "agent-device").is_err());
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
    let mut history = TaskHistory { events: Vec::new(), created_at: 1, updated_at: 80 };
    for version in 1..=80 {
        let c = if version == 1 {
            first.clone()
        } else {
            sign(
                &f.agent,
                "thread",
                &format!("update-{version}"),
                TaskEventBody::Update(TaskUpdate {
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
            actor_kind_verified: false,
            received_at: i64::try_from(version)?,
            decision_certificate: None,
        });
    }
    assert_eq!(history.state()?.task().ok_or("task")?.version, 80);
    f.agent.account_db()?.persist_actor_state(&scoped("history", "thread", "task")?, &history)?;
    let packets = f.agent.own_task_packets()?;
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
