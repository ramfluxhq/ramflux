// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated decision provenance survives compact receipts and legacy reads fail closed.
use super::*;
use crate::client::task::approval_retention::DeliveryState;

#[test]
fn verified_task_decision_signer_is_retained_for_approved_and_denied_receipts() -> Case {
    for approved in [true, false] {
        let (root, mut agent, human) = pair("approval-signer")?;
        open_named(&human, &agent, "task", "grant")?;
        pending(&mut agent, "approval", "grant")?;
        let request = request_job(&agent, "task")?;
        let decision = decide(&human, &request.packet, approved)?;
        let signer =
            json!({"principal_id":decision.packet.principal,"device_id":decision.packet.device});
        let requester = human.client.task_get(Some("thread"), "task")?;
        assert_eq!(requester["approval_decisions"][0]["decided_by"], signer);
        agent.client.accept_task_approval(&decision.packet)?;
        apply_decisions(&mut agent)?;
        let executor = agent.client.task_get(Some("thread"), "task")?;
        let row = &executor["approval_decisions"][0];
        assert_eq!(row["status"], if approved { "approved" } else { "denied" });
        assert_eq!(row["delivery_state"], "applied");
        assert_eq!(
            row["decided_by"], signer,
            "the read model must retain the verified packet signer"
        );
        assert_eq!(agent.mcp_grants.contains_key("grant"), approved);
        drop(human);
        drop(agent);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn legacy_task_decision_receipt_never_infers_a_signer_during_read_or_delivery_update() -> Case {
    let (root, mut agent, human) = pair("approval-legacy-signer")?;
    open_named(&human, &agent, "task", "grant")?;
    pending(&mut agent, "approval", "grant")?;
    let request = request_job(&agent, "task")?;
    let decision = decide(&human, &request.packet, false)?;
    agent.client.accept_task_approval(&decision.packet)?;
    apply_decisions(&mut agent)?;
    let id = decision.packet.id()?;
    let storage = key("approval_receipt", &id);
    let db = agent.client.account_db()?;
    let mut old: Value = db.load_actor_state(&storage)?.ok_or("receipt")?;
    old.as_object_mut().ok_or("receipt object")?.remove("decided_by");
    db.persist_actor_state(&storage, &old)?;
    let row = agent.client.task_get(Some("thread"), "task")?;
    assert!(row["approval_decisions"][0].get("decided_by").is_none());
    agent.client.record_task_approval_delivery(&decision.packet, DeliveryState::Submitted, None)?;
    let row = agent.client.task_get(Some("thread"), "task")?;
    assert!(
        row["approval_decisions"][0].get("decided_by").is_none(),
        "a legacy receipt must remain unproven"
    );
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn unverified_task_decision_packet_cannot_publish_signer_provenance() -> Case {
    let (root, mut agent, human) = pair("approval-forged-signer")?;
    open_named(&human, &agent, "task", "grant")?;
    pending(&mut agent, "approval", "grant")?;
    let request = request_job(&agent, "task")?;
    let decision = decide(&human, &request.packet, false)?;
    let mut forged = decision.packet.clone();
    forged.signature = "invalid".into();
    assert!(agent.client.accept_task_approval(&forged).is_err());
    apply_decisions(&mut agent)?;
    let row = agent.client.task_get(Some("thread"), "task")?;
    assert_eq!(row["approval_decisions"], json!([]));
    assert!(
        !agent.client.account_db()?.actor_state_exists(&key("approval_receipt", &forged.id()?))?
    );
    agent.client.accept_task_approval(&decision.packet)?;
    apply_decisions(&mut agent)?;
    let row = agent.client.task_get(Some("thread"), "task")?;
    assert_eq!(row["approval_decisions"][0]["decided_by"]["device_id"], decision.packet.device);
    drop(human);
    drop(agent);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
