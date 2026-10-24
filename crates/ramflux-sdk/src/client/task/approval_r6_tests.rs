// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pending and failed delivery receipts survive both retention tiers while jobs remain live.
use super::*;
use crate::client::task::approval_retention::{DeliveryState, Receipt};
#[test]
fn r6_an_inflight_receipt_survives_peer_and_account_retention_until_its_job_retires() -> TestResult
{
    for state in [DeliveryState::Pending, DeliveryState::Failed] {
        let f = Fixture::new()?;
        open(&f, "task")?;
        let request = request(&f)?;
        f.human.accept_task_approval(&request)?;
        let id = request.id()?;
        let scoped = format!("task_approval_{id}");
        f.human.decide_task_approval(&scoped, true)?;
        let db = f.human.account_db()?;
        let receipt_key = key("approval_receipt", &id);
        let mut receipt: Receipt = db.load_actor_state(&receipt_key)?.ok_or("receipt")?;
        receipt.delivery_state = state;
        receipt.updated_at = 0;
        db.persist_actor_state(&receipt_key, &receipt)?;
        for n in 0..64 {
            seed(&f, &receipt, n, "agent")?;
        }
        f.human.prune_task_approval_receipts()?;
        assert!(db.actor_state_exists(&receipt_key)?, "active receipt lost at peer retention");
        for peer in 0..8 {
            for n in 0..64 {
                seed(&f, &receipt, 1000 + peer * 64 + n, &format!("peer-{peer}"))?;
            }
        }
        f.human.prune_task_approval_receipts()?;
        assert!(db.actor_state_exists(&receipt_key)?, "active receipt lost at account retention");
        assert!(db.task_state_usage("task/approval_receipt/")?.0 <= 512);
        let retried = f.human.decide_task_approval(&scoped, true)?;
        assert_eq!(retried["delivery_state"], "pending");
        db.delete_task_state(&key("approval_decision_out", &id))?;
        receipt.expires_at = 1;
        db.persist_actor_state(&receipt_key, &receipt)?;
        f.human.prune_task_approval_receipts()?;
        assert!(!db.actor_state_exists(&receipt_key)?);
    }
    Ok(())
}
fn seed(f: &Fixture, template: &Receipt, n: u64, peer: &str) -> Result<(), SdkError> {
    let mut receipt = template.clone();
    receipt.request_id = format!("retained-{peer}-{n}");
    receipt.peer = peer.into();
    receipt.delivery_state = DeliveryState::Submitted;
    receipt.updated_at = i64::try_from(n).map_err(|_| invalid("index"))? + 1;
    f.human
        .account_db()?
        .persist_actor_state(&key("approval_receipt", &receipt.request_id), &receipt)?;
    Ok(())
}
