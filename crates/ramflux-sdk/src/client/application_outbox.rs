// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT W1 adapter for application projection (S6b P16). No production caller reaches it:
//! live `project_committed_message` still swallows a claim failure and publishes to RAM, and
//! `claim_inbox_projection` still commits the projected flag in its own transaction. The
//! expectation values come from the caller; P20 supplies them and calls `admit_in` on the W1
//! transaction.
//!
//! Contract: W0 (`stage`) precedes admission. The authenticated projected marker (shared
//! `write_inbox_projection_claim_at`) and a DURABLE application outbox row commit on the
//! caller's open receive transaction. RAM publication is a replay from that outbox
//! (at-least-once into RAM, exactly-once per application marker). A seen/crypto Duplicate
//! still drains an unfinished projection (outbox present → replay). A failed claim or outbox
//! write rolls back, retains W0, and never yields a terminal ACK. The outbox carries envelope
//! identity already on the committed receipt, not extra plaintext. Footprint/erase/backup use
//! the existing `gateway/%` policy.
#![allow(dead_code)]

use crate::client::routed::Committed;
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, ReceiveExpectation, ReceiveStage, ReceiveStageResult, ReceiveTransaction,
    StorageError,
};
use serde::{Deserialize, Serialize};

/// Backup native/merge/archive already exclude `gateway/%`.
pub(crate) const OUTBOX: &str = "gateway/application-outbox/";

/// Envelope identity already persisted on the committed receipt. No extra plaintext.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplicationEvent {
    pub envelope_id: String,
    pub payload_hash: String,
    pub committed_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admit {
    Admitted,
    Duplicate,
}

pub(crate) struct AdmitRequest<'a> {
    pub sequence: u64,
    pub auth_key: &'a str,
    pub entry: &'a GatewayInboxEntry,
    pub message: Option<&'a str>,
    pub client: &'a RamfluxClient,
}

pub(crate) struct ApplicationOutbox<'a> {
    pub expected: ReceiveExpectation<'a>,
    /// The caller actor's current generation (the fence compares it with `expected.generation`).
    pub generation: u64,
}

impl ApplicationOutbox<'_> {
    pub(crate) fn stage(
        &self,
        db: &AccountDb,
        input: ReceiveStage<'_>,
    ) -> Result<ReceiveStageResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.stage(input))?)
    }

    /// Standalone admission when the caller is not already inside a receive transaction.
    pub(crate) fn admit(
        &self,
        db: &AccountDb,
        request: &AdmitRequest<'_>,
    ) -> Result<Admit, SdkError> {
        let mut outcome = None;
        let fenced = db.receive_transaction(self.expected, self.generation, |tx| {
            let result = self.admit_in(tx, request);
            let failed = result.is_err();
            outcome = Some(result);
            if failed {
                return Err(StorageError::Integrity("source effect failed"));
            }
            Ok(())
        });
        match (fenced, outcome) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(()), Some(Ok(value))) => Ok(value),
            (Ok(()), None) => {
                Err(SdkError::LocalBus("application outbox admit did not run".into()))
            }
        }
    }

    /// Admits on the caller's open W1 receive transaction (projected marker + outbox).
    /// P20 joins this with the W1 that writes the authenticated receipt.
    #[allow(clippy::unused_self)]
    pub(crate) fn admit_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        request: &AdmitRequest<'_>,
    ) -> Result<Admit, SdkError> {
        tx.require_writer()?;
        tx.require_open_input(request.sequence)?;
        live_checks(tx.account(), request.auth_key, request.entry)?;
        transfer(tx, request)
    }
}

fn outbox_key(auth_key: &str) -> String {
    format!("{OUTBOX}{auth_key}")
}

fn live_checks(db: &AccountDb, auth_key: &str, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    let Some(receipt) = db.load_actor_state::<Committed>(auth_key)? else {
        return Err(StorageError::Integrity("application projection receipt missing").into());
    };
    if receipt.entry.envelope.envelope_id != entry.envelope.envelope_id
        || receipt.entry.envelope.payload_hash != entry.envelope.payload_hash
    {
        return Err(StorageError::Integrity("application projection envelope is immutable").into());
    }
    Ok(())
}

fn transfer(tx: &ReceiveTransaction<'_>, request: &AdmitRequest<'_>) -> Result<Admit, SdkError> {
    let db = tx.account();
    let stored = outbox_key(request.auth_key);
    claim_fault()?;
    if db.actor_state_exists(&stored)? {
        let existing: ApplicationEvent = db
            .load_actor_state(&stored)?
            .ok_or(StorageError::Integrity("application outbox row missing"))?;
        if existing.envelope_id != request.entry.envelope.envelope_id
            || existing.payload_hash != request.entry.envelope.payload_hash
            || existing.committed_key != request.auth_key
        {
            return Err(
                StorageError::Integrity("application projection envelope is immutable").into()
            );
        }
        // Unfinished projection: the marker may already be set; drain by keeping the row.
        request.client.write_inbox_projection_claim_at(db, request.auth_key, request.entry)?;
        before_commit_fault()?;
        return Ok(Admit::Duplicate);
    }
    let newly =
        request.client.write_inbox_projection_claim_at(db, request.auth_key, request.entry)?;
    outbox_fault()?;
    let event = ApplicationEvent {
        envelope_id: request.entry.envelope.envelope_id.clone(),
        payload_hash: request.entry.envelope.payload_hash.clone(),
        committed_key: request.auth_key.to_owned(),
    };
    if let Some(message) = request.message {
        db.persist_message_actor_state(message, &stored, &event)?;
    } else {
        db.persist_actor_state(&stored, &event)?;
    }
    before_commit_fault()?;
    if newly { Ok(Admit::Admitted) } else { Ok(Admit::Duplicate) }
}

/// Rebuilds the RAM page from durable outbox rows. At-least-once into `pending`;
/// exactly-once per application marker.
pub(crate) fn replay(db: &AccountDb, pending: &mut Vec<GatewayInboxEntry>) -> Result<(), SdkError> {
    for key in db.actor_state_key_page(OUTBOX, 64)? {
        let event: ApplicationEvent = db
            .load_actor_state(&key)?
            .ok_or_else(|| SdkError::LocalBus("application outbox row missing".into()))?;
        let Some(receipt) = db.load_actor_state::<Committed>(&event.committed_key)? else {
            continue;
        };
        publish_application_entry(pending, &receipt.entry);
    }
    Ok(())
}

pub(crate) fn publish_application_entry(
    pending: &mut Vec<GatewayInboxEntry>,
    entry: &GatewayInboxEntry,
) {
    if pending.iter().any(|pending| pending.envelope == entry.envelope) {
        return;
    }
    pending.push(entry.clone());
    if pending.len() > 64 {
        pending.remove(0);
    }
}

fn claim_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::Claim) {
        return Err(StorageError::Integrity("application projection claim failed"));
    }
    Ok(())
}

fn outbox_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::Outbox) {
        return Err(StorageError::Integrity("application projection outbox failed"));
    }
    Ok(())
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("application projection before-commit"));
    }
    Ok(())
}

fn current_fault() -> Fault {
    #[cfg(test)]
    {
        FAULT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        Fault::None
    }
}

/// In-transaction fault injected by tests. Production always uses `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    None,
    Claim,
    Outbox,
    BeforeCommit,
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: Fault, f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|cell| cell.set(Fault::None));
        }
    }
    FAULT.with(|cell| cell.set(fault));
    let _reset = Reset;
    f()
}

#[cfg(test)]
#[path = "application_outbox/projection_stage_redrive_tests.rs"]
pub(crate) mod projection_stage_redrive;
#[cfg(test)]
#[path = "application_outbox/projection_write_failure_tests.rs"]
pub(crate) mod projection_write_failure;
