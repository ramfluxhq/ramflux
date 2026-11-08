// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT W1 adapter for durable reply admission (S6b P17). No production caller reaches it:
//! live `take_surface_resync_answer` still consumes the queued answer, and
//! `connection_manager` still best-effort submits a RAM pair-reset envelope. The expectation
//! values come from the caller; P20 supplies them.
//!
//! Contract: W0 (`stage`) precedes admission. An authenticated-input-keyed transfer marker and
//! an IMMUTABLE prepared courier envelope are committed before response state is removed.
//! Bounded couriers send and retry that unchanged envelope (S6a P7 / P14 `submit_accepted`).
//! A full outbox refuses and retains W0 as held. Never persist plaintext to make a step
//! resumable. Network send is not in the transaction.
#![allow(dead_code)]

use crate::prelude::*;
use ramflux_protocol::Envelope;
use ramflux_storage::{
    AccountDb, ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError,
};
use serde::{Deserialize, Serialize};

/// Existing courier reply cap (`MAX_REPLIES` on the surface window).
pub(crate) const MAX_OUTBOX: u32 = 256;
/// Backup native/merge/archive already exclude `gateway/%`.
pub(crate) const OUTBOX: &str = "gateway/reply-outbox/";
pub(crate) const MARKER: &str = "gateway/reply-transferred/";

/// One immutable prepared courier envelope per authenticated receive input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedReply {
    pub envelope_id: String,
    pub envelope: Envelope,
    pub kind: ReplyKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReplyKind {
    Surface,
    Pair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admit {
    Admitted,
    Duplicate,
}

pub(crate) struct AdmitRequest<'a> {
    pub sequence: u64,
    pub auth_key: &'a str,
    pub envelope: Envelope,
    pub kind: ReplyKind,
    pub response_key: Option<&'a str>,
    pub message: Option<&'a str>,
}

pub(crate) struct ReplyOutbox<'a> {
    pub expected: ReceiveExpectation<'a>,
    /// The caller actor's current generation (the fence compares it with `expected.generation`).
    pub generation: u64,
}

impl ReplyOutbox<'_> {
    pub(crate) fn stage(
        &self,
        db: &AccountDb,
        input: ReceiveStage<'_>,
    ) -> Result<ReceiveStageResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.stage(input))?)
    }

    /// Admits `envelope` under `auth_key` and then removes `response_key` in the same
    /// receive transaction. A present marker is Duplicate and never rewrites the envelope.
    pub(crate) fn admit(
        &self,
        db: &AccountDb,
        request: AdmitRequest<'_>,
    ) -> Result<Admit, SdkError> {
        // BtF: a committed remove *before* the admission transaction loses the reply on crash.
        if remove_response_before_admission() {
            if let Some(key) = request.response_key {
                db.remove_actor_state(key)?;
            }
            return Err(SdkError::Storage(StorageError::Integrity(
                "reply outbox removed response before admission",
            )));
        }
        Ok(db.receive_transaction(self.expected, self.generation, |tx| {
            tx.require_open_input(request.sequence)?;
            transfer(db, request)
        })?)
    }
}

fn outbox_key(auth_key: &str) -> String {
    format!("{OUTBOX}{auth_key}")
}

fn marker_key(auth_key: &str) -> String {
    format!("{MARKER}{auth_key}")
}

fn transfer(db: &AccountDb, request: AdmitRequest<'_>) -> Result<Admit, StorageError> {
    let stored = outbox_key(request.auth_key);
    let marker = marker_key(request.auth_key);
    if db.actor_state_exists(&marker)? {
        let existing: PreparedReply = db
            .load_actor_state(&marker)?
            .ok_or(StorageError::Integrity("reply outbox marker missing envelope"))?;
        if existing.envelope != request.envelope || existing.kind != request.kind {
            return Err(StorageError::Integrity("reply outbox envelope is immutable"));
        }
        before_commit_fault()?;
        return Ok(Admit::Duplicate);
    }
    if db.actor_state_usage(OUTBOX)?.0 >= u64::from(MAX_OUTBOX) {
        return Err(StorageError::Integrity("reply outbox is full"));
    }
    let prepared = PreparedReply {
        envelope_id: request.envelope.envelope_id.clone(),
        envelope: request.envelope,
        kind: request.kind,
    };
    if let Some(message) = request.message {
        db.persist_message_actor_state(message, &stored, &prepared)?;
        db.persist_message_actor_state(message, &marker, &prepared)?;
    } else {
        db.persist_actor_state(&stored, &prepared)?;
        db.persist_actor_state(&marker, &prepared)?;
    }
    if let Some(key) = request.response_key {
        db.remove_actor_state(key)?;
    }
    before_commit_fault()?;
    Ok(Admit::Admitted)
}

/// Couriers load the next unchanged envelope. Network send stays outside the actor.
pub(crate) fn due(db: &AccountDb) -> Result<Option<(String, PreparedReply)>, SdkError> {
    let Some(key) = db.actor_state_key_page(OUTBOX, 1)?.into_iter().next() else {
        return Ok(None);
    };
    let reply: PreparedReply = db
        .load_actor_state(&key)?
        .ok_or_else(|| SdkError::LocalBus("reply outbox row missing".into()))?;
    let auth_key = key
        .strip_prefix(OUTBOX)
        .ok_or_else(|| SdkError::LocalBus("reply outbox key prefix".into()))?
        .to_owned();
    Ok(Some((auth_key, reply)))
}

/// Submit acknowledgement retires the outbox row and keeps the transfer marker.
pub(crate) fn acknowledge(db: &AccountDb, auth_key: &str) -> Result<(), SdkError> {
    db.write_transaction(|| {
        db.remove_actor_state(&outbox_key(auth_key))?;
        Ok::<(), StorageError>(())
    })?;
    Ok(())
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("reply outbox before-commit"));
    }
    Ok(())
}

fn remove_response_before_admission() -> bool {
    #[cfg(test)]
    {
        REMOVE_BEFORE.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
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
    BeforeCommit,
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static REMOVE_BEFORE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
pub(crate) fn with_remove_before_admission<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REMOVE_BEFORE.with(|cell| cell.set(false));
        }
    }
    REMOVE_BEFORE.with(|cell| cell.set(true));
    let _reset = Reset;
    f()
}

#[cfg(test)]
mod reply_outbox_crash_tests;
#[cfg(test)]
mod reply_stage_redrive_tests;
