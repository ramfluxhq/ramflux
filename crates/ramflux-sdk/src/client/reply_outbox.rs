// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT W1 adapter for durable reply admission (S6b P17). No production caller reaches it:
//! live `take_surface_resync_answer` still consumes the queued answer, and
//! `connection_manager` still best-effort submits a RAM pair-reset envelope. The expectation
//! values come from the caller; P20 supplies them and calls `admit_in` on the W1 transaction.
//!
//! Contract: W0 (`stage`) precedes admission. An authenticated-input-keyed transfer marker
//! (envelope id + digest) and an IMMUTABLE prepared courier envelope are committed on the
//! caller's open receive transaction before response state is removed. Bounded couriers send
//! and retry that unchanged envelope (S6a P7 / P14 `submit_accepted`). A full outbox returns
//! `OutboxFull` and retains W0 as held. Markers count toward `MAX_OUTBOX` (256 combined
//! outbox+marker rows after both writes) and are pruned with W0 terminal settlement, never
//! at courier ack. Never persist plaintext to make a step resumable. Network send is not
//! in the transaction.
#![allow(dead_code)]

use crate::client::routed::Opened;
use crate::client::surface::ResyncReply;
use crate::prelude::*;
use ramflux_protocol::Envelope;
use ramflux_storage::{
    AccountDb, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult, ReceiveExpectation,
    ReceiveStage, ReceiveStageResult, ReceiveTransaction, StorageError,
};
use serde::{Deserialize, Serialize};

/// Existing courier reply cap (`MAX_REPLIES` on the surface window). Combined outbox+marker rows.
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

/// Digest-only transfer marker. The courier outbox holds the envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferMarker {
    pub envelope_id: String,
    pub digest: String,
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
    OutboxFull,
}

pub(crate) struct AdmitRequest<'a> {
    pub sequence: u64,
    pub auth_key: &'a str,
    pub envelope: Envelope,
    pub kind: ReplyKind,
    pub response_key: Option<&'a str>,
    pub message: Option<&'a str>,
    pub client: &'a RamfluxClient,
    pub pair: Option<PairLive<'a>>,
    /// Surface BUILD signs through this session; pair prepare uses [`PairLive::config`].
    pub config: Option<&'a GatewaySessionConfig>,
}

/// Inputs so pair admission calls `prepare_received_pair_reply` rather than trusting the envelope.
pub(crate) struct PairLive<'a> {
    pub config: &'a GatewaySessionConfig,
    pub opened: &'a Opened,
    pub body: &'a [u8],
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

    /// Standalone admission for tests. Production callers use [`Self::admit_in`].
    #[cfg(test)]
    pub(crate) fn admit(
        &self,
        db: &AccountDb,
        request: AdmitRequest<'_>,
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
            (Ok(()), None) => Err(SdkError::LocalBus("reply outbox admit did not run".into())),
        }
    }

    /// Admits on the caller's open W1 receive transaction (marker + envelope + response
    /// removal). P20 joins this with the W1 that creates the reply.
    #[allow(clippy::unused_self)]
    pub(crate) fn admit_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        request: AdmitRequest<'_>,
    ) -> Result<Admit, SdkError> {
        tx.require_writer()?;
        tx.require_open_input(request.sequence)?;
        if tx.account().actor_state_exists(&marker_key(request.auth_key))? {
            before_commit_fault()?;
            return Ok(Admit::Duplicate);
        }
        let request = if let Some(envelope) = live_checks(&request, tx)? {
            AdmitRequest { envelope, ..request }
        } else {
            request
        };
        transfer(tx, request)
    }

    /// W0 terminal cover and marker prune in one writer transaction.
    pub(crate) fn settle_terminal(
        &self,
        db: &AccountDb,
        sequence: u64,
        auth_key: &str,
    ) -> Result<(), SdkError> {
        db.receive_transaction(self.expected, self.generation, |tx| {
            prune_on_terminal(tx, sequence, auth_key)
        })?;
        Ok(())
    }
}

fn outbox_key(auth_key: &str) -> String {
    format!("{OUTBOX}{auth_key}")
}

fn marker_key(auth_key: &str) -> String {
    format!("{MARKER}{auth_key}")
}

fn digest(envelope: &Envelope) -> Result<String, StorageError> {
    let bytes = serde_json::to_vec(envelope)?;
    Ok(format!("{}", blake3::hash(&bytes).to_hex()))
}

fn live_checks(
    request: &AdmitRequest<'_>,
    tx: &ReceiveTransaction<'_>,
) -> Result<Option<Envelope>, SdkError> {
    match request.kind {
        ReplyKind::Surface => {
            let key = request
                .response_key
                .ok_or(StorageError::Integrity("reply outbox surface requires a queued reply"))?;
            let db = tx.account();
            let Some(stored) = db.load_actor_state::<serde_json::Value>(key)? else {
                return Err(StorageError::Integrity("reply outbox surface reply missing").into());
            };
            let reply: ResyncReply = serde_json::from_value(stored)?;
            if reply.destination.expires_at <= now_unix_timestamp() {
                return Err(StorageError::Integrity("reply outbox surface expired").into());
            }
            request.client.validate_surface_resync_reply(&reply)?;
            if request.envelope.target_delivery_id != reply.destination.target {
                return Err(
                    StorageError::Integrity("reply outbox surface destination mismatch").into()
                );
            }
            let config = request
                .config
                .ok_or(StorageError::Integrity("reply outbox surface requires session config"))?;
            Ok(Some(request.client.surface_resync_reply_envelope(config, &reply)?))
        }
        ReplyKind::Pair => {
            let live = request
                .pair
                .as_ref()
                .ok_or(StorageError::Integrity("reply outbox pair requires live prepare"))?;
            let prepared =
                request.client.prepare_received_pair_reply(live.config, live.opened, live.body)?;
            let Some(envelope) = prepared else {
                return Err(StorageError::Integrity("reply outbox pair is not a reset ack").into());
            };
            Ok(Some(envelope))
        }
    }
}

fn transfer(tx: &ReceiveTransaction<'_>, request: AdmitRequest<'_>) -> Result<Admit, SdkError> {
    let db = tx.account();
    let stored = outbox_key(request.auth_key);
    let marker = marker_key(request.auth_key);
    let hashed = digest(&request.envelope)?;
    let (outbox_rows, _) = db.actor_state_usage(OUTBOX)?;
    let (marker_rows, _) = db.actor_state_usage(MARKER)?;
    if outbox_rows.saturating_add(marker_rows).saturating_add(2) > u64::from(MAX_OUTBOX) {
        hold_open(tx, request.sequence)?;
        before_commit_fault()?;
        return Ok(Admit::OutboxFull);
    }
    let prepared = PreparedReply {
        envelope_id: request.envelope.envelope_id.clone(),
        envelope: request.envelope,
        kind: request.kind,
    };
    let transfer = TransferMarker { envelope_id: prepared.envelope_id.clone(), digest: hashed };
    if let Some(message) = request.message {
        db.persist_message_actor_state(message, &stored, &prepared)?;
        db.persist_message_actor_state(message, &marker, &transfer)?;
    } else {
        db.persist_actor_state(&stored, &prepared)?;
        db.persist_actor_state(&marker, &transfer)?;
    }
    if let Some(key) = request.response_key {
        db.remove_actor_state(key)?;
    }
    before_commit_fault()?;
    Ok(Admit::Admitted)
}

fn hold_open(tx: &ReceiveTransaction<'_>, sequence: u64) -> Result<(), StorageError> {
    tx.hold_receipt(sequence)
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

/// Submit acknowledgement retires the outbox row. The transfer marker stays until W0 terminal.
pub(crate) fn acknowledge(db: &AccountDb, auth_key: &str) -> Result<(), SdkError> {
    db.write_transaction(|| {
        db.remove_actor_state(&outbox_key(auth_key))?;
        Ok::<(), StorageError>(())
    })?;
    Ok(())
}

fn prune_on_terminal(
    tx: &ReceiveTransaction<'_>,
    sequence: u64,
    auth_key: &str,
) -> Result<(), StorageError> {
    tx.require_writer()?;
    let covered = tx.cover(ReceiveCover {
        sequence,
        kind: ReceiveCoverKind::Terminal,
        gaps: &[],
        retain_until: 0,
    })?;
    if covered != ReceiveCoverResult::Covered {
        return Err(StorageError::Integrity("reply outbox terminal cover paused"));
    }
    tx.account().remove_actor_state(&marker_key(auth_key))?;
    Ok(())
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("reply outbox before-commit"));
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
pub(crate) mod reply_outbox_crash_tests;
#[cfg(test)]
pub(crate) mod reply_stage_redrive_tests;
