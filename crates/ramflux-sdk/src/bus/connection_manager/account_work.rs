// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded messages to the account writer; connection tasks never own an account DB.

use super::SessionMetadata;
use crate::{GatewaySessionConfig, SdkError};
use ramflux_storage::{
    ReceiveAckApplyResult, ReceiveAckOutcome, ReceiveAckResult, ReceiveExpectation,
};
use tokio::{sync::oneshot, time::Instant};

/// Exact WA result set the actor applies after `push_point::ack_batch`.
#[derive(Clone, Debug)]
pub(crate) struct AckFlushResults {
    pub incarnation: String,
    pub sequences: Vec<u64>,
    pub results: Vec<ReceiveAckResult>,
}

/// Actor answer to one [`AccountWork::AckFlush`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AckFlushReply {
    /// Inactive discriminator: the caller must not send a batch.
    Inactive,
    /// Due sequences for this incarnation, possibly empty.
    Selected {
        incarnation: String,
        sequences: Vec<u64>,
    },
    Applied(ReceiveAckApplyResult),
    /// Compat proof-gated plan: `envelope_id` Some means send a legacy ACK first.
    Authorized {
        plans: Vec<CompatAckPlan>,
    },
}

/// One compat intent after `authorize_legacy_ack`. The connection child sends
/// when `envelope_id` is set, then WA-applies `outcome` (or Uncertain on send loss).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompatAckPlan {
    pub sequence: u64,
    pub envelope_id: Option<String>,
    pub outcome: ReceiveAckOutcome,
}

/// Owned actor/durable coordinates carried on a receive turn. The commit fence
/// borrows this as `ReceiveExpectation`.
#[derive(Clone, Debug)]
pub(crate) struct ReceiveTurn {
    pub target: String,
    pub incarnation: String,
    pub cursor: u64,
    pub generation: u64,
    pub erasure_generation: i64,
    /// True on an activated Legacy/Compat session: W2 is `CompatTerminal`.
    pub compat: bool,
}

impl ReceiveTurn {
    #[must_use]
    pub(crate) fn expected(&self) -> ReceiveExpectation<'_> {
        ReceiveExpectation {
            target: &self.target,
            incarnation: &self.incarnation,
            cursor: self.cursor,
            generation: self.generation,
            erasure_generation: self.erasure_generation,
        }
    }
}

pub(crate) enum AccountWork {
    Fatal {
        generation: u64,
        error: SdkError,
    },
    Courier(crate::bus::couriers::writer::Checkpoint),
    Contacts(Box<crate::client::contact_requests::ContactWork>),
    OwnCopy(Box<crate::bus::own_device_copy::OwnCopyWork>),
    Receipts(Box<crate::bus::delivery_receipts::ReceiptWork>),
    Directory(Box<crate::bus::couriers::directory::DirectoryWork>),
    PrepareReceive {
        generation: u64,
        trigger: super::ReceiveTrigger,
        reply: oneshot::Sender<Result<super::ReceivePlan, SdkError>>,
    },
    ApplyPage {
        generation: u64,
        /// Prepare-time expectation captured at `PrepareReceive` when the ledger is
        /// active, so E/erase changes during `source::prepare` stay fenced. `None` on
        /// the live unactivated path and as a rescan fallback (the actor then captures
        /// only if active).
        turn: Option<Box<ReceiveTurn>>,
        entry: Box<super::receive::ReceiveEntry>,
        source: crate::bus::sync_driver::source::PreparedSource,
        backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
        reply: oneshot::Sender<Result<super::receive::ReceiveApplied, SdkError>>,
    },
    #[allow(dead_code, reason = "P20a dormant; live senders arrive in later P20 parts")]
    SettleRetained {
        generation: u64,
        turn: Box<ReceiveTurn>,
        sequence: u64,
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
    /// Pre-send ACK decision for an activated turn. No ACK leaves the process
    /// unless the actor answers `Permitted`.
    AckPermit {
        generation: u64,
        turn: Box<ReceiveTurn>,
        sequence: u64,
        reply: oneshot::Sender<
            Result<crate::bus::account_runtime::lifecycle_fence::AckRecord, SdkError>,
        >,
    },
    AckResults {
        generation: u64,
        /// Ledger coordinates captured with the turn. `None` keeps today's live
        /// `finish()` path (unactivated accounts). P19 WA tokens are not on this
        /// base; ACK emission stays on the live receive send.
        turn: Option<Box<ReceiveTurn>>,
        state: Box<crate::bus::sync_driver::AckState>,
        cursor: Box<Result<crate::GatewayCursor, SdkError>>,
        backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
        reply: oneshot::Sender<Result<super::receive::ReceiveAcked, SdkError>>,
    },
    /// Activated-ledger WA flush: `results` is `None` to select a due batch, `Some` to
    /// apply the exact router result set. Inactive accounts never emit this arm.
    AckFlush {
        generation: u64,
        force: bool,
        now: i64,
        results: Option<AckFlushResults>,
        lookups: Option<Vec<(u64, crate::bus::push_receiver::compat::OwnedLookup)>>,
        reply: oneshot::Sender<Result<AckFlushReply, SdkError>>,
    },
    ReceiveObservation {
        generation: u64,
        event: super::ConnectionEvent,
    },
    /// Deliver intake: durable W0 on the account writer, then a reorder witness.
    StageIntake {
        generation: u64,
        entry: Box<crate::GatewayInboxEntry>,
        incarnation: String,
        retain_until: i64,
        reply: oneshot::Sender<
            Result<Option<(crate::bus::push_receiver::reorder::DurableW0, ReceiveTurn)>, SdkError>,
        >,
    },
    Metadata {
        metadata: Box<SessionMetadata>,
    },
    Prepare {
        generation: u64,
        deadline: Instant,
        reply: oneshot::Sender<Result<GatewaySessionConfig, SdkError>>,
    },
    Connected {
        metadata: Box<SessionMetadata>,
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
    Failed {
        generation: u64,
        error: SdkError,
    },
}
