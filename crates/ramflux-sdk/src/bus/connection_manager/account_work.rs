// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded messages to the account writer; connection tasks never own an account DB.

use super::SessionMetadata;
use crate::{GatewaySessionConfig, SdkError};
use tokio::{sync::oneshot, time::Instant};

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
    ReceivePrepare {
        generation: u64,
        trigger: super::ReceiveTrigger,
        reply: oneshot::Sender<Result<super::ReceivePlan, SdkError>>,
    },
    ReceiveApply {
        generation: u64,
        entry: Box<super::receive::ReceiveEntry>,
        source: crate::bus::sync_driver::source::PreparedSource,
        backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
        reply: oneshot::Sender<Result<super::receive::ReceiveApplied, SdkError>>,
    },
    ReceiveAck {
        generation: u64,
        state: Box<crate::bus::sync_driver::AckState>,
        cursor: Box<Result<crate::GatewayCursor, SdkError>>,
        backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
        reply: oneshot::Sender<Result<super::receive::ReceiveAcked, SdkError>>,
    },
    Metadata {
        metadata: Box<SessionMetadata>,
    },
    Observation {
        event: super::ConnectionEvent,
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
