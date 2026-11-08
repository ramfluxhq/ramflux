// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant SDK ephemeral send and receiver: D1/D5 submit, lifetime, channel, dedup, lock.

mod lifetime;
mod receiver;
mod send;

pub use lifetime::{
    AuthenticatedCiphertext, HoldLease, ReceiverClock, ReceiverDropReason, ReceiverHandoff,
    ReceiverLifetime, admit_authenticated_ciphertext, authenticate, ttl_seconds,
};
pub use receiver::{
    EphemeralReceiver, LedgerProbe, RECEIVER_CHANNEL_BYTES, RECEIVER_CHANNEL_FRAMES,
    RECEIVER_DEDUP_BOUND, RECEIVER_DEDUP_BUDGET_BYTES, RECEIVER_DEDUP_ENTRY_BYTES,
    RECEIVER_MAX_FRAME_BYTES, ReceiverAdmit, ReceiverDequeue,
};
pub use send::{
    EphemeralSendError, EphemeralSendOutcome, EphemeralWire, decode_ephemeral_result,
    echo_holds_ephemeral_send, encode_ephemeral_submit, send_ephemeral,
};
