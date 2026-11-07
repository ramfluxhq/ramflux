// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant SDK ephemeral receiver: authenticated lifetime, bounded channel, dedup, lock.

mod lifetime;
mod receiver;

pub use lifetime::{
    AuthenticatedCiphertext, HoldLease, ReceiverClock, ReceiverDropReason, ReceiverHandoff,
    ReceiverLifetime, admit_authenticated_ciphertext, authenticate, ttl_seconds,
};
pub use receiver::{
    EphemeralReceiver, LedgerProbe, RECEIVER_CHANNEL_BYTES, RECEIVER_CHANNEL_FRAMES,
    RECEIVER_DEDUP_BOUND, RECEIVER_DEDUP_BUDGET_BYTES, RECEIVER_DEDUP_ENTRY_BYTES,
    RECEIVER_MAX_FRAME_BYTES, ReceiverAdmit, ReceiverDequeue,
};
