// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT P07 adapter: W0-backed hold admission with joined journal and receipt writes.
//! P20 supplies the live actor's expected E/C/generation/erasure fence; this adapter has no
//! network work and never sends a reply or ACK.
#![allow(dead_code)] // linked by `bus/tests/receive_hold.rs` until P20 wires the actor.

use ramflux_storage::{
    AccountDb, ReceiveExpectation, ReceiveHold, ReceiveHoldClass, ReceiveHoldJournal,
    ReceiveHoldResult, ReceiveTransaction,
};

use crate::{SdkError, gateway::GatewayInboxEntry};

pub(crate) struct SourceHold<'a> {
    pub expected: ReceiveExpectation<'a>,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HoldDisposition {
    HeldLocal { evicted: Vec<u64> },
    Paused,
}

impl SourceHold<'_> {
    /// V2-blocked and unbound branches share one W0-backed admission/journal transaction.
    pub(crate) fn unrouted_entry(
        &self,
        db: &AccountDb,
        entry: &GatewayInboxEntry,
        admission_key: &str,
        at: i64,
    ) -> Result<HoldDisposition, SdkError> {
        let source_key = format!("unrouted:{admission_key}");
        let body = serde_json::json!({
            "envelope_id": entry.envelope.envelope_id,
            "claimed_source_device_id": entry.envelope.source_device_id,
            "payload_hash": entry.envelope.payload_hash,
            "inbox_seq": entry.inbox_seq,
        });
        let input = ReceiveHold {
            sequence: entry.inbox_seq,
            admission_key,
            class: ReceiveHoldClass::Unrouted,
            contact_root: None,
            unrouted_id: Some(admission_key),
            journal: Some(ReceiveHoldJournal {
                source_key: &source_key,
                topic: "message.unrouted",
                body: &body,
                subject: None,
            }),
            at,
        };
        self.admit(db, input)
    }

    /// Contact-capacity pressure shares WS and does not save an actor retry/floor row.
    pub(crate) fn contact_entry(
        &self,
        db: &AccountDb,
        entry: &GatewayInboxEntry,
        admission_key: &str,
        root: &str,
        at: i64,
    ) -> Result<HoldDisposition, SdkError> {
        self.admit(
            db,
            ReceiveHold {
                sequence: entry.inbox_seq,
                admission_key,
                class: ReceiveHoldClass::Contact,
                contact_root: Some(root),
                unrouted_id: None,
                journal: None,
                at,
            },
        )
    }

    /// Hold admission inside an already-open receive transaction.
    ///
    /// # Errors
    /// Returns the storage refusal from [`ReceiveTransaction::admit_hold`].
    pub(crate) fn admit_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        input: ReceiveHold<'_>,
    ) -> Result<HoldDisposition, ramflux_storage::StorageError> {
        let _ = self;
        Ok(match tx.admit_hold(input)? {
            ReceiveHoldResult::Held { evicted } => HoldDisposition::HeldLocal { evicted },
            ReceiveHoldResult::Paused => HoldDisposition::Paused,
        })
    }

    pub(crate) fn admit(
        &self,
        db: &AccountDb,
        input: ReceiveHold<'_>,
    ) -> Result<HoldDisposition, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| self.admit_in(tx, input))?)
    }
}
