// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT W1 adapter for legacy DM/A2I (S6b P15). No production caller reaches it: the live
//! `receive_legacy_entry` / `receive_bound_legacy_a2i` paths are unchanged. The expectation
//! values come from the caller; P20 supplies them.
//!
//! Contract: W0 (`stage`) precedes the irreversible effect; ratchet, content/rejection/receipt
//! and the authenticated dedup marker run inside one generation, incarnation, cursor and
//! erase-fenced receive transaction. Cursor and ACK are not embedded (ledger WA). Attachment
//! and auth reads stay outside the transaction. Group holds remain held. Never persist
//! plaintext to make a step resumable.
#![allow(dead_code)]

use crate::client::a2i::{self, LegacyA2iOpened};
use crate::client::dm::{LegacyDmDecrypt, LegacyDmPrepared};
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, ReceiveBind, ReceiveExpectation, ReceiveStage, ReceiveStageResult,
    ReceiveTransaction, StorageError,
};

pub(crate) struct LegacyW1<'a> {
    pub expected: ReceiveExpectation<'a>,
    /// The caller actor's current generation (the fence compares it with `expected.generation`).
    pub generation: u64,
}

impl LegacyW1<'_> {
    pub(crate) fn stage(
        &self,
        db: &AccountDb,
        input: ReceiveStage<'_>,
    ) -> Result<ReceiveStageResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.stage(input))?)
    }

    /// Runs the irreversible effect and optional logical-message bind inside one receive
    /// transaction. A missing recovery input refuses before the effect.
    pub(crate) fn effect<T>(
        &self,
        db: &AccountDb,
        sequence: u64,
        message: Option<&str>,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        let mut outcome = None;
        let fenced = db.receive_transaction(self.expected, self.generation, |tx| {
            match self.effect_in(tx, sequence, message, effect) {
                Ok(value) => {
                    outcome = Some(Ok(value));
                    Ok(())
                }
                Err(error) => {
                    outcome = Some(Err(error));
                    Err(StorageError::Integrity("legacy effect failed"))
                }
            }
        });
        match (fenced, outcome) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(()), Some(Ok(value))) => Ok(value),
            (Ok(()), None) => Err(SdkError::LocalBus("legacy effect did not run".into())),
        }
    }

    /// Same cut as [`Self::effect`], joining an already-open receive transaction.
    #[allow(clippy::unused_self)]
    pub(crate) fn effect_in<T>(
        &self,
        tx: &ReceiveTransaction<'_>,
        sequence: u64,
        message: Option<&str>,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        tx.require_open_input(sequence)?;
        let value = effect()?;
        if let Some(message) = message {
            match tx.bind_logical_message(sequence, message)? {
                ReceiveBind::Bound | ReceiveBind::Erased => {}
            }
        }
        before_commit_fault()?;
        Ok(value)
    }
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("legacy w1 before-commit"));
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
    /// Outer unbound check passed; the in-tx hold must redrive (`LegacyBindingChanged`).
    BindingAppeared,
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

impl RamfluxClient {
    #[cfg(test)]
    pub(crate) fn w1_gate<'a>(
        db: &'a AccountDb,
        target: &'a str,
    ) -> Result<LegacyW1<'a>, SdkError> {
        Ok(LegacyW1 {
            expected: ReceiveExpectation {
                target,
                incarnation: "e",
                cursor: 0,
                generation: 1,
                erasure_generation: db.privacy_erasure_generation()?,
            },
            generation: 1,
        })
    }

    /// Wired by P20. Decrypts a bound legacy DM and commits content+ratchet+marker through W1.
    ///
    /// Precondition: the caller has already run `ensure_inbound_device` for `entry` (it is async
    /// and cannot run inside this sync W1 path). This function runs the same sync routing-binding
    /// check the live DM path runs (`authorize_bound_legacy`), including the v2-blocks-legacy guard.
    pub(crate) fn apply_legacy_success_w1(
        &self,
        entry: &GatewayInboxEntry,
        local_device: &str,
        conversation: &str,
        expected: ReceiveExpectation<'_>,
        generation: u64,
    ) -> Result<(), SdkError> {
        self.require_legacy_routing_binding(local_device, entry, conversation)?;
        if self.legacy_w1_committed(entry)? {
            return Ok(());
        }
        let (envelope, session, decrypted) = self.decrypt_legacy_entry(conversation, entry)?;
        let db = self.account_db()?;
        let gate = LegacyW1 { expected, generation };
        let sequence = entry.inbox_seq;
        let message = entry.envelope.envelope_id.clone();
        let principal =
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id.clone();
        gate.effect(db, sequence, Some(&message), || {
            self.commit_legacy_success_effect(
                entry,
                conversation,
                &envelope,
                &session,
                &decrypted,
                &principal,
            )
        })
    }

    /// Same cut as [`Self::apply_legacy_success_w1`], joining an already-open receive transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_legacy_success_w1_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        entry: &GatewayInboxEntry,
        local_device: &str,
        conversation: &str,
        expected: ReceiveExpectation<'_>,
        generation: u64,
    ) -> Result<(), SdkError> {
        self.require_legacy_routing_binding(local_device, entry, conversation)?;
        if self.legacy_w1_committed(entry)? {
            return Ok(());
        }
        let (envelope, session, decrypted) = self.decrypt_legacy_entry(conversation, entry)?;
        let gate = LegacyW1 { expected, generation };
        let sequence = entry.inbox_seq;
        let message = entry.envelope.envelope_id.clone();
        let principal =
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id.clone();
        gate.effect_in(tx, sequence, Some(&message), || {
            self.commit_legacy_success_effect(
                entry,
                conversation,
                &envelope,
                &session,
                &decrypted,
                &principal,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_legacy_success_effect(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        envelope: &SdkDmEncryptedEnvelope,
        session: &ramflux_crypto::DmSession,
        decrypted: &ramflux_crypto::DmDecryptionOutput,
        principal: &str,
    ) -> Result<(), SdkError> {
        if self.legacy_w1_committed(entry)? {
            return Ok(());
        }
        match self.prepare_legacy_dm_after_decrypt(&LegacyDmDecrypt {
            conversation,
            entry,
            target: &entry.target_delivery_id,
            session,
            envelope,
            decrypted,
            consume_erased: true,
            persist_cursor: false,
        })? {
            LegacyDmPrepared::Finished => Ok(()),
            LegacyDmPrepared::Message(prepared) => {
                self.persist_legacy_dm_projection(
                    conversation,
                    entry,
                    &prepared.projection_body,
                    prepared.metadata.as_ref(),
                    principal,
                )?;
                self.commit_legacy_effect(conversation, entry, session)
            }
        }
    }

    /// Wired by P20. Peer-rejection cut — reject row + ratchet + marker, no cursor.
    ///
    /// Same precondition as `apply_legacy_success_w1`: the caller has run `ensure_inbound_device`,
    /// and the sync routing-binding check (incl. v2-blocks-legacy) runs here.
    pub(crate) fn apply_legacy_reject_w1(
        &self,
        entry: &GatewayInboxEntry,
        local_device: &str,
        conversation: &str,
        expected: ReceiveExpectation<'_>,
        generation: u64,
    ) -> Result<(), SdkError> {
        self.require_legacy_routing_binding(local_device, entry, conversation)?;
        if self.legacy_w1_committed(entry)? {
            return Ok(());
        }
        let (envelope, session, decrypted) = self.decrypt_legacy_entry(conversation, entry)?;
        let db = self.account_db()?;
        let gate = LegacyW1 { expected, generation };
        let sequence = entry.inbox_seq;
        gate.effect(db, sequence, None, || {
            if self.legacy_w1_committed(entry)? {
                return Ok(());
            }
            match self.prepare_legacy_dm_after_decrypt(&LegacyDmDecrypt {
                conversation,
                entry,
                target: &entry.target_delivery_id,
                session: &session,
                envelope: &envelope,
                decrypted: &decrypted,
                consume_erased: true,
                persist_cursor: false,
            })? {
                LegacyDmPrepared::Finished => Ok(()),
                LegacyDmPrepared::Message(_) => {
                    Err(SdkError::LocalBus("legacy reject did not reject".into()))
                }
            }
        })
    }

    /// Wired by P20. A2I ratchet + receipt + event, no ACK and no cursor.
    ///
    /// `local_device` is the receiver's own device id (`engine.config().device_id` on the live
    /// path). It must NOT be derived from `entry.target_delivery_id`, which is the delivery id.
    /// Precondition: the caller has run `ensure_inbound_device` for `entry`. Routing is checked
    /// first and the receipt second, matching `receive_bound_legacy_a2i`.
    pub(crate) fn apply_legacy_a2i_w1(
        &self,
        entry: &GatewayInboxEntry,
        local_device: &str,
        expected: ReceiveExpectation<'_>,
        generation: u64,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let gate = LegacyW1 { expected, generation };
        let sequence = entry.inbox_seq;
        if self.legacy_a2i_is_unbound(local_device, entry)? {
            return gate.effect(db, sequence, None, || {
                self.commit_unbound_legacy_a2i(local_device, entry)
            });
        }
        if self.load_legacy_a2i_receipt(entry)?.is_some() {
            return Ok(());
        }
        let opened = self.decrypt_bound_legacy_a2i(local_device, entry)?;
        gate.effect(db, sequence, None, || self.commit_legacy_a2i_w1(entry, &opened))
    }

    /// Same cut as [`Self::apply_legacy_a2i_w1`], joining an already-open receive transaction.
    ///
    /// Returns `true` when the in-transaction binding check held the entry, `false` when it
    /// applied. Callers cover from this value so held vs applied is one decision.
    pub(crate) fn apply_legacy_a2i_w1_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        entry: &GatewayInboxEntry,
        local_device: &str,
        expected: ReceiveExpectation<'_>,
        generation: u64,
    ) -> Result<bool, SdkError> {
        let gate = LegacyW1 { expected, generation };
        let sequence = entry.inbox_seq;
        if self.legacy_a2i_is_unbound(local_device, entry)? {
            gate.effect_in(tx, sequence, None, || {
                self.commit_unbound_legacy_a2i(local_device, entry)
            })?;
            return Ok(true);
        }
        if self.load_legacy_a2i_receipt(entry)?.is_some() {
            return Ok(false);
        }
        let opened = self.decrypt_bound_legacy_a2i(local_device, entry)?;
        gate.effect_in(tx, sequence, None, || self.commit_legacy_a2i_w1(entry, &opened))?;
        Ok(false)
    }

    fn commit_unbound_legacy_a2i(
        &self,
        local_device: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        if matches!(current_fault(), Fault::BindingAppeared) {
            return Err(SdkError::LegacyBindingChanged);
        }
        if self.hold_unbound_legacy_a2i(local_device, entry)? {
            Ok(())
        } else {
            Err(SdkError::LegacyBindingChanged)
        }
    }

    fn commit_legacy_a2i_w1(
        &self,
        entry: &GatewayInboxEntry,
        opened: &LegacyA2iOpened,
    ) -> Result<(), SdkError> {
        if let Some(receipt) = self
            .account_db()?
            .load_actor_state::<a2i::LegacyControlReceipt>(&self.legacy_a2i_receipt_key(entry)?)?
        {
            a2i::reject_legacy_a2i_payload_reuse(&receipt, entry)?;
            return Ok(());
        }
        self.persist_legacy_a2i_effect(entry, opened)
    }

    /// Wired by P20. Group local apply that cannot complete stays held; no terminal marker.
    pub(crate) fn apply_legacy_group_hold_w1(
        &self,
        entry: &GatewayInboxEntry,
        expected: ReceiveExpectation<'_>,
        generation: u64,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let gate = LegacyW1 { expected, generation };
        let sequence = entry.inbox_seq;
        gate.effect(db, sequence, None, || Self::commit_legacy_group_hold(db, entry))
    }

    /// Same cut as [`Self::apply_legacy_group_hold_w1`], joining an already-open receive transaction.
    #[allow(clippy::unused_self)]
    pub(crate) fn apply_legacy_group_hold_w1_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        entry: &GatewayInboxEntry,
        expected: ReceiveExpectation<'_>,
        generation: u64,
    ) -> Result<(), SdkError> {
        let gate = LegacyW1 { expected, generation };
        let sequence = entry.inbox_seq;
        gate.effect_in(tx, sequence, None, || Self::commit_legacy_group_hold(tx.account(), entry))
    }

    fn commit_legacy_group_hold(db: &AccountDb, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        db.hold_unrouted(
            &entry.envelope.envelope_id,
            entry.inbox_seq,
            &serde_json::to_vec(entry)?,
            now_unix_timestamp(),
        )?;
        Ok(())
    }

    pub(crate) fn legacy_w1_committed(&self, entry: &GatewayInboxEntry) -> Result<bool, SdkError> {
        Ok(self.account_db()?.actor_state_exists(&self.legacy_committed_key(entry)?)?)
    }

    pub(crate) fn legacy_a2i_committed(&self, entry: &GatewayInboxEntry) -> Result<bool, SdkError> {
        Ok(self.account_db()?.actor_state_exists(&self.legacy_a2i_receipt_key(entry)?)?)
    }
}
