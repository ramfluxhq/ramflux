// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exclusive actor/standalone ledger executor. P20 wires it into the S2 actor;
//! standalone public receive uses the same routines under the exclusive client borrow.

use super::authority::{AuthorityKind, LedgerAuthority};
use super::hooks;
use crate::dm::gateway_receive_cursor_checkpoint_name;
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, ProjectionStore, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult, ReceiveSettle,
    ReceiveSettleKind, ReceiveSettleResult, ReceiveTransaction, StorageError,
};
use std::cell::RefCell;
use std::collections::HashSet;

thread_local! {
    static ACTOR_ACCOUNTS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

/// Who holds the exclusive receive writer for an account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutorOwner {
    Actor,
    Standalone,
}

/// Shared W0/W1/W2/WS/WA entry points. Actor and standalone share this type.
pub(crate) struct LedgerExecutor {
    owner: ExecutorOwner,
}

/// Result of one W2 cover through the executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoverOutcome {
    pub result: ReceiveCoverResult,
    pub authority: LedgerAuthority,
    pub ack_eligible: bool,
}

/// Result of one WS settle through the executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SettleOutcome {
    pub result: ReceiveSettleResult,
    pub authority: LedgerAuthority,
    pub ack_eligible: bool,
}

#[allow(clippy::unused_self)] // exclusive owner is bind_account; P20 uses the bound instance.
impl LedgerExecutor {
    #[must_use]
    pub(crate) const fn actor() -> Self {
        Self { owner: ExecutorOwner::Actor }
    }

    #[must_use]
    pub(crate) const fn standalone() -> Self {
        Self { owner: ExecutorOwner::Standalone }
    }

    /// Binds this executor to `account`. A standalone bind on an actor-owned account
    /// returns the existing exclusive-writer error instead of starting a second receiver.
    ///
    /// # Errors
    /// [`StorageError::AccountWriterBusy`] when the account already has an actor receiver.
    pub(crate) fn bind_account(&self, account: &str) -> Result<(), SdkError> {
        ACTOR_ACCOUNTS.with(|held| {
            let mut held = held.borrow_mut();
            match self.owner {
                ExecutorOwner::Actor => {
                    held.insert(account.to_owned());
                    Ok(())
                }
                ExecutorOwner::Standalone if held.contains(account) => {
                    Err(SdkError::Storage(StorageError::AccountWriterBusy(account.to_owned())))
                }
                ExecutorOwner::Standalone => Ok(()),
            }
        })
    }

    /// W2 cover inside the caller's open receive transaction.
    ///
    /// # Errors
    /// Propagates cover refusals; records the C write with the minted W2 token.
    pub(crate) fn cover_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        cover: ReceiveCover<'_>,
    ) -> Result<CoverOutcome, SdkError> {
        let seq = cover.sequence;
        let ack_eligible =
            matches!(cover.kind, ReceiveCoverKind::Terminal | ReceiveCoverKind::Oversize);
        let result = tx.cover(cover)?;
        let authority = LedgerAuthority::w2(seq);
        if result == ReceiveCoverResult::Covered {
            hooks::record_sql(seq, authority);
        }
        Ok(CoverOutcome { result, authority, ack_eligible })
    }

    /// WS settle inside the caller's open receive transaction. Never records a C write.
    ///
    /// # Errors
    /// Propagates settle refusals.
    pub(crate) fn settle_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        settle: ReceiveSettle,
    ) -> Result<SettleOutcome, SdkError> {
        let seq = settle.sequence;
        let ack_eligible = settle.kind == ReceiveSettleKind::Terminal;
        let result = tx.settle(settle)?;
        Ok(SettleOutcome { result, authority: LedgerAuthority::ws(seq), ack_eligible })
    }

    /// Mints a reset token. Actual reset writes stay in P10; the token is what the
    /// generic checkpoint setter requires.
    #[must_use]
    pub(crate) fn reset_token(&self, seq: u64) -> LedgerAuthority {
        LedgerAuthority::reset(seq)
    }

    /// Mints an erasure token for hold cleanup joined to explicit erasure.
    #[must_use]
    pub(crate) fn erasure_token(&self, seq: u64) -> LedgerAuthority {
        LedgerAuthority::erasure(seq)
    }

    /// WA token for a terminal intent at `seq`. Held cover/settle cannot mint one.
    ///
    /// # Errors
    /// Refuses a held or paused outcome and a sequence that is not the covered one.
    pub(crate) fn mint_wa(
        &self,
        from: LedgerAuthority,
        ack_eligible: bool,
        seq: u64,
    ) -> Result<LedgerAuthority, SdkError> {
        if !ack_eligible {
            return Err(SdkError::Storage(StorageError::Integrity(
                "held sequence is not eligible for ACK",
            )));
        }
        if from.seq() != seq || !matches!(from.kind(), AuthorityKind::W2 | AuthorityKind::Ws) {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        Ok(LedgerAuthority::wa(seq))
    }

    /// Generic receive-checkpoint write. The receive-cursor namespace requires W2 or reset.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] when the token cannot write C.
    pub(crate) fn persist_receive_checkpoint_in(
        &self,
        db: &AccountDb,
        token: &LedgerAuthority,
        target: &str,
        seq: u64,
    ) -> Result<(), SdkError> {
        if !token.allows_receive_checkpoint() || token.seq() != seq {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        db.set_projection_checkpoint(
            &gateway_receive_cursor_checkpoint_name(target),
            &seq.to_string(),
        )?;
        hooks::record_sql(seq, *token);
        Ok(())
    }

    /// Raw ACK. Records the frame with the real WA token, then refuses any other kind.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] when the token is not WA for `seq`.
    pub(crate) fn send_ack_in(&self, token: &LedgerAuthority, seq: u64) -> Result<(), SdkError> {
        hooks::record_ack(seq, Some(*token));
        if !token.is_wa() || token.seq() != seq {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        Ok(())
    }

    /// Hold-table delete joined to W2 / WS / reset / erasure.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] without transaction authority; storage errors from the delete.
    pub(crate) fn remove_unrouted_in(
        &self,
        db: &AccountDb,
        token: &LedgerAuthority,
        id: &str,
    ) -> Result<(), SdkError> {
        if !token.allows_hold_delete() {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        db.remove_unrouted(id)?;
        hooks::record_delete(id, Some(*token));
        Ok(())
    }

    /// Inbox Resume / page request. Only the shared executor may issue one.
    pub(crate) fn request_inbox_in(&self, after: u64, limit: usize) {
        hooks::record_inbox(after, limit);
    }

    /// Read-only startup C. Never writes max into C.
    ///
    /// # Errors
    /// [`SdkError::InvalidGatewayCursor`] when the stored checkpoint is not a u64.
    pub(crate) fn load_startup_cursor(
        &self,
        db: &AccountDb,
        target: &str,
    ) -> Result<u64, SdkError> {
        let checkpoint = db
            .projection_checkpoint(&gateway_receive_cursor_checkpoint_name(target))?
            .unwrap_or_else(|| "0".to_owned());
        checkpoint.parse::<u64>().map_err(|_error| SdkError::InvalidGatewayCursor(checkpoint))
    }
}

#[cfg(test)]
pub(crate) fn reset_actor_accounts() {
    ACTOR_ACCOUNTS.with(|held| held.borrow_mut().clear());
}

/// Conversation `message.receive` redrive ACK. WA owns the wire frame.
///
/// # Errors
/// [`StorageError::AuthorizationRejected`] when `token` is not WA for `seq`.
pub(crate) fn message_receive_ack_in(
    exec: &LedgerExecutor,
    token: &LedgerAuthority,
    seq: u64,
) -> Result<(), SdkError> {
    exec.send_ack_in(token, seq)
}

/// Group terminal hold cleanup. Joins every `remove_unrouted` to transaction authority.
///
/// # Errors
/// [`StorageError::AuthorizationRejected`] without W2/WS/reset/erasure; storage errors from the delete.
pub(crate) fn group_remove_unrouted_in(
    exec: &LedgerExecutor,
    db: &AccountDb,
    token: &LedgerAuthority,
    id: &str,
) -> Result<(), SdkError> {
    exec.remove_unrouted_in(db, token, id)
}
