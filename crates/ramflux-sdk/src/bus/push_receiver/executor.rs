// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exclusive per-account ledger executor. P20 wires it into the S2 actor;
//! standalone public receive uses the same routines under the exclusive client borrow.

pub(crate) mod authority;

use super::hooks;
use crate::prelude::*;
use authority::{AuthorityKind, LedgerAuthority};
use ramflux_storage::{
    AccountDb, ReceiveBind, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult, ReceiveReset,
    ReceiveResetResult, ReceiveSettle, ReceiveSettleKind, ReceiveSettleResult, ReceiveTransaction,
    StorageError,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static REGISTRY: OnceLock<Mutex<HashMap<String, ExecutorOwner>>> = OnceLock::new();
#[cfg(test)]
thread_local! {
    static LAST_OWNER: std::cell::Cell<Option<ExecutorOwner>> = const { std::cell::Cell::new(None) };
}

fn registry() -> &'static Mutex<HashMap<String, ExecutorOwner>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_registry() -> std::sync::MutexGuard<'static, HashMap<String, ExecutorOwner>> {
    registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Who holds the exclusive receive writer for an account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutorOwner {
    Actor,
    Standalone,
}

/// Shared W0/W1/W2/WS/WA entry points. Actor and standalone share this type.
/// Drop releases the per-account exclusive bind.
#[derive(Debug)]
pub(crate) struct LedgerExecutor {
    owner: ExecutorOwner,
    account: String,
}

/// Result of one W2 cover through the executor.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CoverOutcome {
    pub result: ReceiveCoverResult,
    pub authority: Option<LedgerAuthority>,
    pub ack_eligible: bool,
}

/// Result of one WS settle through the executor.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SettleOutcome {
    pub result: ReceiveSettleResult,
    pub authority: Option<LedgerAuthority>,
    pub ack_eligible: bool,
}

/// Result of one reset through the executor.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResetOutcome {
    pub result: ReceiveResetResult,
    pub authority: Option<LedgerAuthority>,
}

/// Result of one logical-message bind through the executor.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BindOutcome {
    pub result: ReceiveBind,
    pub authority: Option<LedgerAuthority>,
}

/// Read-only startup incarnation E and cursor C.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StartupCursor {
    pub incarnation: String,
    pub cursor: u64,
}

#[allow(clippy::unused_self)] // exclusive owner is the RAII bind; P25 uses the bound account.
impl LedgerExecutor {
    fn bind(owner: ExecutorOwner, account: String) -> Result<Self, SdkError> {
        let mut held = lock_registry();
        if held.contains_key(&account) {
            return Err(SdkError::Storage(StorageError::AccountWriterBusy(account)));
        }
        held.insert(account.clone(), owner);
        #[cfg(test)]
        LAST_OWNER.with(|cell| cell.set(Some(owner)));
        Ok(Self { owner, account })
    }

    /// Last exclusive bind in this process. Test-only proof for the standalone row.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn last_bound_owner() -> Option<ExecutorOwner> {
        LAST_OWNER.with(std::cell::Cell::get)
    }

    /// Exclusive actor bind for `account`. Released on drop.
    ///
    /// # Errors
    /// [`StorageError::AccountWriterBusy`] when the account already has a receiver.
    pub(crate) fn bind_actor(account: impl Into<String>) -> Result<Self, SdkError> {
        Self::bind(ExecutorOwner::Actor, account.into())
    }

    /// Exclusive standalone bind for `account`. Released on drop.
    ///
    /// # Errors
    /// [`StorageError::AccountWriterBusy`] when the account already has a receiver.
    pub(crate) fn bind_standalone(account: impl Into<String>) -> Result<Self, SdkError> {
        Self::bind(ExecutorOwner::Standalone, account.into())
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> ExecutorOwner {
        self.owner
    }

    #[must_use]
    pub(crate) fn account(&self) -> &str {
        &self.account
    }

    /// W2 cover inside the caller's open receive transaction.
    ///
    /// # Errors
    /// Propagates cover refusals; records the C write only when storage returns [`ReceiveCoverResult::Covered`].
    pub(crate) fn cover_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        cover: ReceiveCover<'_>,
    ) -> Result<CoverOutcome, SdkError> {
        let seq = cover.sequence;
        let kind = cover.kind;
        let result = tx.cover(cover)?;
        let outcome = cover_outcome(seq, kind, result, tx.writer_id());
        if let Some(ref token) = outcome.authority {
            hooks::record_sql(seq, token.kind());
        }
        Ok(outcome)
    }

    /// WS settle inside the caller's open receive transaction.
    ///
    /// # Errors
    /// Propagates settle refusals; records a C write only when settle advanced C.
    pub(crate) fn settle_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        settle: ReceiveSettle,
    ) -> Result<SettleOutcome, SdkError> {
        let seq = settle.sequence;
        let kind = settle.kind;
        let before = tx.receive_cursor()?;
        let result = tx.settle(settle)?;
        let after = tx.receive_cursor()?;
        let outcome = settle_outcome(seq, kind, result, after > before, tx.writer_id());
        if after > before
            && let Some(ref token) = outcome.authority
        {
            hooks::record_sql(seq, token.kind());
        }
        Ok(outcome)
    }

    /// Reset token minted only from [`ReceiveTransaction::reset`] → [`ReceiveResetResult::Reset`].
    ///
    /// # Errors
    /// Propagates reset refusals.
    pub(crate) fn reset_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        input: ReceiveReset<'_>,
    ) -> Result<ResetOutcome, SdkError> {
        let seq = input.settled;
        let result = tx.reset(input)?;
        Ok(reset_outcome(seq, result, tx.writer_id()))
    }

    /// Erasure token minted only from [`ReceiveBind::Erased`].
    ///
    /// # Errors
    /// Propagates bind refusals.
    pub(crate) fn bind_logical_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        sequence: u64,
        message: &str,
    ) -> Result<BindOutcome, SdkError> {
        let result = tx.bind_logical_message(sequence, message)?;
        Ok(bind_outcome(sequence, result, tx.writer_id()))
    }

    /// WA token for a terminal storage result at `seq`. Held or paused work cannot mint one.
    ///
    /// # Errors
    /// Refuses a missing token, a held or paused outcome, and a sequence that is not the covered one.
    pub(crate) fn mint_wa(
        &self,
        from: Option<LedgerAuthority>,
        ack_eligible: bool,
        seq: u64,
    ) -> Result<LedgerAuthority, SdkError> {
        let Some(from) = from else {
            return Err(SdkError::Storage(StorageError::Integrity(
                "storage result minted no ACK token",
            )));
        };
        if !ack_eligible {
            return Err(SdkError::Storage(StorageError::Integrity(
                "held sequence is not eligible for ACK",
            )));
        }
        let (kind, token_seq, writer_id) = from.into_parts();
        if token_seq != seq || !matches!(kind, AuthorityKind::W2 | AuthorityKind::Ws) {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        Ok(LedgerAuthority::wa(seq, writer_id))
    }

    /// Generic receive-checkpoint write. The receive-cursor namespace requires a Reset
    /// token (W2 writes C through `cover_in`) and the caller's open receive transaction.
    /// The token is consumed.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] when the token cannot write C, is bound to
    /// another transaction, or the writer is closed.
    pub(crate) fn persist_receive_checkpoint_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        token: LedgerAuthority,
        seq: u64,
    ) -> Result<(), SdkError> {
        tx.require_writer()?;
        let (kind, token_seq, writer_id) = token.into_parts();
        if kind != AuthorityKind::Reset || token_seq != seq {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        if writer_id != tx.writer_id() {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        tx.persist_receive_cursor(seq)?;
        hooks::record_sql(seq, kind);
        Ok(())
    }

    /// Raw ACK. Refuses any other kind, then records the frame with the real WA token.
    /// The token is consumed.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] when the token is not WA for `seq`.
    pub(crate) fn send_ack_in(&self, token: LedgerAuthority, seq: u64) -> Result<(), SdkError> {
        let (kind, token_seq, _) = token.into_parts();
        if kind != AuthorityKind::Wa || token_seq != seq {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        hooks::record_ack(seq, Some(kind));
        Ok(())
    }

    /// Hold-table delete joined to W2 / WS / reset / erasure on the caller's transaction.
    /// The token is consumed.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] without transaction authority; storage errors from the delete.
    pub(crate) fn remove_unrouted_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        token: LedgerAuthority,
        id: &str,
    ) -> Result<(), SdkError> {
        let (kind, _, writer_id) = token.into_parts();
        if !matches!(
            kind,
            AuthorityKind::W2 | AuthorityKind::Ws | AuthorityKind::Reset | AuthorityKind::Erasure
        ) {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        if writer_id != tx.writer_id() {
            return Err(SdkError::Storage(StorageError::AuthorizationRejected));
        }
        tx.remove_unrouted(id)?;
        hooks::record_delete(id, Some(kind));
        Ok(())
    }

    /// Inbox Resume / page request. Only the shared executor may issue one.
    pub(crate) fn request_inbox_in(&self, after: u64, limit: usize) {
        hooks::record_inbox(after, limit);
    }

    /// Read-only startup E+C. Never writes max into C.
    ///
    /// # Errors
    /// [`SdkError::InvalidGatewayCursor`] when the stored checkpoint is not a u64.
    pub(crate) fn load_startup_cursor(
        &self,
        db: &AccountDb,
        target: &str,
    ) -> Result<StartupCursor, SdkError> {
        let (incarnation, cursor) = db.receive_startup(target)?;
        Ok(StartupCursor { incarnation, cursor })
    }
}

impl Drop for LedgerExecutor {
    fn drop(&mut self) {
        lock_registry().remove(&self.account);
    }
}

fn cover_outcome(
    seq: u64,
    kind: ReceiveCoverKind,
    result: ReceiveCoverResult,
    writer_id: u64,
) -> CoverOutcome {
    match result {
        ReceiveCoverResult::Covered => CoverOutcome {
            result,
            authority: Some(LedgerAuthority::w2(seq, writer_id)),
            ack_eligible: matches!(kind, ReceiveCoverKind::Terminal | ReceiveCoverKind::Oversize),
        },
        ReceiveCoverResult::Paused => CoverOutcome { result, authority: None, ack_eligible: false },
    }
}

fn settle_outcome(
    seq: u64,
    kind: ReceiveSettleKind,
    result: ReceiveSettleResult,
    wrote_c: bool,
    writer_id: u64,
) -> SettleOutcome {
    let ack_eligible =
        result == ReceiveSettleResult::Settled && kind == ReceiveSettleKind::Terminal;
    let authority = match result {
        ReceiveSettleResult::Settled if wrote_c => Some(LedgerAuthority::w2(seq, writer_id)),
        ReceiveSettleResult::Settled => Some(LedgerAuthority::ws(seq, writer_id)),
        ReceiveSettleResult::Held | ReceiveSettleResult::Paused => None,
    };
    SettleOutcome { result, authority, ack_eligible }
}

fn reset_outcome(seq: u64, result: ReceiveResetResult, writer_id: u64) -> ResetOutcome {
    let authority = match result {
        ReceiveResetResult::Reset => Some(LedgerAuthority::reset(seq, writer_id)),
        ReceiveResetResult::PausedFence | ReceiveResetResult::PausedLoss => None,
    };
    ResetOutcome { result, authority }
}

fn bind_outcome(seq: u64, result: ReceiveBind, writer_id: u64) -> BindOutcome {
    let authority = match result {
        ReceiveBind::Erased => Some(LedgerAuthority::erasure(seq, writer_id)),
        ReceiveBind::Bound => None,
    };
    BindOutcome { result, authority }
}

#[cfg(test)]
pub(crate) fn cover_outcome_for_test(
    seq: u64,
    kind: ReceiveCoverKind,
    result: ReceiveCoverResult,
    writer_id: u64,
) -> CoverOutcome {
    cover_outcome(seq, kind, result, writer_id)
}

#[cfg(test)]
pub(crate) fn settle_outcome_for_test(
    seq: u64,
    kind: ReceiveSettleKind,
    result: ReceiveSettleResult,
    wrote_c: bool,
    writer_id: u64,
) -> SettleOutcome {
    settle_outcome(seq, kind, result, wrote_c, writer_id)
}

#[cfg(test)]
pub(crate) fn reset_outcome_for_test(
    seq: u64,
    result: ReceiveResetResult,
    writer_id: u64,
) -> ResetOutcome {
    reset_outcome(seq, result, writer_id)
}

#[cfg(test)]
pub(crate) fn bind_outcome_for_test(seq: u64, result: ReceiveBind, writer_id: u64) -> BindOutcome {
    bind_outcome(seq, result, writer_id)
}

/// Conversation `message.receive` redrive ACK. WA owns the wire frame.
///
/// # Errors
/// [`StorageError::AuthorizationRejected`] when `token` is not WA for `seq`.
pub(crate) fn message_receive_ack_in(
    exec: &LedgerExecutor,
    token: LedgerAuthority,
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
    tx: &ReceiveTransaction<'_>,
    token: LedgerAuthority,
    id: &str,
) -> Result<(), SdkError> {
    exec.remove_unrouted_in(tx, token, id)
}
