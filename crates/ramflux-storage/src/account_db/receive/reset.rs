// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real E/U incarnation reset, WJ-before-reset publication, bounded retired-E fence
//! and same-E issued<C freeze. Dormant until P20/P24 wire it. Reset takes the
//! caller's receive transaction (old E, old C).
use super::ReceiveTransaction;
use crate::{AccountDb, JournalEvent, ProjectionStore, StorageError};
use rusqlite::params;

/// At most 64 retired incarnation names per target.
pub const RETIRED_FENCE_CAP: usize = 64;
/// Exact freeze diagnostic; receive and settlement write nothing while it is set.
pub const CURSOR_AHEAD: &str = "cursor_ahead";
const PAUSE_FENCE: &str = "retired_incarnation_fence";

/// Why the active incarnation is being replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveResetReason {
    /// Router restore / WAL rotation created a new E.
    RouterReset,
    /// First verified E after a proofless compatibility namespace U.
    IncarnationFirstVerified,
}

impl ReceiveResetReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RouterReset => "router_reset",
            Self::IncarnationFirstVerified => "incarnation_first_verified",
        }
    }
}

/// One expected-E reset onto a validated first-page settled prefix S.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveReset<'a> {
    pub new_incarnation: &'a str,
    pub settled: u64,
    /// Issued watermark of the after=0 page; `settled` must satisfy `0 ≤ S ≤ issued`.
    pub issued: u64,
    /// Page cursor; only `after=0` is valid for this first-page reset.
    pub after: u64,
    pub reason: ReceiveResetReason,
}

/// Reset either commits the new epoch or pauses without changing C/E/ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReceiveResetResult {
    Reset,
    PausedFence,
    PausedLoss,
}

/// Observation of the current session's issued watermark against durable C.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReceiveIssued {
    Live,
    Frozen,
}

impl AccountDb {
    /// WJ for reset: publish unpublished old-E loss outbox rows, one unique source key each.
    /// A failure leaves unpublished rows so reset pauses. Commits separately from reset.
    ///
    /// # Errors
    /// Returns SQL or journal errors.
    pub fn publish_pending_receive_loss(
        &self,
        target: &str,
        incarnation: &str,
        at: i64,
    ) -> Result<u32, StorageError> {
        let mut published = 0u32;
        loop {
            let batch = self.pending_loss_outbox_for(Some(target), Some(incarnation), 256)?;
            if batch.is_empty() {
                return Ok(published);
            }
            for (sequence, keys) in batch {
                let _events: Vec<JournalEvent> =
                    self.journal_outbox(sequence, &[super::loss::loss_journal_event(&keys)], at)?;
                published = published.saturating_add(1);
            }
        }
    }

    /// Pause diagnostic written when the 65th retired-E transition is refused.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn receive_pause(&self, target: &str) -> Result<Option<String>, StorageError> {
        self.projection_checkpoint(&pause_name(target))
    }

    /// Recovery clears the retired-fence pause so a later reset may run.
    ///
    /// # Errors
    /// Requires an open writer transaction.
    pub fn clear_receive_pause(&self, target: &str) -> Result<(), StorageError> {
        if self.connection.is_autocommit()? {
            return Err(StorageError::AuthorizationRejected);
        }
        self.connection.execute(
            "DELETE FROM projection_checkpoint WHERE projection_name=?1",
            params![pause_name(target)],
        )?;
        Ok(())
    }
}

impl ReceiveTransaction<'_> {
    /// Atomic expected-E reset: C=S, activated=S, fence=S, one `inbox_reset` event,
    /// old work local-only, terminal compat rows released. WJ must have already run.
    /// Empty U with C=0 initializes the first verified E without `inbox_reset`.
    ///
    /// # Errors
    /// Requires the writer; refuses a retired inbox, a retired new E, an empty new E,
    /// `after != 0`, and `S > issued`.
    pub fn reset(&self, input: ReceiveReset<'_>) -> Result<ReceiveResetResult, StorageError> {
        self.require_writer()?;
        self.refuse_retired()?;
        if input.new_incarnation.is_empty() {
            return Err(StorageError::Integrity("receive reset identity missing"));
        }
        if input.after != 0 {
            return Err(StorageError::Integrity("receive reset after must be zero"));
        }
        if input.settled > input.issued {
            return Err(StorageError::Integrity("receive reset settled prefix invalid"));
        }
        if self.unpublished_old_loss()? != 0 {
            return Ok(ReceiveResetResult::PausedLoss);
        }
        if input.new_incarnation == self.incarnation {
            return Ok(ReceiveResetResult::Reset);
        }
        let mut retired = self.retired_names()?;
        if retired.iter().any(|was| was == input.new_incarnation) {
            return Err(StorageError::Integrity("receive reset incarnation is retired"));
        }
        if !retired.iter().any(|was| was == self.incarnation) {
            if retired.len() >= RETIRED_FENCE_CAP {
                self.db.set_projection_checkpoint(&pause_name(self.target), PAUSE_FENCE)?;
                before_reset_commit()?;
                return Ok(ReceiveResetResult::PausedFence);
            }
            retired.push(self.incarnation.to_owned());
        }
        let cursor = self.db.receive_cursor(self.target)?;
        let verified = self.incarnation_verified()?;
        // Only an EMPTY unverified U with C=0 initializes silently (design §2.5).
        let initialize = !verified && cursor == 0 && self.old_namespace_empty()?;
        let reason =
            if verified { input.reason } else { ReceiveResetReason::IncarnationFirstVerified };
        self.release_terminal_compat()?;
        self.db.connection.execute(
            "DELETE FROM gateway_ack_intent WHERE target_delivery_id=?1 AND incarnation_id=?2",
            params![self.target, self.incarnation],
        )?;
        self.db.connection.execute(
            "DELETE FROM gateway_inbox_loss WHERE target_delivery_id=?1 AND incarnation_id=?2",
            params![self.target, self.incarnation],
        )?;
        let settled = input.settled.to_be_bytes();
        self.db.connection.execute(
            "UPDATE gateway_receive_epoch
             SET incarnation_id=?1, incarnation_verified=1, retired_incarnations=?2,
                 activated_cursor=?3, legacy_uncertain_through=?3
             WHERE target_delivery_id=?4",
            params![
                input.new_incarnation,
                serde_json::to_vec(&retired)?,
                settled.as_slice(),
                self.target
            ],
        )?;
        self.db.set_projection_checkpoint(
            &format!("gateway_receive_cursor:{}", self.target),
            &input.settled.to_string(),
        )?;
        self.clear_freeze()?;
        if !initialize {
            let body = serde_json::json!({
                "target_delivery_id": self.target,
                "old_incarnation": self.incarnation,
                "new_incarnation": input.new_incarnation,
                "old_cursor": cursor,
                "reason": reason.as_str(),
                "classification": "legacy_unverified",
            });
            let source = format!(
                "inbox_reset:{}:{}:{}",
                self.target, self.incarnation, input.new_incarnation
            );
            let _event =
                self.db.insert_journal(&source, "inbox.reset", &body, crate::unix_now(), None)?;
        }
        before_reset_commit()?;
        Ok(ReceiveResetResult::Reset)
    }

    /// Same-E issued<C freezes receive/settlement with `cursor_ahead` until recover.
    ///
    /// # Errors
    /// Requires the writer. Refuses a retired incarnation.
    pub fn observe_issued(&self, issued: u64) -> Result<ReceiveIssued, StorageError> {
        self.require_writer()?;
        self.refuse_retired()?;
        if self.frozen()? {
            return Ok(ReceiveIssued::Frozen);
        }
        let cursor = self.db.receive_cursor(self.target)?;
        if issued < cursor {
            self.db.set_projection_checkpoint(&freeze_name(self.target), CURSOR_AHEAD)?;
            before_reset_commit()?;
            return Ok(ReceiveIssued::Frozen);
        }
        Ok(ReceiveIssued::Live)
    }

    /// Explicit recovery from a same-E `cursor_ahead` freeze.
    ///
    /// # Errors
    /// Requires the writer.
    pub fn recover_cursor_ahead(&self) -> Result<(), StorageError> {
        self.require_writer()?;
        self.clear_freeze()
    }

    /// Cover, stage and live settle refuse a frozen inbox.
    ///
    /// # Errors
    /// Returns the exact `cursor_ahead` integrity error.
    pub(crate) fn refuse_frozen(&self) -> Result<(), StorageError> {
        if self.frozen()? {
            return Err(StorageError::Integrity(CURSOR_AHEAD));
        }
        Ok(())
    }

    fn frozen(&self) -> Result<bool, StorageError> {
        Ok(self.db.projection_checkpoint(&freeze_name(self.target))?.as_deref()
            == Some(CURSOR_AHEAD))
    }

    fn unpublished_old_loss(&self) -> Result<i64, StorageError> {
        Ok(self.db.connection.query_row(
            "SELECT count(*) FROM runtime_outbox
             WHERE published=0 AND table_name='gateway_inbox_loss'
               AND json_extract(keys_json,'$.target')=?1
               AND json_extract(keys_json,'$.incarnation')=?2",
            params![self.target, self.incarnation],
            |row| row.get(0),
        )?)
    }

    fn old_namespace_empty(&self) -> Result<bool, StorageError> {
        let rows: i64 = self.db.connection.query_row(
            "SELECT
               (SELECT count(*) FROM gateway_receive_work WHERE target_delivery_id=?1 AND incarnation_id=?2)
             + (SELECT count(*) FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2)
             + (SELECT count(*) FROM gateway_ack_intent WHERE target_delivery_id=?1 AND incarnation_id=?2)
             + (SELECT count(*) FROM gateway_inbox_loss WHERE target_delivery_id=?1 AND incarnation_id=?2)",
            params![self.target, self.incarnation],
            |row| row.get(0),
        )?;
        Ok(rows == 0)
    }

    fn incarnation_verified(&self) -> Result<bool, StorageError> {
        let verified: i64 = self.db.connection.query_row(
            "SELECT incarnation_verified FROM gateway_receive_epoch WHERE target_delivery_id=?1",
            params![self.target],
            |row| row.get(0),
        )?;
        Ok(verified != 0)
    }

    fn clear_freeze(&self) -> Result<(), StorageError> {
        self.db.connection.execute(
            "DELETE FROM projection_checkpoint WHERE projection_name=?1",
            params![freeze_name(self.target)],
        )?;
        Ok(())
    }

    fn retired_names(&self) -> Result<Vec<String>, StorageError> {
        let blob: Vec<u8> = self.db.connection.query_row(
            "SELECT retired_incarnations FROM gateway_receive_epoch WHERE target_delivery_id=?1",
            params![self.target],
            |row| row.get(0),
        )?;
        super::retired_incarnations(&blob)
    }

    fn release_terminal_compat(&self) -> Result<(), StorageError> {
        self.db.connection.execute(
            "DELETE FROM gateway_receive_work WHERE target_delivery_id=?1 AND incarnation_id=?2
             AND inbox_seq IN (
               SELECT inbox_seq FROM gateway_receive_receipt
                WHERE target_delivery_id=?1 AND incarnation_id=?2
                  AND disposition IN ('completed','rejected')
             )",
            params![self.target, self.incarnation],
        )?;
        self.db.connection.execute(
            "DELETE FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2
             AND disposition IN ('completed','rejected')",
            params![self.target, self.incarnation],
        )?;
        Ok(())
    }
}

pub(super) fn before_reset_commit() -> Result<(), StorageError> {
    if current_fault() == Fault::BeforeCommit {
        return Err(StorageError::Integrity("receive reset before-commit"));
    }
    Ok(())
}

fn freeze_name(target: &str) -> String {
    format!("gateway_receive_freeze:{target}")
}

fn pause_name(target: &str) -> String {
    format!("gateway_receive_pause:{target}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    BeforeCommit,
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

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: FaultKind, write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|slot| slot.set(Fault::None));
        }
    }
    let mapped = match fault {
        FaultKind::BeforeCommit => Fault::BeforeCommit,
    };
    FAULT.with(|slot| slot.set(mapped));
    let _reset = Reset;
    write()
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultKind {
    BeforeCommit,
}
