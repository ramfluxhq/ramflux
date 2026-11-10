// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Crash reopen for pairing journal writers that exist on main (P04).
//! Vault, [`crate::AccountIndex`], `authority.json` and node persistence cuts are later parts.

use super::journal::{AdoptionRow, FloorRow, HeadRow, LiveRow, TerminalRow};
use crate::{AccountDb, StorageError};
use rusqlite::params;

/// Writers annex F names whose production owners are not on main yet.
pub const MISSING_CRASH_WRITERS: &[(&str, &str)] = &[
    ("J0 AccountIndex/directory reservation", "P08"),
    ("J1 vault branch/data/primary commits", "P08"),
    ("J3 same-transaction head+live prepared", "P05"),
    ("J4 same-transaction head+live submitted", "P05"),
    ("J5 node authority persistence / Published", "P09"),
    ("J6 same-transaction head+live acknowledged", "P05"),
    ("J7b authority.json temp/fsync/rename/dir-fsync", "P10"),
    ("J7c same-transaction adoption+locally_installed", "P10"),
    ("J8 vault old-management provider deletion", "P14"),
    ("J7c/J8 production load/register/own-sync gates", "P10"),
];

/// Admission stays closed until install, authority, DB and vault agree (P10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Closed,
}

/// Recovered ceremony after reopen. Candidate hash is preserved after J3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveredOutcome {
    Empty,
    HandshakeCancelled { operation_id: String },
    CandidateFenced { operation_id: String, candidate_hash: String, head_state: String },
}

/// Durable pairing rows observed after recover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredPairing {
    pub floor: Option<FloorRow>,
    pub head: Option<HeadRow>,
    pub live: Vec<LiveRow>,
    pub terminals: Vec<TerminalRow>,
    pub outcome: RecoveredOutcome,
    pub admission: Admission,
}

fn field(name: &'static str) -> StorageError {
    StorageError::PairingField(name)
}

fn require(ok: bool, name: &'static str) -> Result<(), StorageError> {
    if ok { Ok(()) } else { Err(field(name)) }
}

impl RecoveredPairing {
    fn from_rows(
        floor: Option<FloorRow>,
        head: Option<HeadRow>,
        live: Vec<LiveRow>,
        terminals: Vec<TerminalRow>,
    ) -> Self {
        let outcome = if let Some(head) = &head {
            RecoveredOutcome::CandidateFenced {
                operation_id: head.operation_id.clone(),
                candidate_hash: head.candidate_hash.clone(),
                head_state: head.state.clone(),
            }
        } else if let Some(row) = terminals.iter().find(|row| row.outcome == "cancelled") {
            RecoveredOutcome::HandshakeCancelled { operation_id: row.operation_id.clone() }
        } else {
            RecoveredOutcome::Empty
        };
        Self { floor, head, live, terminals, outcome, admission: Admission::Closed }
    }
}

impl AccountDb {
    /// Commit the adopted local authority and retire its acknowledged candidate atomically.
    ///
    /// # Errors
    /// Rejects mismatched operations/hashes and rolls back the adoption if cleanup fails.
    pub fn commit_pairing_adoption_cleanup(
        &self,
        adoption: &AdoptionRow,
        terminal: &TerminalRow,
    ) -> Result<(), StorageError> {
        adoption.validate()?;
        terminal.validate()?;
        self.require_local(&adoption.account_id)?;
        self.require_local(&terminal.account_id)?;
        require(adoption.operation_id == terminal.operation_id, "operation_id")?;
        require(terminal.record_hash.as_deref() == Some(&adoption.record_hash), "record_hash")?;
        let transaction = self.connection.immediate_transaction()?;
        self.put_pairing_adoption(adoption)?;
        self.require_terminal_cleanup(terminal)?;
        self.delete_live(&terminal.account_id, &terminal.operation_id)?;
        self.delete_head(&terminal.account_id, &terminal.operation_id)?;
        self.put_pairing_terminal(terminal)?;
        transaction.commit()?;
        Ok(())
    }

    /// Commit J7c adoption and the corresponding live phase in one account transaction.
    ///
    /// # Errors
    /// Rejects malformed refs, account mismatch or a live candidate for a different hash.
    pub fn commit_pairing_install(&self, adoption: &AdoptionRow) -> Result<(), StorageError> {
        adoption.validate()?;
        self.require_local(&adoption.account_id)?;
        let transaction = self.connection.immediate_transaction()?;
        if let Some(mut live) = self
            .pairing_live_rows()?
            .into_iter()
            .find(|live| live.operation_id == adoption.operation_id)
        {
            let head = self.pairing_head()?.ok_or(field("state"))?;
            require(head.operation_id == adoption.operation_id, "operation_id")?;
            require(head.candidate_hash == adoption.record_hash, "record_hash")?;
            require(head.state == "acknowledged", "state")?;
            live.phase = "locally_installed".into();
            self.put_pairing_live(&live)?;
        }
        self.put_pairing_adoption(adoption)?;
        transaction.commit()?;
        Ok(())
    }

    /// Annex F writers whose production owners are later parts. P04J models existing writers only.
    #[must_use]
    pub const fn pairing_missing_crash_writers() -> &'static [(&'static str, &'static str)] {
        MISSING_CRASH_WRITERS
    }

    /// Reopen recovery: cancel pre-candidate live with no matching head; fence a durable candidate.
    ///
    /// # Errors
    /// Returns `PairingField("phase")` for a post-candidate live row with no matching head,
    /// or SQLite / field errors.
    pub fn recover_pairing(&self) -> Result<RecoveredPairing, StorageError> {
        let head = self.pairing_head()?;
        for live in self.pairing_live_rows()? {
            if !live_handshake_open(head.as_ref(), &live) {
                continue;
            }
            let outcome = unsubmitted_live_outcome(&live.phase)?;
            self.retire_unsubmitted_live(&live, outcome)?;
        }
        Ok(RecoveredPairing::from_rows(
            self.pairing_floor()?,
            self.pairing_head()?,
            self.pairing_live_rows()?,
            self.pairing_terminal_rows()?,
        ))
    }

    /// Load live rows for this account.
    ///
    /// # Errors
    /// Returns SQLite errors or a malformed stored row.
    pub fn pairing_live_rows(&self) -> Result<Vec<LiveRow>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT account_id,operation_id,invitation_id,issuer_seq,local_seq,generation,role,
                    descriptor,phase,context,transcript_hash,proposal_hash,transfer_ciphertext_hash,
                    candidate_id,branch_reservation,branch_vault_ref,primary_vault_ref,
                    base_record_hash,base_epoch,expires_at,result
             FROM pairing_live WHERE account_id=?1",
        )?;
        let rows: Vec<LiveRow> = statement
            .query_map(params![self.local_account_id], map_live)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for row in &rows {
            row.validate()?;
        }
        Ok(rows)
    }

    /// Load terminal rows for this account.
    ///
    /// # Errors
    /// Returns SQLite errors or a malformed stored row.
    pub fn pairing_terminal_rows(&self) -> Result<Vec<TerminalRow>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT account_id,operation_id,invitation_id,issuer_seq,local_seq,generation,outcome,
                    record_hash,finished_at,cleanup
             FROM pairing_terminal WHERE account_id=?1",
        )?;
        let rows: Vec<TerminalRow> = statement
            .query_map(params![self.local_account_id], map_terminal)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for row in &rows {
            row.validate()?;
        }
        Ok(rows)
    }

    /// J8 DB cleanup: terminal row plus live/head delete in one transaction.
    ///
    /// A prepared (unsubmitted) head is cleared by `cancelled`/`expired`/`rejected` with no
    /// `record_hash`. An acknowledged head requires `completed`, `record_hash == candidate_hash`,
    /// and a matching `pairing_adoption` row. A submitted head stays fenced. With no head, an
    /// existing terminal is immutable, a post-candidate live row is refused, and `completed` is
    /// refused.
    ///
    /// # Errors
    /// Returns `PairingField("state")` for a submitted head, `PairingField("outcome")` when an
    /// acknowledged head would be rewritten as cancelled or when `completed` has no head,
    /// `PairingField("phase")` for a post-candidate live row with no head, `PairingField("record_hash")`
    /// when the terminal or adoption hash disagrees, or SQLite errors.
    pub fn commit_pairing_terminal_cleanup(&self, row: &TerminalRow) -> Result<(), StorageError> {
        row.validate()?;
        self.require_local(&row.account_id)?;
        self.require_terminal_cleanup(row)?;
        let transaction = self.connection.immediate_transaction()?;
        self.delete_live(&row.account_id, &row.operation_id)?;
        self.delete_head(&row.account_id, &row.operation_id)?;
        self.put_pairing_terminal(row)?;
        transaction.commit()?;
        Ok(())
    }

    fn require_terminal_cleanup(&self, row: &TerminalRow) -> Result<(), StorageError> {
        match self.pairing_head()? {
            Some(head) if head.operation_id != row.operation_id => Err(field("operation_id")),
            Some(head) => match head.state.as_str() {
                "prepared" => require_prepared_cleanup(row),
                "acknowledged" => self.require_acknowledged_cleanup(&head, row),
                _ => Err(field("state")),
            },
            None => {
                if let Some(existing) = self
                    .pairing_terminal_rows()?
                    .into_iter()
                    .find(|stored| stored.operation_id == row.operation_id)
                {
                    require(existing.outcome == row.outcome, "outcome")?;
                    require(existing.record_hash == row.record_hash, "record_hash")?;
                }
                if let Some(live) = self
                    .pairing_live_rows()?
                    .into_iter()
                    .find(|stored| stored.operation_id == row.operation_id)
                {
                    unsubmitted_live_outcome(&live.phase)?;
                }
                require_prepared_cleanup(row)
            }
        }
    }

    fn require_acknowledged_cleanup(
        &self,
        head: &HeadRow,
        row: &TerminalRow,
    ) -> Result<(), StorageError> {
        require(row.outcome == "completed", "outcome")?;
        let hash = row.record_hash.as_deref().ok_or(field("record_hash"))?;
        require(hash == head.candidate_hash, "record_hash")?;
        let adoption = self.pairing_adoption()?.ok_or(field("record_hash"))?;
        require(adoption.operation_id == head.operation_id, "operation_id")?;
        require(adoption.record_hash == head.candidate_hash, "record_hash")
    }

    fn retire_unsubmitted_live(&self, live: &LiveRow, outcome: &str) -> Result<(), StorageError> {
        let terminal = TerminalRow {
            account_id: live.account_id.clone(),
            operation_id: live.operation_id.clone(),
            invitation_id: live.invitation_id.clone(),
            issuer_seq: live.issuer_seq,
            local_seq: live.local_seq,
            generation: live.generation,
            outcome: outcome.into(),
            record_hash: None,
            finished_at: self.now_unix().cast_unsigned(),
            cleanup: "none".into(),
        };
        let transaction = self.connection.immediate_transaction()?;
        self.delete_live(&live.account_id, &live.operation_id)?;
        self.put_pairing_terminal(&terminal)?;
        transaction.commit()?;
        Ok(())
    }

    fn require_local(&self, account_id: &str) -> Result<(), StorageError> {
        if account_id == self.local_account_id { Ok(()) } else { Err(field("account_id")) }
    }

    fn delete_live(&self, account_id: &str, operation_id: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM pairing_live WHERE account_id=?1 AND operation_id=?2",
            params![account_id, operation_id],
        )?;
        Ok(())
    }

    fn delete_head(&self, account_id: &str, operation_id: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM pairing_head WHERE account_id=?1 AND operation_id=?2",
            params![account_id, operation_id],
        )?;
        Ok(())
    }
}

fn live_handshake_open(head: Option<&HeadRow>, live: &LiveRow) -> bool {
    head.is_none_or(|head| head.operation_id != live.operation_id)
}

fn unsubmitted_live_outcome(phase: &str) -> Result<&'static str, StorageError> {
    match phase {
        "invited" | "commitments" | "revealed" | "sas_pending" | "mutually_confirmed"
        | "proposal_pending" | "cancelled" => Ok("cancelled"),
        "expired" => Ok("expired"),
        "rejected" => Ok("rejected"),
        _ => Err(field("phase")),
    }
}

fn require_prepared_cleanup(row: &TerminalRow) -> Result<(), StorageError> {
    require(matches!(row.outcome.as_str(), "cancelled" | "expired" | "rejected"), "outcome")?;
    require(row.record_hash.is_none(), "record_hash")
}

fn map_live(row: &crate::database::Row) -> rusqlite::Result<LiveRow> {
    Ok(LiveRow {
        account_id: row.get(0)?,
        operation_id: row.get(1)?,
        invitation_id: row.get(2)?,
        issuer_seq: row.get::<_, i64>(3)?.cast_unsigned(),
        local_seq: row.get::<_, i64>(4)?.cast_unsigned(),
        generation: row.get::<_, i64>(5)?.cast_unsigned(),
        role: row.get(6)?,
        descriptor: row.get(7)?,
        phase: row.get(8)?,
        context: row.get(9)?,
        transcript_hash: row.get(10)?,
        proposal_hash: row.get(11)?,
        transfer_ciphertext_hash: row.get(12)?,
        candidate_id: row.get(13)?,
        branch_reservation: row.get(14)?,
        branch_vault_ref: row.get(15)?,
        primary_vault_ref: row.get(16)?,
        base_record_hash: row.get(17)?,
        base_epoch: row.get::<_, i64>(18)?.cast_unsigned(),
        expires_at: row.get::<_, i64>(19)?.cast_unsigned(),
        result: row.get(20)?,
    })
}

fn map_terminal(row: &crate::database::Row) -> rusqlite::Result<TerminalRow> {
    Ok(TerminalRow {
        account_id: row.get(0)?,
        operation_id: row.get(1)?,
        invitation_id: row.get(2)?,
        issuer_seq: row.get::<_, i64>(3)?.cast_unsigned(),
        local_seq: row.get::<_, i64>(4)?.cast_unsigned(),
        generation: row.get::<_, i64>(5)?.cast_unsigned(),
        outcome: row.get(6)?,
        record_hash: row.get(7)?,
        finished_at: row.get::<_, i64>(8)?.cast_unsigned(),
        cleanup: row.get(9)?,
    })
}
