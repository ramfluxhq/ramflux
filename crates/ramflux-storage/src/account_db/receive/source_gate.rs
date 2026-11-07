// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source preparation gate: a preparation effect may run only while its W0 input is retained.
use super::ReceiveTransaction;
use crate::StorageError;
use rusqlite::params;

impl ReceiveTransaction<'_> {
    /// Refuses unless the coordinate still holds a staged or held receipt together with its
    /// work row, i.e. the recovery input every preparation effect depends on.
    ///
    /// # Errors
    /// Requires the writer transaction; refuses a missing, terminal or workless coordinate.
    pub fn require_open_input(&self, sequence: u64) -> Result<(), StorageError> {
        self.require_writer()?;
        let seq = sequence.to_be_bytes();
        let open: i64 = self.db.connection.query_row(
            "SELECT count(*) FROM gateway_receive_receipt r JOIN gateway_receive_work w \
             ON w.target_delivery_id=r.target_delivery_id AND w.incarnation_id=r.incarnation_id \
             AND w.inbox_seq=r.inbox_seq \
             WHERE r.target_delivery_id=?1 AND r.incarnation_id=?2 AND r.inbox_seq=?3 \
             AND r.disposition IN ('staged','held')",
            params![self.target, self.incarnation, seq.as_slice()],
            |row| row.get(0),
        )?;
        if open == 0 {
            return Err(StorageError::Integrity("source effect requires staged receive work"));
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-instrumentation"))]
impl crate::AccountDb {
    /// Test support: installs the receive epoch row the dormant ledger expects.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn seed_receive_epoch_for_test(
        &self,
        target: &str,
        incarnation: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT INTO gateway_receive_epoch VALUES(?1,?2,1,x'',?3,?3)",
            params![target, incarnation, 0u64.to_be_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Test support: the receipt disposition and the work-row count of the whole ledger.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn receive_state_for_test(
        &self,
        sequence: u64,
    ) -> Result<(Option<String>, i64), StorageError> {
        use rusqlite::OptionalExtension;
        let seq = sequence.to_be_bytes();
        let disposition = self
            .connection
            .query_row(
                "SELECT disposition FROM gateway_receive_receipt WHERE inbox_seq=?1",
                params![seq.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let work =
            self.connection
                .query_row("SELECT count(*) FROM gateway_receive_work", [], |r| r.get(0))?;
        Ok((disposition, work))
    }

    /// Test support: advances the private-erasure generation as an erase would.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn advance_erasure_generation_for_test(&self) -> Result<(), StorageError> {
        self.connection
            .execute("UPDATE account_erasure_generation SET generation=generation+1", [])?;
        Ok(())
    }
}
