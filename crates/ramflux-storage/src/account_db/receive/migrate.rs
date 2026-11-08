// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Direct pre-ledger migration. Preserves C, activates at C, and fences uncertainty
//! through the first issued P. Does not import S and does not emit `inbox_reset`.
//! Dormant until P24 activation wires it. Entry points require the caller's writer.
use super::ReceiveTransaction;
use super::cover::ReceiveGap;
use crate::{AccountDb, ProjectionStore, StorageError};
use rusqlite::params;

/// Direct-upgrade bind of the first verified incarnation onto a pre-ledger inbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveMigrate<'a> {
    pub target: &'a str,
    pub incarnation: &'a str,
}

/// Migration either installs the epoch or finds it already present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReceiveMigrateResult {
    /// Epoch, imported holds and preserved C were written.
    Migrated,
    /// This target already has an epoch; U→E uses reset instead.
    Existing,
}

impl AccountDb {
    /// Installs the ledger epoch for a pre-ledger DB: preserve C, activated=C,
    /// import retries/unrouted as held receipts, no fence and no reset event.
    ///
    /// # Errors
    /// Requires an open writer transaction. Refuses a missing target or incarnation.
    pub fn migrate_direct(
        &self,
        input: ReceiveMigrate<'_>,
    ) -> Result<ReceiveMigrateResult, StorageError> {
        if self.connection.is_autocommit()? {
            return Err(StorageError::AuthorizationRejected);
        }
        if input.target.is_empty() || input.incarnation.is_empty() {
            return Err(StorageError::Integrity("receive migrate identity missing"));
        }
        self.install_receive_ledger_schema()?;
        let exists: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_receive_epoch WHERE target_delivery_id=?1)",
            params![input.target],
            |row| row.get(0),
        )?;
        if exists != 0 {
            return Ok(ReceiveMigrateResult::Existing);
        }
        self.import_local_holds(input)?;
        let cursor = self.receive_cursor(input.target)?;
        let activated = cursor.to_be_bytes();
        self.connection.execute(
            "INSERT INTO gateway_receive_epoch VALUES(?1,?2,1,?3,?4,?5)",
            params![
                input.target,
                input.incarnation,
                serde_json::to_vec(&Vec::<String>::new())?,
                activated.as_slice(),
                0u64.to_be_bytes().as_slice()
            ],
        )?;
        Ok(ReceiveMigrateResult::Migrated)
    }

    pub(crate) fn receive_cursor(&self, target: &str) -> Result<u64, StorageError> {
        self.projection_checkpoint(&format!("gateway_receive_cursor:{target}"))?
            .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))
    }

    fn import_local_holds(&self, input: ReceiveMigrate<'_>) -> Result<(), StorageError> {
        let mut unrouted = self
            .connection
            .prepare("SELECT envelope_id,inbox_seq,entry_json,received_at FROM runtime_unrouted")?;
        let rows = unrouted.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (id, seq, entry, at) = row?;
            let Ok(sequence) = u64::try_from(seq) else {
                continue;
            };
            self.insert_imported_hold(input, sequence, &id, &entry, at)?;
        }
        let mut retries = self
            .connection
            .prepare("SELECT envelope_key,entry_json,created_at FROM runtime_inbox_retry")?;
        let rows = retries.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?))
        })?;
        for row in rows {
            let (key, entry, at) = row?;
            let Some(sequence) = seq_from_entry(&entry) else {
                continue;
            };
            self.insert_imported_hold(input, sequence, &key, &entry, at)?;
        }
        Ok(())
    }

    fn insert_imported_hold(
        &self,
        input: ReceiveMigrate<'_>,
        sequence: u64,
        admission: &str,
        entry: &[u8],
        at: i64,
    ) -> Result<(), StorageError> {
        if sequence == 0 || entry.is_empty() {
            return Ok(());
        }
        let seq = sequence.to_be_bytes();
        let length = i64::try_from(entry.len())
            .map_err(|_| StorageError::Integrity("receive entry byte bound"))?;
        self.connection.execute(
            "INSERT OR IGNORE INTO gateway_receive_receipt VALUES(?1,?2,?3,'held',?4,?5)",
            params![
                input.target,
                input.incarnation,
                seq.as_slice(),
                at.saturating_add(604_800),
                at
            ],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO gateway_receive_work VALUES(?1,?2,?3,?4,?5,?6)",
            params![input.target, input.incarnation, seq.as_slice(), entry, admission, length],
        )?;
        Ok(())
    }
}

impl ReceiveTransaction<'_> {
    /// First capable page of a direct migration: set the uncertainty fence to issued P
    /// and write `legacy_unverified` for each missing interval in `(C, S]`. C is unchanged.
    ///
    /// # Errors
    /// Requires the writer; refuses a retired or frozen inbox and an invalid `0<=S<=P`.
    pub fn fence_first_page(&self, settled: u64, issued: u64) -> Result<(), StorageError> {
        self.require_writer()?;
        self.refuse_retired()?;
        self.refuse_frozen()?;
        if settled > issued {
            return Err(StorageError::Integrity("receive reset settled prefix invalid"));
        }
        let uncertain = self.epoch_u64(
            "SELECT legacy_uncertain_through FROM gateway_receive_epoch WHERE target_delivery_id=?1",
        )?;
        if uncertain == issued {
            return Ok(());
        }
        let cursor = self.db.receive_cursor(self.target)?;
        let present = self.receipts_in(cursor, settled)?;
        let now = crate::unix_now();
        for (from, to) in missing_ranges(cursor, settled, &present) {
            self.write_gap(
                &ReceiveGap {
                    from_seq: from,
                    to_seq: to,
                    reason: "unknown",
                    classification: "legacy_unverified",
                },
                now,
            )?;
        }
        let issued_bytes = issued.to_be_bytes();
        self.db.connection.execute(
            "UPDATE gateway_receive_epoch SET legacy_uncertain_through=?1 WHERE target_delivery_id=?2",
            params![issued_bytes.as_slice(), self.target],
        )?;
        super::reset::before_reset_commit()?;
        Ok(())
    }

    pub(crate) fn epoch_u64(&self, sql: &str) -> Result<u64, StorageError> {
        let bytes: Vec<u8> =
            self.db.connection.query_row(sql, params![self.target], |row| row.get(0))?;
        let arr: [u8; 8] =
            bytes.try_into().map_err(|_| StorageError::Integrity("receive sequence encoding"))?;
        Ok(u64::from_be_bytes(arr))
    }

    fn receipts_in(&self, cursor: u64, settled: u64) -> Result<Vec<u64>, StorageError> {
        if settled == 0 || settled <= cursor {
            return Ok(Vec::new());
        }
        let from = cursor.saturating_add(1).to_be_bytes();
        let to = settled.to_be_bytes();
        let mut query = self.db.connection.prepare(
            "SELECT inbox_seq FROM gateway_receive_receipt
             WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq>=?3 AND inbox_seq<=?4
             ORDER BY inbox_seq",
        )?;
        let rows = query.query_map(
            params![self.target, self.incarnation, from.as_slice(), to.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut out = Vec::new();
        for row in rows {
            let bytes = row?;
            let seq = u64::from_be_bytes(
                bytes
                    .try_into()
                    .map_err(|_| StorageError::Integrity("receive sequence encoding"))?,
            );
            out.push(seq);
        }
        Ok(out)
    }
}

fn seq_from_entry(entry: &[u8]) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_slice(entry).ok()?;
    value.get("inbox_seq")?.as_u64()
}

fn missing_ranges(cursor: u64, settled: u64, present: &[u64]) -> Vec<(u64, u64)> {
    let Some(start) = cursor.checked_add(1) else {
        return Vec::new();
    };
    if start > settled {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut next = start;
    for &seq in present {
        if seq < next || seq > settled {
            continue;
        }
        if seq > next {
            ranges.push((next, seq - 1));
        }
        next = seq.saturating_add(1);
    }
    if next <= settled {
        ranges.push((next, settled));
    }
    ranges
}

#[cfg(test)]
mod range_tests {
    use super::missing_ranges;

    #[test]
    fn missing_ranges_splits_around_receipts() {
        assert_eq!(missing_ranges(10, 20, &[]), vec![(11, 20)]);
        assert_eq!(missing_ranges(10, 20, &[15]), vec![(11, 14), (16, 20)]);
        assert_eq!(missing_ranges(10, 10, &[]), Vec::<(u64, u64)>::new());
        assert_eq!(missing_ranges(20, 10, &[]), Vec::<(u64, u64)>::new());
    }
}
