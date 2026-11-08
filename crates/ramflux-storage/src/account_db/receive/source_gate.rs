// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source preparation gate: a preparation effect may run only while its W0 input is retained.
use super::ReceiveTransaction;
use crate::StorageError;
use rusqlite::params;

impl ReceiveTransaction<'_> {
    /// Refuses unless the coordinate still holds a staged or held receipt together with its
    /// work row, i.e. the recovery input every preparation effect depends on. A retired
    /// incarnation is allowed for already-retained work (local redrive); new stage/cover
    /// still refuse it.
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

    /// Test support: every row of the durable effect tables, rendered column by column and
    /// sorted, so a before/after comparison covers values, not just key names or counts.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn durable_rows_for_test(&self) -> Result<Vec<String>, StorageError> {
        const TABLES: [&str; 8] = [
            "runtime_actor_state",
            "message_copy_binding",
            "message_footprint",
            "direct_message_projection",
            "object_key_slot",
            "group_sender_key_counter_seen",
            "gateway_receive_receipt",
            "gateway_receive_work",
        ];
        let mut rows = Vec::new();
        for table in TABLES {
            let columns = self
                .connection
                .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            // quote() renders NULL, integers, reals, text and blobs unambiguously in one string.
            let cells = columns
                .iter()
                .map(|column| format!("quote(\"{column}\")"))
                .collect::<Vec<_>>()
                .join("||'|'||");
            rows.extend(
                self.connection
                    .prepare(&format!("SELECT '{table}|'||{cells} FROM {table}"))?
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        rows.sort();
        Ok(rows)
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

    /// Test support: set receipt disposition without touching the work row (P12 L2 pin).
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn set_receipt_disposition_for_test(
        &self,
        sequence: u64,
        disposition: &str,
    ) -> Result<(), StorageError> {
        let seq = sequence.to_be_bytes();
        self.connection.execute(
            "UPDATE gateway_receive_receipt SET disposition=?1 WHERE inbox_seq=?2",
            params![disposition, seq.as_slice()],
        )?;
        Ok(())
    }

    /// Test support: verified inbox-policy row used as the hold source bucket.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn seed_inbox_policy_for_test(&self, key: &str, source: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT INTO runtime_inbox_policy VALUES(?1,?2,1,1,604801,0,'none','',0,0)",
            params![key, source],
        )?;
        Ok(())
    }

    /// Test support: overwrite staged work `byte_len` without a multi-MiB payload.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn set_receive_work_bytes_for_test(
        &self,
        sequence: u64,
        byte_len: i64,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE gateway_receive_work SET entry_json=zeroblob(?1), byte_len=?1 WHERE inbox_seq=?2",
            params![byte_len, sequence.to_be_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Test support: retry and policy row counts for one admission key.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn inbox_retry_and_policy_counts_for_test(
        &self,
        key: &str,
    ) -> Result<(i64, i64), StorageError> {
        let retry = self.connection.query_row(
            "SELECT count(*) FROM runtime_inbox_retry WHERE envelope_key=?1",
            params![key],
            |row| row.get(0),
        )?;
        let policy = self.connection.query_row(
            "SELECT count(*) FROM runtime_inbox_policy WHERE envelope_key=?1",
            params![key],
            |row| row.get(0),
        )?;
        Ok((retry, policy))
    }

    /// Test support: retire the live E so a new incarnation can redrive the same key.
    ///
    /// # Errors
    /// Returns SQL or encoding errors.
    pub fn retire_receive_incarnation_for_test(
        &self,
        target: &str,
        live: &str,
        next: &str,
    ) -> Result<(), StorageError> {
        use crate::ProjectionStore;
        self.connection.execute(
            "UPDATE gateway_receive_epoch
             SET incarnation_id=?2, retired_incarnations=?3
             WHERE target_delivery_id=?1",
            params![target, next, serde_json::to_vec(&[live])?],
        )?;
        self.connection.execute(
            "UPDATE gateway_receive_receipt SET first_seen=0 WHERE incarnation_id=?1",
            params![live],
        )?;
        self.set_projection_checkpoint(&format!("gateway_receive_cursor:{target}"), "0")?;
        Ok(())
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

    /// Test support: pin ACK-intent clocks so flush-timing tests do not wait on the wall clock.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn set_ack_intent_clock_for_test(
        &self,
        created_at: i64,
        next_attempt_at: i64,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE gateway_ack_intent SET created_at=?1, next_attempt_at=?2",
            params![created_at, next_attempt_at],
        )?;
        Ok(())
    }

    /// Test support: leftover terminal work+receipt the P18 executor keeps until WA/reset.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn seed_compat_terminal_for_test(
        &self,
        target: &str,
        incarnation: &str,
        sequence: u64,
        entry: &[u8],
    ) -> Result<(), StorageError> {
        insert_receipt_work(self, target, incarnation, sequence, "completed", "compat", entry)
    }

    /// Test support: a held receipt+work row that reset must retain.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn seed_held_receive_for_test(
        &self,
        target: &str,
        incarnation: &str,
        sequence: u64,
        entry: &[u8],
    ) -> Result<(), StorageError> {
        insert_receipt_work(self, target, incarnation, sequence, "held", "held", entry)
    }

    /// Test support: rewrite the live epoch name (empty-U simulation) without a reset write.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn rewrite_receive_incarnation_for_test(
        &self,
        target: &str,
        from: &str,
        to: &str,
        verified: bool,
    ) -> Result<(), StorageError> {
        self.connection.execute_batch("PRAGMA foreign_keys=OFF")?;
        let rewritten = (|| {
            self.connection.execute(
                "UPDATE gateway_receive_epoch SET incarnation_id=?1, incarnation_verified=?2 WHERE target_delivery_id=?3",
                params![to, i64::from(verified), target],
            )?;
            self.connection.execute(
                "UPDATE gateway_receive_receipt SET incarnation_id=?1 WHERE target_delivery_id=?2 AND incarnation_id=?3",
                params![to, target, from],
            )?;
            self.connection.execute(
                "UPDATE gateway_receive_work SET incarnation_id=?1 WHERE target_delivery_id=?2 AND incarnation_id=?3",
                params![to, target, from],
            )?;
            self.connection.execute(
                "UPDATE gateway_ack_intent SET incarnation_id=?1 WHERE target_delivery_id=?2 AND incarnation_id=?3",
                params![to, target, from],
            )?;
            Ok(())
        })();
        self.connection.execute_batch("PRAGMA foreign_keys=ON")?;
        rewritten
    }

    /// Test support: cursor, losses, receipts, intents and work for one target.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn receive_ledger_snap_for_test(
        &self,
        target: &str,
    ) -> Result<ReceiveLedgerSnap, StorageError> {
        use crate::ProjectionStore;
        let cursor = self
            .projection_checkpoint(&format!("gateway_receive_cursor:{target}"))?
            .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?;
        let mut losses = Vec::new();
        let mut query = self.connection.prepare(
            "SELECT from_seq,to_seq,count,reason FROM gateway_inbox_loss WHERE target_delivery_id=?1 ORDER BY from_seq",
        )?;
        for row in query.query_map(params![target], |row| {
            Ok((
                be_seq(&row.get::<_, Vec<u8>>(0)?),
                be_seq(&row.get::<_, Vec<u8>>(1)?),
                be_seq(&row.get::<_, Vec<u8>>(2)?),
                row.get(3)?,
            ))
        })? {
            losses.push(row?);
        }
        let mut receipts = Vec::new();
        let mut query = self.connection.prepare(
            "SELECT inbox_seq,disposition FROM gateway_receive_receipt WHERE target_delivery_id=?1 ORDER BY inbox_seq",
        )?;
        for row in query.query_map(params![target], |row| {
            Ok((be_seq(&row.get::<_, Vec<u8>>(0)?), row.get(1)?))
        })? {
            receipts.push(row?);
        }
        let mut intents = Vec::new();
        let mut query = self.connection.prepare(
            "SELECT inbox_seq FROM gateway_ack_intent WHERE target_delivery_id=?1 ORDER BY inbox_seq",
        )?;
        for row in query.query_map(params![target], |row| Ok(be_seq(&row.get::<_, Vec<u8>>(0)?)))? {
            intents.push(row?);
        }
        let work = self.connection.query_row(
            "SELECT count(*) FROM gateway_receive_work WHERE target_delivery_id=?1",
            params![target],
            |row| row.get(0),
        )?;
        // Every runtime_outbox row (gap outbox included), so duplicate effects are visible.
        let mut outbox = Vec::new();
        let mut query = self.connection.prepare(
            "SELECT table_name,change_kind,published,keys_json FROM runtime_outbox ORDER BY keys_json,table_name,change_kind",
        )?;
        for row in
            query.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
        {
            outbox.push(row?);
        }
        Ok(ReceiveLedgerSnap { cursor, losses, receipts, intents, work, outbox })
    }
}

/// Value snapshot of ledger rows used by SDK page-apply tests.
#[cfg(any(test, feature = "test-instrumentation"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveLedgerSnap {
    pub cursor: u64,
    pub losses: Vec<(u64, u64, u64, String)>,
    pub receipts: Vec<(u64, String)>,
    pub intents: Vec<u64>,
    pub work: i64,
    /// `(table_name, change_kind, published, keys_json)` for every `runtime_outbox` row.
    pub outbox: Vec<(String, String, i64, String)>,
}

#[cfg(any(test, feature = "test-instrumentation"))]
#[allow(clippy::too_many_arguments)]
fn insert_receipt_work(
    db: &crate::AccountDb,
    target: &str,
    incarnation: &str,
    sequence: u64,
    disposition: &str,
    admission: &str,
    entry: &[u8],
) -> Result<(), StorageError> {
    let seq = sequence.to_be_bytes();
    let length = i64::try_from(entry.len())
        .map_err(|_| StorageError::Integrity("receive entry byte bound"))?;
    db.connection.execute(
        "INSERT INTO gateway_receive_receipt VALUES(?1,?2,?3,?4,100,1)",
        params![target, incarnation, seq.as_slice(), disposition],
    )?;
    db.connection.execute(
        "INSERT INTO gateway_receive_work VALUES(?1,?2,?3,?4,?5,?6)",
        params![target, incarnation, seq.as_slice(), entry, admission, length],
    )?;
    Ok(())
}

#[cfg(any(test, feature = "test-instrumentation"))]
fn be_seq(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    if bytes.len() == 8 {
        buf.copy_from_slice(bytes);
    }
    u64::from_be_bytes(buf)
}
