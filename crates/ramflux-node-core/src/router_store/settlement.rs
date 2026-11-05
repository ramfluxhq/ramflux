// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiver cursor candidates are validated against durable rows and publication
//! before commit. The transaction serializes receiver checkpoints without holding
//! the publication data mutex across storage I/O. New allocations are above this
//! observed prefix; resolving an existing guard can only enlarge it.
use super::{
    CursorAckState, NodeCoreError, ROUTER_INBOX_ENTRY_TABLE, ReadableTable, RouterRedbStore,
    expiry_index, inbox_entry_storage_key, incarnation, incarnation_state,
};

pub(crate) fn retires(cursor: &CursorAckState, seq: u64) -> bool {
    cursor.last_acknowledged_inbox_seq == Some(seq)
        || cursor.acked_inbox_seqs.contains(&seq)
        || cursor.retired_inbox_seqs.contains(&seq)
}

impl RouterRedbStore {
    pub(super) fn receiver_settlement(
        &self,
        txn: &redb::WriteTransaction,
        incoming: &CursorAckState,
        previous: Option<&CursorAckState>,
    ) -> Result<(CursorAckState, Option<String>), NodeCoreError> {
        let mut cursor = incoming.clone();
        let metadata = incarnation_state::read(txn, &cursor.target_delivery_id)?;
        let Some((id, issued)) = metadata else {
            return Ok((cursor, None));
        };
        let previous_r = previous.map_or(0, |old| old.settled_inbox_seq);
        // Keep independently committed out-of-order dispositions during concurrent
        // receiver updates. Other checkpoint writers share the persisted cursor.
        if let Some(old) = previous {
            cursor.acked_inbox_seqs.extend(old.acked_inbox_seqs.iter().copied());
        }
        // A core initializer holds this mutex while waiting for the DB writer.
        // Never wait on it while this transaction owns that writer. Contention
        // keeps the last committed floor; a later receiver checkpoint can advance.
        let installed = self.publication.try_lock().ok().map(|core| core.clone());
        let mut settled = installed.map_or(previous_r, |core| {
            core.as_ref()
                .map_or(issued, |core| core.settled_view(&cursor.target_delivery_id, &id).0)
        });
        let entries = txn.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(incarnation::error)?;
        let start =
            inbox_entry_storage_key(&cursor.target_delivery_id, previous_r.saturating_add(1));
        let end = inbox_entry_storage_key(&cursor.target_delivery_id, u64::MAX);
        for row in entries.range(start.as_str()..=end.as_str()).map_err(incarnation::error)? {
            let (_, bytes) = row.map_err(incarnation::error)?;
            let (entry, _) = expiry_index::decode_entry(bytes.value())?;
            if !retires(&cursor, entry.inbox_seq) {
                settled = settled.min(entry.inbox_seq.saturating_sub(1));
                break;
            }
        }
        if let Some(wal) = &self.submission_wal
            && let Some(seq) = wal.settlement_head(&cursor, previous_r)?
        {
            settled = settled.min(seq.saturating_sub(1));
        }
        cursor.settled_inbox_seq = settled;
        cursor.acked_inbox_seqs.retain(|seq| *seq > settled);
        Ok((cursor, Some(id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router_store::{
        incarnation::test_store,
        publication::tests::{entry, fixture},
    };
    use redb::ReadableDatabase;

    #[test]
    fn receiver_checkpoint_does_not_wait_for_core_initializer_under_writer()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture("settlement-initializer");
        let store = std::sync::Arc::new(test_store(&root, 0, 1 << 20)?);
        store.record_inbox_entry(&entry(1))?;
        let (committed, observed) = std::sync::mpsc::sync_channel(1);
        let signal = std::sync::Mutex::new(Some(committed));
        let registration = crate::durability_test_hooks::observe(
            root.clone(),
            std::sync::Arc::new(move |_, operation, done| {
                if operation == "direct_commit"
                    && done
                    && let Some(signal) =
                        signal.lock().map_err(|_| std::io::Error::other("signal lock"))?.take()
                {
                    signal.send(()).map_err(std::io::Error::other)?;
                }
                Ok(())
            }),
        );
        // Model an initializer holding publication installation while waiting
        // for this receiver's DB writer. The receiver must reach commit first.
        let initializing = store.publication.lock().map_err(incarnation::error)?;
        let worker_store = std::sync::Arc::clone(&store);
        let worker = std::thread::spawn(move || {
            worker_store.record_ack_increment(
                &CursorAckState {
                    target_delivery_id: "target".into(),
                    last_acknowledged_inbox_seq: Some(1),
                    acked_inbox_seqs: [1].into(),
                    ..CursorAckState::default()
                },
                "entry-1",
            )
        });
        let reached = observed.recv_timeout(std::time::Duration::from_secs(5));
        drop(initializing);
        worker.join().map_err(|_| incarnation::error("receiver worker panicked"))??;
        reached?;
        let tx = store.db.begin_read()?;
        let table = tx.open_table(crate::ROUTER_CURSOR_STATE_TABLE)?;
        let row = table.get("target")?.ok_or("cursor")?;
        let cursor = incarnation::decode_cursor(row.value())?;
        assert_eq!(cursor.settled_inbox_seq, 0, "contention preserves committed R");
        assert!(cursor.acked_inbox_seqs.contains(&1), "ACK disposition still commits");
        drop(row);
        drop(table);
        drop(tx);
        drop(registration);
        drop(store);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
