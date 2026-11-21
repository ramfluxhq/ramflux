// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! J6 and the single source tail read cut share the actual all-writer fence.
use super::{AccountDb, FullTransferCut, StorageError};
use crate::HeadRow;
use rusqlite::params;
use std::time::{Duration, Instant};
fn busy() -> StorageError {
    StorageError::PairingField("Busy")
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
fn b32(value: &str) -> Result<(), StorageError> {
    let bytes = ramflux_protocol::decode_base64url(value).map_err(|_| wrong())?;
    if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != value {
        return Err(wrong());
    }
    Ok(())
}
impl AccountDb {
    pub(in crate::account_db) fn commit_full_ack_tail(
        &self,
        head: &HeadRow,
        stage_id: &str,
        snapshot_id: &str,
        abandon: bool,
        owner: &crate::FullSourcePrimaryOwner,
    ) -> Result<FullTransferCut, StorageError> {
        crate::account_db::pairing::journal::decode_head(head)?;
        if head.account_id != self.local_account_id
            || head.kind != "transfer"
            || head.state != "acknowledged"
        {
            return Err(wrong());
        }
        b32(owner.reference())?;
        b32(owner.public_key())?;
        let primary_ref = owner.reference().to_owned();
        let old_self_key = owner.public_key().to_owned();
        b32(stage_id)?;
        b32(snapshot_id)?;
        self.require_selected_transfer_source()?;
        // Open/key the independent reader before quiescing ordinary writes. Its
        // transaction starts only inside the fence; it retains no original writer.
        let reader = self.open_reader()?;
        let unlocked_owner = self.connection.downgrade();
        let head = head.clone();
        let stage_id = stage_id.to_owned();
        let snapshot_id = snapshot_id.to_owned();
        let outcome = self.connection.call_generation(move |raw| {
            let result=(|| -> Result<FullTransferCut,StorageError> {
                let deadline=Instant::now()+Duration::from_secs(10);
                // A newly created account may not have initialized ordinary runtime
                // yet. WAL permits the pinned pre-ACK content view to survive COMMIT.
                let journal:String=raw.query_row("PRAGMA journal_mode=WAL",[],|row|row.get(0))?;
                if journal!="wal" || Instant::now()>=deadline {return Err(busy());}
                let tx=raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let exact:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM pairing_head WHERE account_id=?1 AND operation_id=?2 AND kind='transfer' AND state='submitted' AND candidate_hash=?3 AND candidate=?4 AND publisher_ref=?5 AND recipient_ref=?6 AND generation=?7 AND base_record_hash=?8 AND base_epoch=?9)",params![head.account_id,head.operation_id,head.candidate_hash,head.candidate,head.publisher_ref,head.recipient_ref,head.generation,head.base_record_hash,head.base_epoch],|row|row.get(0))?;
                if !exact {return Err(wrong());}
                let terminal:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM pairing_live WHERE account_id=?1 AND operation_id=?2 AND phase IN ('cancelled','expired','rejected','completed'))",params![head.account_id,head.operation_id],|row|row.get(0))?;
                if terminal && !abandon {return Err(wrong());}
                let existing:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM pairing_full_tail WHERE account_id=?1 AND (operation_id=?2 OR tail_status='pending'))",params![head.account_id,head.operation_id],|row|row.get(0))?;
                if existing {return Err(StorageError::PairingField("ResumeRequired"));}
                let snapshot=reader.connection.deferred_transaction()?;
                let _:String=reader.connection.query_row("SELECT key_fingerprint FROM account_key_check WHERE singleton_id=1",[],|row|row.get(0))?;
                snapshot.pin_read_snapshot()?;
                // No content mutation occurs between this read cut and J6. Other
                // SQLite writers are excluded by IMMEDIATE; all local workers queue.
                if Instant::now()>=deadline {return Err(busy());}
                if tx.execute("UPDATE pairing_head SET state='acknowledged',ack=?1 WHERE account_id=?2 AND operation_id=?3 AND candidate_hash=?4 AND state='submitted'",params![head.ack,head.account_id,head.operation_id,head.candidate_hash])?!=1 {return Err(wrong());}
                tx.execute("UPDATE pairing_live SET phase=CASE WHEN ?4 THEN CASE WHEN phase IN ('cancelled','expired','rejected','completed') THEN phase ELSE 'cancelled' END ELSE 'acknowledged' END,candidate_id=?1,proposal_hash=COALESCE(proposal_hash,?2) WHERE account_id=?3 AND operation_id=?1",params![head.operation_id,head.candidate_hash,head.account_id,abandon])?;
                if tx.execute("INSERT INTO pairing_full_tail VALUES(?1,?2,?3,?4,?5,?6,'pinned') ON CONFLICT(account_id) DO UPDATE SET operation_id=excluded.operation_id,stage_id=excluded.stage_id,snapshot_id=excluded.snapshot_id,record_hash=excluded.record_hash,tail_status=excluded.tail_status,cut_state='pinned' WHERE pairing_full_tail.tail_status!='pending' OR EXISTS(SELECT 1 FROM pairing_full_completion c WHERE c.operation_id=pairing_full_tail.operation_id AND c.cleanup_state='done')",params![head.account_id,head.operation_id,stage_id,snapshot_id,head.candidate_hash,if abandon {"abandoned"} else {"pending"}])? != 1 { return Err(wrong()); }
                let owners:u64=tx.query_row("SELECT count(*) FROM pairing_source_cleanup",[],|row|row.get(0))?;
                if owners>=128 {return Err(StorageError::PairingField("LocalQuotaExceeded"));}
                tx.execute("INSERT INTO pairing_source_cleanup VALUES(?1,?2,?3,?4,?5,?6)",params![head.account_id,head.operation_id,head.candidate_hash,head.publisher_ref,primary_ref,old_self_key])?;
                if Instant::now()>=deadline {return Err(busy());}
                tx.commit()?;
                Ok(FullTransferCut {reader,unlocked_owner})
            })();
            (Ok(result),false)
        }).map_err(StorageError::from).and_then(std::convert::identity);
        outcome.map_err(|error| {
            if matches!(&error, StorageError::Sqlite(sql) if matches!(sql.sqlite_error_code(),Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked))) {busy()} else {error}
        })
    }
}

#[cfg(test)]
mod tests;
