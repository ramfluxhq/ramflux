// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Monotonic consent/deletion fences and requester-authority floors across snapshot merge.
use super::backup_database::BackupDatabase;
use crate::StorageError;
impl BackupDatabase {
    pub(super) fn merge_contact_fences(&self) -> Result<(), StorageError> {
        self.db.execute_batch("INSERT INTO contact_request_authority_floor(root,epoch,record_hash,until) SELECT root,epoch,record_hash,until FROM incoming.contact_request_authority_floor WHERE 1 ON CONFLICT(root) DO UPDATE SET epoch=MAX(contact_request_authority_floor.epoch,excluded.epoch),record_hash=CASE WHEN excluded.epoch>contact_request_authority_floor.epoch THEN excluded.record_hash ELSE contact_request_authority_floor.record_hash END,until=MAX(contact_request_authority_floor.until,excluded.until); INSERT INTO contact_request_fence(root,state,until) SELECT root,state,until FROM incoming.contact_request_fence WHERE 1 ON CONFLICT(root) DO UPDATE SET state=CASE WHEN contact_request_fence.state='blocked' OR excluded.state='blocked' THEN 'blocked' ELSE 'declined' END,until=MAX(contact_request_fence.until,excluded.until);")?;
        let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE name='contact_message_request_fence')",[],|r|r.get(0))?;
        if exists {
            self.db.execute_batch("INSERT OR IGNORE INTO contact_message_request_fence SELECT sender_identity,message_id FROM incoming.contact_message_request_fence;")?;
        }
        Ok(())
    }
    pub(super) fn apply_merged_contact_fences(&self) -> Result<(), StorageError> {
        self.db.execute_batch("UPDATE contact_request_projection SET state=(SELECT state FROM contact_request_fence f WHERE f.root=contact_identity_commitment) WHERE EXISTS(SELECT 1 FROM contact_request_fence f WHERE f.root=contact_identity_commitment AND (f.state='blocked' OR contact_request_projection.state<>'blocked')); DELETE FROM contact_message_request WHERE EXISTS(SELECT 1 FROM contact_message_request_fence f WHERE f.sender_identity=contact_message_request.sender_identity AND f.message_id=contact_message_request.message_id) OR EXISTS(SELECT 1 FROM direct_message_projection d WHERE d.message_id=contact_message_request.message_id AND d.conversation_id=contact_message_request.conversation_id) OR EXISTS(SELECT 1 FROM message_tombstone_projection t WHERE t.message_id=contact_message_request.message_id AND t.conversation_id=contact_message_request.conversation_id) OR EXISTS(SELECT 1 FROM contact_request_fence f WHERE f.root=contact_message_request.contact_identity_commitment) OR EXISTS(SELECT 1 FROM contact_request_projection r WHERE r.contact_identity_commitment=contact_message_request.contact_identity_commitment AND r.direction='inbound' AND r.state IN ('declined','blocked'));")?;
        Ok(())
    }
}
