// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compact consent fences and bounded retirement of private request records.
use super::AccountDb;
use crate::{ContactRequestRecord, StorageError};
use rusqlite::{OptionalExtension, params};
impl AccountDb {
    /// Read a compact rollback fence; it cannot authenticate a device.
    /// # Errors
    /// Returns SQL failures.
    pub fn contact_request_authority_floor(
        &self,
        root: &str,
        now: i64,
    ) -> Result<Option<(u64, String)>, StorageError> {
        Ok(self.connection.query_row("SELECT epoch,record_hash FROM contact_request_authority_floor WHERE root=?1 AND until>?2",params![root,now],|row|Ok((row.get(0)?,row.get(1)?))).optional()?)
    }
    /// Reserve one of 4096 compact rollback fences before retaining new requester material.
    /// # Errors
    /// Returns SQL failures; false means admission must wait for capacity.
    pub fn retain_contact_request_authority_floor(
        &self,
        root: &str,
        epoch: u64,
        hash: &str,
        until: i64,
        now: i64,
    ) -> Result<bool, StorageError> {
        self.write_transaction(|| {
            self.connection.execute("DELETE FROM contact_request_authority_floor WHERE root=?1 AND until<=?2",params![root,now])?;
            let exists:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM contact_request_authority_floor WHERE root=?1)",params![root],|row|row.get(0))?;
            let count:u64=self.connection.query_row("SELECT count(*) FROM contact_request_authority_floor",[],|row|row.get(0))?;
            if !exists && count >= 4096 {
                // Expired floors no longer protect reads. Free only the oldest required slots.
                self.connection.execute("DELETE FROM contact_request_authority_floor WHERE root IN (SELECT root FROM contact_request_authority_floor WHERE until<=?1 ORDER BY until,root LIMIT ?2)", params![now,count.saturating_sub(4095)])?;
                let remaining:u64=self.connection.query_row("SELECT count(*) FROM contact_request_authority_floor",[],|row|row.get(0))?;
                if remaining >= 4096 { return Ok(false); }
            }
            self.connection.execute("INSERT INTO contact_request_authority_floor VALUES(?1,?2,?3,?4) ON CONFLICT(root) DO UPDATE SET epoch=excluded.epoch,record_hash=excluded.record_hash,until=MAX(contact_request_authority_floor.until,excluded.until) WHERE excluded.epoch>contact_request_authority_floor.epoch OR (excluded.epoch=contact_request_authority_floor.epoch AND excluded.record_hash=contact_request_authority_floor.record_hash)",params![root,epoch,hash,until])?;
            Ok(true)
        })
    }
    /// Returns live floor count and the subset without any unexpired pending request.
    /// # Errors
    /// Returns SQL failures.
    pub fn contact_request_authority_floor_usage(
        &self,
        now: i64,
    ) -> Result<(u64, u64), StorageError> {
        Ok(self.connection.query_row("SELECT count(*),count(CASE WHEN NOT EXISTS(SELECT 1 FROM contact_request_projection r WHERE r.contact_identity_commitment=f.root AND r.state='pending' AND r.expires_at>?1) THEN 1 END) FROM contact_request_authority_floor f WHERE f.until>?1",params![now],|row|Ok((row.get(0)?,row.get(1)?)))?)
    }
    /// Explicitly forget rollback hardening for roots without a live pending request.
    /// Consent fences, request decisions and independently cached authority remain unchanged.
    /// # Errors
    /// Returns SQL failures.
    pub fn clear_retired_contact_request_authority_floors(
        &self,
        now: i64,
    ) -> Result<usize, StorageError> {
        Ok(self.connection.execute("DELETE FROM contact_request_authority_floor WHERE NOT EXISTS(SELECT 1 FROM contact_request_projection r WHERE r.contact_identity_commitment=contact_request_authority_floor.root AND r.state='pending' AND r.expires_at>?1)",params![now])?)
    }

    /// Release a compact temporary fence after normal accepted authority owns the full record.
    /// # Errors
    /// Returns SQL failures.
    pub fn release_contact_request_authority_floor(&self, root: &str) -> Result<(), StorageError> {
        self.connection
            .execute("DELETE FROM contact_request_authority_floor WHERE root=?1", params![root])?;
        Ok(())
    }
    /// Delete only metadata for an unaccepted root admitted by a request, after SDK checks.
    /// # Errors
    /// Returns SQL failures. This method never constructs or grants device authority.
    pub fn purge_contact_request_identity_metadata(
        &self,
        root: &str,
        principal: &str,
        link: &str,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            self.connection.execute("DELETE FROM runtime_actor_state WHERE state_kind GLOB 'directory/device/*' AND json_extract(CAST(state_json AS TEXT),'$.principal_commitment')=?1",params![root])?;
            self.connection.execute("DELETE FROM runtime_actor_state WHERE state_kind IN (?1,?2) AND json_extract(CAST(state_json AS TEXT),'$.principal_commitment')=?3",params![format!("identity/manifest/{principal}"),format!("identity/manifest-root/{root}"),root])?;
            self.connection.execute("DELETE FROM runtime_actor_state WHERE state_kind=?1 AND json_extract(CAST(state_json AS TEXT),'$.contact_identity_commitment')=?2",params![format!("directory/identity/{principal}"),root])?;
            for key in [format!("directory/commitment/{root}"),format!("identity/signed_set/{root}")] {
                self.remove_actor_state(&key)?;
            }
            self.connection.execute("DELETE FROM device_directory WHERE principal_commitment=?1",params![root])?;
            self.connection.execute("DELETE FROM friend_link_projection WHERE link_id=?1 AND state='pending'",params![link])?;
            Ok(())
        })
    }

    /// # Errors
    /// Rejects oversized metadata or a stale request ID and returns SQL errors.
    pub fn update_contact_request_metadata(
        &self,
        root: &str,
        direction: &str,
        id: &str,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        if bytes.len() > 1024 {
            return Err(StorageError::AuthorizationRejected);
        }
        if self.connection.execute("UPDATE contact_request_projection SET request_json=?4 WHERE contact_identity_commitment=?1 AND direction=?2 AND request_id=?3",params![root,direction,id,bytes])?!=1 {return Err(StorageError::AuthorizationRejected);}
        Ok(())
    }
    /// # Errors
    /// Returns SQL failures; only a finite page of deferred replies is loaded.
    pub fn deferred_contact_replies(
        &self,
        now: i64,
    ) -> Result<Vec<ContactRequestRecord>, StorageError> {
        let mut query=self.connection.prepare("SELECT contact_identity_commitment,direction,request_id,principal_id,link_id,state,request_json,expires_at,updated_at FROM contact_request_projection WHERE direction='inbound' AND state IN ('accepted','declined') AND expires_at>?1 AND json_extract(CAST(request_json AS TEXT),'$.needs_reply') IS NOT NULL ORDER BY updated_at,contact_identity_commitment LIMIT 16")?;
        Ok(query
            .query_map(params![now], super::contact_requests::request_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// # Errors
    /// Returns SQL failures. Replies waiting for their first queue slot retain only compact metadata.
    pub fn closed_contact_requests(
        &self,
        now: i64,
    ) -> Result<Vec<ContactRequestRecord>, StorageError> {
        let mut query=self.connection.prepare("SELECT contact_identity_commitment,direction,request_id,principal_id,link_id,state,request_json,expires_at,updated_at FROM contact_request_projection WHERE state<>'pending' AND NOT EXISTS(SELECT 1 FROM contact_request_retirement r WHERE r.root=contact_identity_commitment AND r.direction=contact_request_projection.direction AND r.next_at>?2) AND updated_at<=?1 AND (expires_at<=?2 OR json_extract(CAST(request_json AS TEXT),'$.needs_reply') IS NULL) ORDER BY updated_at,contact_identity_commitment LIMIT 128")?;
        Ok(query
            .query_map(
                params![now.saturating_sub(3600), now],
                super::contact_requests::request_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Delay a failed retirement without blocking later rows.
    /// # Errors
    /// Returns SQL failures.
    pub fn defer_contact_request_retirement(
        &self,
        root: &str,
        direction: &str,
        next_at: i64,
    ) -> Result<(), StorageError> {
        self.connection.execute("INSERT INTO contact_request_retirement VALUES(?1,?2,?3) ON CONFLICT(root,direction) DO UPDATE SET next_at=excluded.next_at",params![root,direction,next_at])?;
        Ok(())
    }
    /// # Errors
    /// Returns SQL failures; this deletes local request metadata without granting authority.
    pub fn remove_contact_request(
        &self,
        root: &str,
        direction: &str,
        id: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM contact_request_retirement WHERE root=?1 AND direction=?2",
            params![root, direction],
        )?;
        self.connection.execute("DELETE FROM contact_request_projection WHERE contact_identity_commitment=?1 AND direction=?2 AND request_id=?3",params![root,direction,id])?;
        Ok(())
    }
    /// # Errors
    /// Rejects unknown fence states and returns SQL errors. An existing block wins over decline.
    pub fn fence_contact_request(
        &self,
        root: &str,
        state: &str,
        until: i64,
    ) -> Result<(), StorageError> {
        if !matches!(state, "blocked" | "declined") {
            return Err(StorageError::AuthorizationRejected);
        }
        self.persist_contact_consent(root, Some((state, until)), None)
    }
    /// Remove a local consent fence after the local user explicitly restores consent.
    /// `None` clears any state; `Some(state)` clears only that state, so a block survives a re-add.
    /// # Errors
    /// Returns SQL failures.
    pub fn clear_contact_request_fence(
        &self,
        root: &str,
        state: Option<&str>,
    ) -> Result<(), StorageError> {
        self.persist_contact_consent(root, None, state)
    }
    /// Read the retained decision, including its replay barrier after cooldown.
    /// # Errors
    /// Returns SQL failures.
    pub fn retained_contact_request_fence(
        &self,
        root: &str,
    ) -> Result<Option<(String, i64)>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT state,until FROM contact_request_fence WHERE root=?1",
                params![root],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }
    /// # Errors
    /// Returns SQL failures. Zero is the explicit operator block's indefinite lifetime.
    pub fn contact_request_fence(
        &self,
        root: &str,
        now: i64,
    ) -> Result<Option<(String, i64)>, StorageError> {
        Ok(self.connection.query_row("SELECT state,until FROM contact_request_fence WHERE root=?1 AND (until=0 OR until>?2)",params![root,now],|row|Ok((row.get(0)?,row.get(1)?))).optional()?)
    }
    /// # Errors
    /// Returns SQL failures while deleting elapsed temporary fences and old private journal fields.
    pub fn prune_contact_request_fences_and_previews(&self, now: i64) -> Result<(), StorageError> {
        const MARKER: &str = "contact-request/private-journal-redacted-v1";
        self.connection.execute(
            "DELETE FROM contact_request_fence WHERE root IN (SELECT root FROM contact_request_fence WHERE until>0 AND until<=?1 LIMIT 128)",
            params![now.saturating_sub(604_800)],
        )?;
        self.connection.execute("DELETE FROM contact_message_request_fence WHERE (sender_identity,message_id) IN (SELECT sender_identity,message_id FROM contact_message_fence_retention WHERE until<=?1 LIMIT 128)", params![now])?;
        self.connection.execute("DELETE FROM contact_message_fence_retention WHERE NOT EXISTS(SELECT 1 FROM contact_message_request_fence f WHERE f.sender_identity=contact_message_fence_retention.sender_identity AND f.message_id=contact_message_fence_retention.message_id)", [])?;
        if self.actor_state_exists(MARKER)? {
            return Ok(());
        }
        self.connection.execute_batch(
            "CREATE INDEX IF NOT EXISTS runtime_journal_contact_topic ON runtime_journal(topic)",
        )?;
        self.connection.execute("UPDATE runtime_journal SET body_json=CAST(json_remove(CAST(body_json AS TEXT),'$.preview','$.note','$.safety_number') AS BLOB) WHERE topic IN ('contact.requested','contact.accepted','contact.declined','contact.blocked','contact.request.expired') AND (json_type(CAST(body_json AS TEXT),'$.preview') IS NOT NULL OR json_type(CAST(body_json AS TEXT),'$.note') IS NOT NULL OR json_type(CAST(body_json AS TEXT),'$.safety_number') IS NOT NULL)",[])?;
        self.persist_actor_state(MARKER, &true)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "contact_request_floor_tests.rs"]
mod floor_tests;
