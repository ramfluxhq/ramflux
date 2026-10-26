// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded request admission, durable message quarantine and terminal decisions.
use super::AccountDb;
use crate::{ContactMessageRequestWrite, ContactRequestRecord, StorageError};
use rusqlite::{OptionalExtension, params};
const MAX_PENDING: u64 = 128;
const MAX_MESSAGES_PER_ROOT: u64 = 20;
const MAX_MESSAGES: u64 = 256;
const MAX_BYTES_PER_ROOT: u64 = 1_048_576;
const MAX_BYTES: u64 = 8_388_608;

pub(super) fn request_row(row: &crate::database::Row) -> rusqlite::Result<ContactRequestRecord> {
    Ok(ContactRequestRecord {
        contact_identity_commitment: row.get(0)?,
        direction: row.get(1)?,
        request_id: row.get(2)?,
        principal_id: row.get(3)?,
        link_id: row.get(4)?,
        state: row.get(5)?,
        request_json: row.get(6)?,
        expires_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}
impl AccountDb {
    /// # Errors
    /// Returns SQL failures; the caller verifies current device material before using its hash.
    pub fn contact_request_delivered(
        &self,
        request_id: &str,
        recipient: &ramflux_crypto::RootQualifiedDeviceRef,
        material_hash: &str,
    ) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM contact_request_delivery WHERE request_id=?1 AND recipient_identity=?2 AND material_hash=?3)",params![request_id,recipient.storage_key(),material_hash],|row|row.get(0))?)
    }
    /// Record positive gateway submission before allowing the first ordinary message to that device.
    /// # Errors
    /// Rejects a mismatched outbound request and returns SQL failures.
    pub fn mark_contact_request_delivered(
        &self,
        request_id: &str,
        recipient: &ramflux_crypto::RootQualifiedDeviceRef,
        material_hash: &str,
        now: i64,
    ) -> Result<(), StorageError> {
        let matches:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM contact_request_projection WHERE request_id=?1 AND contact_identity_commitment=?2 AND direction='outbound' AND state='pending')",params![request_id,recipient.root_commitment()],|row|row.get(0))?;
        if !matches {
            return Err(StorageError::AuthorizationRejected);
        }
        self.connection.execute("INSERT INTO contact_request_delivery VALUES(?1,?2,?3,?4) ON CONFLICT(request_id,recipient_identity) DO UPDATE SET material_hash=excluded.material_hash,submitted_at=excluded.submitted_at",params![request_id,recipient.storage_key(),material_hash,now])?;
        Ok(())
    }
    /// # Errors
    /// Refuses ambiguous selectors and returns SQL errors. Selection grants no identity authority.
    pub fn select_inbound_contact_request(
        &self,
        field: &str,
        selector: &str,
    ) -> Result<Option<ContactRequestRecord>, StorageError> {
        let column = match field {
            "request_id" => "request_id",
            "link_id" => "link_id",
            "principal_id" => "principal_id",
            "root_commitment" => "contact_identity_commitment",
            _ => return Err(StorageError::AuthorizationRejected),
        };
        let sql = format!(
            "SELECT contact_identity_commitment,direction,request_id,principal_id,link_id,state,request_json,expires_at,updated_at FROM contact_request_projection WHERE direction='inbound' AND {column}=?1 LIMIT 2"
        );
        let mut query = self.connection.prepare(&sql)?;
        let rows = query
            .query_map(params![selector], request_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > 1 {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(rows.into_iter().next())
    }
    /// # Errors
    /// Returns SQL failures; this metadata never authenticates a device key.
    pub fn contact_request(
        &self,
        root: &str,
        direction: &str,
    ) -> Result<Option<ContactRequestRecord>, StorageError> {
        Ok(self.connection.query_row("SELECT contact_identity_commitment,direction,request_id,principal_id,link_id,state,request_json,expires_at,updated_at FROM contact_request_projection WHERE contact_identity_commitment=?1 AND direction=?2",params![root,direction],request_row).optional()?)
    }
    /// Store an already authenticated request without replacing another root's link or terminal decision.
    /// # Errors
    /// Refuses invalid direction, oversized wire records and pending account capacity exhaustion.
    pub fn persist_contact_request(
        &self,
        request: &ContactRequestRecord,
    ) -> Result<bool, StorageError> {
        if !matches!(request.direction.as_str(), "inbound" | "outbound")
            || request.request_json.len() > 131_072
        {
            return Err(StorageError::AuthorizationRejected);
        }
        self.write_transaction(|| {
            if let Some(old) = self.contact_request(&request.contact_identity_commitment, &request.direction)?
                && (old.request_id == request.request_id || !(matches!(old.state.as_str(), "expired" | "declined") || (request.direction == "inbound" && old.state == "accepted")))
            { return Ok(false); }
            if request.state=="pending" {
                let count:u64=self.connection.query_row("SELECT count(*) FROM contact_request_projection WHERE direction=?1 AND state='pending'",params![request.direction],|row|row.get(0))?;
                if count>=MAX_PENDING { return Err(StorageError::AuthorizationRejected); }
            }
            self.connection.execute("INSERT INTO contact_request_projection VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(contact_identity_commitment,direction) DO UPDATE SET request_id=excluded.request_id,principal_id=excluded.principal_id,link_id=excluded.link_id,state=excluded.state,request_json=excluded.request_json,expires_at=excluded.expires_at,updated_at=excluded.updated_at",params![request.contact_identity_commitment,request.direction,request.request_id,request.principal_id,request.link_id,request.state,request.request_json,request.expires_at,request.updated_at])?;
            Ok(true)
        })
    }
    /// # Errors
    /// Returns SQL errors. Only the bounded pending inbound page is loaded.
    pub fn pending_contact_requests(&self) -> Result<Vec<ContactRequestRecord>, StorageError> {
        let mut query=self.connection.prepare("SELECT contact_identity_commitment,direction,request_id,principal_id,link_id,state,request_json,expires_at,updated_at FROM contact_request_projection WHERE direction='inbound' AND state='pending' ORDER BY updated_at,contact_identity_commitment LIMIT 128")?;
        Ok(query.query_map([], request_row)?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// The newest bounded outgoing page includes terminal decisions and prioritizes pending rows.
    /// # Errors
    /// Returns SQL failures. These records grant no identity authority.
    pub fn outgoing_contact_requests(&self) -> Result<Vec<ContactRequestRecord>, StorageError> {
        let mut query = self.connection.prepare("SELECT contact_identity_commitment,direction,request_id,principal_id,link_id,state,request_json,expires_at,updated_at FROM contact_request_projection WHERE direction='outbound' ORDER BY (state='pending') DESC,updated_at DESC,contact_identity_commitment LIMIT 128")?;
        Ok(query.query_map([], request_row)?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// A verified reciprocal request and local acceptance establish fresh account consent.
    /// # Errors
    /// Returns SQL failures. This does not clear a local block or grant device authority.
    pub fn confirm_reciprocal_contact(&self, root: &str, now: i64) -> Result<(), StorageError> {
        self.connection.execute("UPDATE contact_request_projection SET state='accepted',updated_at=?2 WHERE contact_identity_commitment=?1 AND direction='outbound' AND state IN ('pending','declined','expired') AND EXISTS(SELECT 1 FROM contact_request_projection r WHERE r.contact_identity_commitment=?1 AND r.direction='inbound' AND r.state='accepted')",params![root,now])?;
        Ok(())
    }
    /// # Errors
    /// Refuses unknown/invalid transitions and returns SQL failures.
    pub fn decide_contact_request(
        &self,
        root: &str,
        direction: &str,
        request_id: &str,
        state: &str,
        now: i64,
    ) -> Result<bool, StorageError> {
        if !matches!(state, "accepted" | "declined" | "blocked" | "expired") {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(self.connection.execute("UPDATE contact_request_projection SET state=?4,updated_at=?5 WHERE contact_identity_commitment=?1 AND direction=?2 AND request_id=?3 AND (state='pending' OR state=?4 OR ?4='blocked') AND (?4<>'accepted' OR state='accepted' OR expires_at>?5)",params![root,direction,request_id,state,now])?>0)
    }
    /// Check a sender's existing bucket without charging unauthenticated traffic.
    /// # Errors
    /// Returns SQL failures.
    pub fn contact_request_budget_available(
        &self,
        bucket: &str,
        limit: u64,
        now: i64,
    ) -> Result<bool, StorageError> {
        Ok(!self.connection.query_row("SELECT EXISTS(SELECT 1 FROM contact_request_rate WHERE bucket=?1 AND window_end>?2 AND count>=?3)",params![bucket,now,limit],|row|row.get::<_,bool>(0))?)
    }
    /// Read-only account capacity for one more pending inbound request, the rate buckets it would
    /// create and its authority floor. Admission checks this before charging any requester bucket.
    /// # Errors
    /// Returns SQL failures.
    pub fn contact_request_inbound_capacity(
        &self,
        buckets: &[String],
        root: Option<&str>,
        now: i64,
    ) -> Result<bool, StorageError> {
        let pending:u64=self.connection.query_row("SELECT count(*) FROM contact_request_projection WHERE direction='inbound' AND state='pending'",[],|row|row.get(0))?;
        if pending >= MAX_PENDING {
            return Ok(false);
        }
        let mut rows: u64 = self.connection.query_row(
            "SELECT count(*) FROM contact_request_rate WHERE window_end>?1",
            params![now],
            |row| row.get(0),
        )?;
        for bucket in buckets {
            if !self.connection.query_row("SELECT EXISTS(SELECT 1 FROM contact_request_rate WHERE bucket=?1 AND window_end>?2)",params![bucket,now],|row|row.get::<_,bool>(0))? {
                rows = rows.saturating_add(1);
            }
        }
        if rows > 1024 {
            return Ok(false);
        }
        let floor: u64 = self.connection.query_row(
            "SELECT count(*) FROM contact_request_authority_floor WHERE until>?1",
            params![now],
            |row| row.get(0),
        )?;
        let retained = match root {
            Some(root) => self.connection.query_row("SELECT EXISTS(SELECT 1 FROM contact_request_authority_floor WHERE root=?1 AND until>?2)",params![root,now],|row|row.get::<_,bool>(0))?,
            None => false,
        };
        Ok(retained || floor < 4096)
    }
    /// Refresh expiry for a single selected request, independently of periodic maintenance.
    /// # Errors
    /// Returns SQL failures.
    pub fn expire_contact_request(
        &self,
        root: &str,
        direction: &str,
        now: i64,
    ) -> Result<(), StorageError> {
        self.connection.execute("UPDATE contact_request_projection SET state='expired',updated_at=?3 WHERE contact_identity_commitment=?1 AND direction=?2 AND state='pending' AND expires_at<=?3",params![root,direction,now])?;
        Ok(())
    }
    /// Consume one bounded rolling-window bucket. Invalid requests cannot roll this write back.
    /// # Errors
    /// Returns SQL failures. False means the quota or bucket capacity is exhausted.
    pub fn charge_contact_request(
        &self,
        bucket: &str,
        limit: u64,
        window: i64,
        now: i64,
    ) -> Result<bool, StorageError> {
        if bucket.len() > 256 || window <= 0 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.write_transaction(|| {
            self.connection.execute("DELETE FROM contact_request_rate WHERE window_end<=?1",params![now])?;
            let count:u64=self.connection.query_row("SELECT count(*) FROM contact_request_rate",[],|r|r.get(0))?;
            if count>=1024 && !self.connection.query_row("SELECT EXISTS(SELECT 1 FROM contact_request_rate WHERE bucket=?1)",params![bucket],|r|r.get::<_,bool>(0))? { return Ok(false); }
            let used:u64=self.connection.query_row("SELECT COALESCE((SELECT count FROM contact_request_rate WHERE bucket=?1),0)",params![bucket],|r|r.get(0))?;
            if used>=limit { return Ok(false); }
            self.connection.execute("INSERT INTO contact_request_rate VALUES(?1,?2,1) ON CONFLICT(bucket) DO UPDATE SET count=count+1",params![bucket,now.saturating_add(window)])?;
            Ok(true)
        })
    }
    /// Hold a fully authenticated message without making it a conversation or running its controls.
    /// # Errors
    /// Returns SQL errors. False means the bounded queue is full or this exact item is already held.
    pub fn hold_contact_message(
        &self,
        message: ContactMessageRequestWrite<'_>,
    ) -> Result<bool, StorageError> {
        self.write_transaction(|| {
            if self.connection.query_row("SELECT EXISTS(SELECT 1 FROM contact_message_request_fence WHERE sender_identity=?1 AND message_id=?2)",params![message.sender.storage_key(),message.message_id],|r|r.get::<_,bool>(0))? {return Ok(false);}
            let counts:(u64,u64,u64,u64)=self.connection.query_row("SELECT count(*),COALESCE(sum(byte_count),0),COALESCE(sum(CASE WHEN contact_identity_commitment=?1 THEN 1 ELSE 0 END),0),COALESCE(sum(CASE WHEN contact_identity_commitment=?1 THEN byte_count ELSE 0 END),0) FROM contact_message_request",params![message.sender.root_commitment()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            let bytes=u64::try_from(message.message_json.len()).map_err(|_|StorageError::AuthorizationRejected)?;
            if counts.0>=MAX_MESSAGES || counts.2>=MAX_MESSAGES_PER_ROOT || counts.1.saturating_add(bytes)>MAX_BYTES || counts.3.saturating_add(bytes)>MAX_BYTES_PER_ROOT { return Ok(false); }
            Ok(self.connection.execute("INSERT OR IGNORE INTO contact_message_request VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![message.sender.root_commitment(),message.sender.storage_key(),message.message_id,message.conversation_id,message.message_json,bytes,message.expires_at,message.created_at])?>0)
        })
    }
    /// Read the bounded queue size without loading private message bodies.
    /// # Errors
    /// Returns SQL failures.
    pub fn contact_message_count(&self, root: &str) -> Result<u64, StorageError> {
        Ok(self.connection.query_row(
            "SELECT count(*) FROM contact_message_request WHERE contact_identity_commitment=?1",
            params![root],
            |row| row.get(0),
        )?)
    }
    /// # Errors
    /// Returns SQL errors; private held contents remain capped to eight MiB account-wide.
    pub fn held_contact_messages(&self, root: &str) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut query=self.connection.prepare("SELECT message_json FROM contact_message_request WHERE contact_identity_commitment=?1 ORDER BY created_at,message_id LIMIT 20")?;
        Ok(query
            .query_map(params![root], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// # Errors
    /// Returns SQL failures.
    pub fn discard_contact_messages(&self, root: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM contact_message_request WHERE contact_identity_commitment=?1",
            params![root],
        )?;
        Ok(())
    }
    /// # Errors
    /// Returns SQL failures; expired requests keep a terminal fence against cached-key admission.
    pub fn expire_contact_requests(&self, now: i64) -> Result<(), StorageError> {
        self.write_transaction(|| {
            self.connection.execute("UPDATE contact_request_projection SET state='expired',updated_at=?1 WHERE state='pending' AND expires_at<=?1",params![now])?;
            self.connection.execute("DELETE FROM contact_message_request WHERE expires_at<=?1 OR EXISTS(SELECT 1 FROM contact_request_projection r WHERE r.contact_identity_commitment=contact_message_request.contact_identity_commitment AND r.direction='inbound' AND r.state NOT IN ('pending','accepted'))",params![now])?;
            self.connection.execute("DELETE FROM contact_request_delivery WHERE NOT EXISTS(SELECT 1 FROM contact_request_projection r WHERE r.direction='outbound' AND r.state='pending' AND r.request_id=contact_request_delivery.request_id)",[])?;
            Ok(())
        })
    }
}
