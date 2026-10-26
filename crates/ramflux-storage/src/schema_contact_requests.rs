// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private request and held-message state; install before the runtime invalidation triggers.
use crate::{StorageError, database::Connection};
pub(crate) fn upgrade(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS contact_request_projection (
            contact_identity_commitment TEXT NOT NULL,
            direction TEXT NOT NULL CHECK(direction IN ('inbound','outbound')),
            request_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            link_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','accepted','declined','blocked','expired')),
            request_json BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(contact_identity_commitment,direction)
        );
        CREATE INDEX IF NOT EXISTS contact_request_pending
            ON contact_request_projection(direction,state,updated_at,contact_identity_commitment);
        CREATE INDEX IF NOT EXISTS contact_request_retire_order ON contact_request_projection(state,updated_at,contact_identity_commitment);
        CREATE TABLE IF NOT EXISTS contact_request_retirement (
            root TEXT NOT NULL, direction TEXT NOT NULL, next_at INTEGER NOT NULL,
            PRIMARY KEY(root,direction)
        );
        CREATE TABLE IF NOT EXISTS contact_request_delivery (
            request_id TEXT NOT NULL,
            recipient_identity TEXT NOT NULL,
            material_hash TEXT NOT NULL,
            submitted_at INTEGER NOT NULL,
            PRIMARY KEY(request_id,recipient_identity)
        );
        CREATE TABLE IF NOT EXISTS contact_message_request (
            contact_identity_commitment TEXT NOT NULL,
            sender_identity TEXT NOT NULL,
            message_id TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            message_json BLOB NOT NULL,
            byte_count INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY(sender_identity,message_id)
        );
        CREATE INDEX IF NOT EXISTS contact_message_request_owner
            ON contact_message_request(contact_identity_commitment,created_at,message_id);
        CREATE TABLE IF NOT EXISTS contact_request_authority_floor (
            root TEXT PRIMARY KEY,
            epoch INTEGER NOT NULL,
            record_hash TEXT NOT NULL,
            until INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contact_request_fence (
            root TEXT PRIMARY KEY,
            state TEXT NOT NULL CHECK(state IN ('blocked','declined')),
            until INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contact_request_rate (
            bucket TEXT PRIMARY KEY,
            window_end INTEGER NOT NULL,
            count INTEGER NOT NULL
        );",
    )?;
    connection.execute_batch(HELD_MESSAGE_FENCES)?;
    connection.execute_batch(CONSENT_DECISIONS)?;
    Ok(())
}

pub(crate) const CONSENT_DECISIONS: &str = "
CREATE TABLE IF NOT EXISTS contact_link_decision(link_id TEXT PRIMARY KEY,state TEXT NOT NULL CHECK(state IN ('blocked','declined','lifted')),decided_at INTEGER NOT NULL);
INSERT OR IGNORE INTO contact_link_decision SELECT link_id,CASE WHEN blocked=1 THEN 'blocked' WHEN state='rejected' THEN 'declined' ELSE 'lifted' END,min(max(updated_at,0),9223372036854775)*1000 FROM friend_link_projection WHERE state IN ('accepted','blocked','rejected');

CREATE TABLE IF NOT EXISTS contact_request_decision(root TEXT PRIMARY KEY,state TEXT NOT NULL CHECK(state IN ('blocked','declined','lifted')),decided_at INTEGER NOT NULL);
INSERT OR IGNORE INTO contact_request_decision
 SELECT f.root,f.state,coalesce((SELECT min(max(max(updated_at),0),9223372036854775)*1000 FROM contact_request_projection WHERE contact_identity_commitment=f.root),0) FROM contact_request_fence f;
INSERT OR IGNORE INTO contact_request_decision
 SELECT contact_identity_commitment,'lifted',min(max(max(updated_at),0),9223372036854775)*1000 FROM contact_request_projection r
 WHERE state='accepted' AND NOT EXISTS(SELECT 1 FROM contact_request_fence f WHERE f.root=r.contact_identity_commitment)
 GROUP BY contact_identity_commitment;
";
pub(crate) const HELD_MESSAGE_FENCES: &str = "
CREATE TABLE IF NOT EXISTS contact_message_request_fence(sender_identity TEXT NOT NULL,message_id TEXT NOT NULL,PRIMARY KEY(sender_identity,message_id));
CREATE TABLE IF NOT EXISTS contact_message_fence_retention(sender_identity TEXT NOT NULL,message_id TEXT NOT NULL,until INTEGER NOT NULL,PRIMARY KEY(sender_identity,message_id));
CREATE INDEX IF NOT EXISTS contact_message_fence_expiry ON contact_message_fence_retention(until);
INSERT OR IGNORE INTO contact_message_fence_retention SELECT sender_identity,message_id,unixepoch()+604800 FROM contact_message_request_fence;
DROP TRIGGER IF EXISTS contact_message_erasure_fence;
CREATE TRIGGER contact_message_erasure_fence AFTER DELETE ON contact_message_request BEGIN
 INSERT OR IGNORE INTO contact_message_request_fence(sender_identity,message_id) VALUES(OLD.sender_identity,OLD.message_id);
 INSERT INTO contact_message_fence_retention VALUES(OLD.sender_identity,OLD.message_id,max(OLD.expires_at,OLD.created_at+604800))
 ON CONFLICT(sender_identity,message_id) DO UPDATE SET until=max(contact_message_fence_retention.until,excluded.until);
END;
";
