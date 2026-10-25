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
    Ok(())
}
