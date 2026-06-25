// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::wildcard_imports)]
use crate::*;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct LocalEventSigningBody<'a> {
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub actor_principal_id: &'a str,
    pub actor_device_id: &'a str,
    pub device_counter: i64,
    pub lamport_time: i64,
    pub created_at: i64,
    pub event_body: &'a [u8],
}

#[derive(Clone, Copy)]
pub(crate) struct LocalEventSigningInput<'a> {
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub actor_principal_id: &'a str,
    pub actor_device_id: &'a str,
    pub device_counter: i64,
    pub lamport_time: i64,
    pub created_at: i64,
    pub event_body: &'a [u8],
}

pub(crate) fn local_event_signing_body(
    input: LocalEventSigningInput<'_>,
) -> LocalEventSigningBody<'_> {
    LocalEventSigningBody {
        event_id: input.event_id,
        event_type: input.event_type,
        actor_principal_id: input.actor_principal_id,
        actor_device_id: input.actor_device_id,
        device_counter: input.device_counter,
        lamport_time: input.lamport_time,
        created_at: input.created_at,
        event_body: input.event_body,
    }
}

pub trait EventStore {
    /// # Errors
    /// Returns an error when the event cannot be stored.
    fn append_event(
        &self,
        event_id: &str,
        event_type: &str,
        body: &[u8],
    ) -> Result<(), StorageError>;
    /// # Errors
    /// Returns an error when the event lookup fails.
    fn event_body(&self, event_id: &str) -> Result<Option<Vec<u8>>, StorageError>;
}

pub trait ProjectionStore {
    /// # Errors
    /// Returns an error when the checkpoint cannot be stored.
    fn set_projection_checkpoint(
        &self,
        projection_name: &str,
        last_event_id: &str,
    ) -> Result<(), StorageError>;
    /// # Errors
    /// Returns an error when the checkpoint lookup fails.
    fn projection_checkpoint(&self, projection_name: &str) -> Result<Option<String>, StorageError>;
}

impl EventStore for AccountDb {
    fn append_event(
        &self,
        event_id: &str,
        event_type: &str,
        body: &[u8],
    ) -> Result<(), StorageError> {
        let actor_principal_id =
            self.device_signer().map_or("principal", |device| device.principal_id.as_str());
        let actor_device_id =
            self.device_signer().map_or("device", |device| device.device_id.as_str());
        let next_device_counter = self.connection.query_row(
            "SELECT COALESCE(MAX(device_counter), 0) + 1
                   FROM local_event_log
                  WHERE actor_device_id = ?1",
            params![actor_device_id],
            |row| row.get::<_, i64>(0),
        )?;
        let created_at = self.now_unix();
        let signing_body = local_event_signing_body(LocalEventSigningInput {
            event_id,
            event_type,
            actor_principal_id,
            actor_device_id,
            device_counter: next_device_counter,
            lamport_time: next_device_counter,
            created_at,
            event_body: body,
        });
        let (signature, signature_status) = if let Some(device) = self.device_signer() {
            (ramflux_crypto::sign_with_device_branch(device, &signing_body)?, "self")
        } else {
            (String::new(), "unchecked")
        };
        self.connection.execute(
            "INSERT INTO local_event_log (
                event_id, event_type, actor_principal_id, actor_device_id, device_counter,
                lamport_time, created_at, causal_prev_json, event_body, signature,
                signature_status, projection_status
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, NULL, ?7, ?8, ?9, 'pending')",
            params![
                event_id,
                event_type,
                actor_principal_id,
                actor_device_id,
                next_device_counter,
                created_at,
                body,
                signature.as_bytes(),
                signature_status
            ],
        )?;
        Ok(())
    }

    fn event_body(&self, event_id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT event_body FROM local_event_log WHERE event_id = ?1",
                params![event_id],
                |row| row.get(0),
            )
            .optional()?)
    }
}

impl ProjectionStore for AccountDb {
    fn set_projection_checkpoint(
        &self,
        projection_name: &str,
        last_event_id: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT INTO projection_checkpoint (
                projection_name, projection_version, last_event_id, checkpoint_hash, updated_at
            ) VALUES (?1, 1, ?2, NULL, ?3)
             ON CONFLICT(projection_name)
             DO UPDATE SET last_event_id = excluded.last_event_id, updated_at = excluded.updated_at",
            params![projection_name, last_event_id, self.now_unix()],
        )?;
        Ok(())
    }

    fn projection_checkpoint(&self, projection_name: &str) -> Result<Option<String>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT last_event_id FROM projection_checkpoint WHERE projection_name = ?1",
                params![projection_name],
                |row| row.get(0),
            )
            .optional()?)
    }
}
