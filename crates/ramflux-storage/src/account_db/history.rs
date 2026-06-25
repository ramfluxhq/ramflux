// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::event_store::{LocalEventSigningInput, local_event_signing_body};
use crate::history_hash::history_bundle_hash;

impl AccountDb {
    pub fn export_history_bundle(
        &self,
        source_device_id: &str,
        target_device_id: &str,
    ) -> Result<HistoryBundle, StorageError> {
        let events = self.history_events()?;
        let checkpoints = self.history_projection_checkpoints()?;
        let checkpoint_hash =
            history_bundle_hash(source_device_id, target_device_id, &events, &checkpoints)?;
        Ok(HistoryBundle {
            source_device_id: source_device_id.to_owned(),
            target_device_id: target_device_id.to_owned(),
            encrypted_event_batch: events,
            projection_checkpoints: checkpoints,
            checkpoint_hash,
        })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn import_history_bundle(&self, bundle: &HistoryBundle) -> Result<(), StorageError> {
        let expected = history_bundle_hash(
            &bundle.source_device_id,
            &bundle.target_device_id,
            &bundle.encrypted_event_batch,
            &bundle.projection_checkpoints,
        )?;
        if expected != bundle.checkpoint_hash {
            return Err(StorageError::HistoryBundleHashMismatch);
        }
        for event in &bundle.encrypted_event_batch {
            if event.actor_device_id != bundle.source_device_id {
                return Err(StorageError::HistoryBundleHashMismatch);
            }
            let signing_body = local_event_signing_body(LocalEventSigningInput {
                event_id: &event.event_id,
                event_type: &event.event_type,
                actor_principal_id: &event.actor_principal_id,
                actor_device_id: &event.actor_device_id,
                device_counter: event.device_counter,
                lamport_time: event.lamport_time,
                created_at: event.created_at,
                event_body: &event.event_body,
            });
            ramflux_crypto::verify_device_branch_signature(
                &event.source_device_public_key,
                &signing_body,
                &event.signature,
            )?;
            self.connection.execute(
                "INSERT OR IGNORE INTO local_event_log (
                    event_id, event_type, actor_principal_id, actor_device_id, device_counter,
                    lamport_time, created_at, causal_prev_json, event_body, signature,
                    signature_status, projection_status
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, 'verified', 'pending')",
                params![
                    event.event_id,
                    event.event_type,
                    event.actor_principal_id,
                    event.actor_device_id,
                    event.device_counter,
                    event.lamport_time,
                    event.created_at,
                    event.event_body,
                    event.signature.as_bytes()
                ],
            )?;
        }
        for checkpoint in &bundle.projection_checkpoints {
            self.set_projection_checkpoint(&checkpoint.projection_name, &checkpoint.last_event_id)?;
        }
        Ok(())
    }

    fn history_events(&self) -> Result<Vec<HistoryEventRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT event_id, event_type, actor_principal_id, actor_device_id, device_counter,
                    lamport_time, created_at, event_body, signature
               FROM local_event_log
              ORDER BY lamport_time ASC, event_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let signature_bytes: Vec<u8> = row.get(8)?;
            let signature = String::from_utf8_lossy(&signature_bytes).into_owned();
            Ok(HistoryEventRecord {
                event_id: row.get(0)?,
                event_type: row.get(1)?,
                actor_principal_id: row.get(2)?,
                actor_device_id: row.get(3)?,
                device_counter: row.get(4)?,
                lamport_time: row.get(5)?,
                created_at: row.get(6)?,
                event_body: row.get(7)?,
                signature,
                source_device_public_key: self
                    .device_signer()
                    .map(|device| {
                        ramflux_protocol::encode_base64url(
                            device.signing_key.verifying_key().to_bytes(),
                        )
                    })
                    .unwrap_or_default(),
            })
        })?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    fn history_projection_checkpoints(
        &self,
    ) -> Result<Vec<ProjectionCheckpointRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT projection_name, last_event_id
               FROM projection_checkpoint
              WHERE last_event_id IS NOT NULL
              ORDER BY projection_name ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(ProjectionCheckpointRecord {
                projection_name: row.get(0)?,
                last_event_id: row.get(1)?,
            })
        })?;
        let mut checkpoints = Vec::new();
        for row in rows {
            checkpoints.push(row?);
        }
        Ok(checkpoints)
    }
}
