#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::row_mappers::contact_verification_from_row;
use rusqlite::OptionalExtension;

impl AccountDb {
    pub fn apply_identity_lifecycle_event(
        &self,
        identity_commitment: &str,
        event_id: &str,
        event_type: &str,
        lifecycle_epoch: u64,
        timing: IdentityLifecycleTiming<'_>,
    ) -> Result<IdentityLifecycleRecord, StorageError> {
        let lifecycle_epoch =
            i64::try_from(lifecycle_epoch).map_err(|_err| StorageError::AuthorizationRejected)?;
        let lifecycle_state = match event_type {
            "identity.deactivated" => "deactivated",
            "identity.reactivated" => "active",
            "identity.deleted" => "deleted",
            _ => return Err(StorageError::AuthorizationRejected),
        };
        self.connection.execute(
            "INSERT INTO identity_lifecycle_projection (
                identity_commitment, lifecycle_state, lifecycle_epoch, causal_event_id,
                reason_code, timelock_until, grace_window_until, finalization_time, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(identity_commitment)
            DO UPDATE SET lifecycle_state = excluded.lifecycle_state,
                          lifecycle_epoch = excluded.lifecycle_epoch,
                          causal_event_id = excluded.causal_event_id,
                          reason_code = excluded.reason_code,
                          timelock_until = excluded.timelock_until,
                          grace_window_until = excluded.grace_window_until,
                          finalization_time = excluded.finalization_time,
                          updated_at = excluded.updated_at
            WHERE excluded.lifecycle_epoch >= identity_lifecycle_projection.lifecycle_epoch",
            params![
                identity_commitment,
                lifecycle_state,
                lifecycle_epoch,
                event_id,
                timing.reason_code,
                timing.timelock_until,
                timing.grace_window_until,
                timing.finalization_time,
                timing.updated_at
            ],
        )?;
        self.identity_lifecycle(identity_commitment)?
            .ok_or_else(|| StorageError::AccountNotFound(identity_commitment.to_owned()))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn identity_lifecycle(
        &self,
        identity_commitment: &str,
    ) -> Result<Option<IdentityLifecycleRecord>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT identity_commitment, lifecycle_state, lifecycle_epoch, causal_event_id,
                        reason_code, timelock_until, grace_window_until, finalization_time,
                        updated_at
                   FROM identity_lifecycle_projection
                  WHERE identity_commitment = ?1",
                params![identity_commitment],
                |row| {
                    let lifecycle_epoch_i64: i64 = row.get(2)?;
                    Ok(IdentityLifecycleRecord {
                        identity_commitment: row.get(0)?,
                        lifecycle_state: row.get(1)?,
                        lifecycle_epoch: u64::try_from(lifecycle_epoch_i64).unwrap_or(0),
                        causal_event_id: row.get(3)?,
                        reason_code: row.get(4)?,
                        timelock_until: row.get(5)?,
                        grace_window_until: row.get(6)?,
                        finalization_time: row.get(7)?,
                        updated_at: row.get(8)?,
                    })
                },
            )
            .optional()?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn ensure_identity_can_send(&self, identity_commitment: &str) -> Result<(), StorageError> {
        match self.identity_lifecycle(identity_commitment)? {
            Some(record) if record.lifecycle_state != "active" => {
                Err(StorageError::IdentityLifecycleBlocked(record.lifecycle_state))
            }
            _ => Ok(()),
        }
    }

    /// # Errors
    /// Returns an error when the verification state cannot be persisted.
    pub fn mark_contact_verified(
        &self,
        update: ContactVerificationUpdate<'_>,
    ) -> Result<ContactVerificationRecord, StorageError> {
        self.connection.execute(
            "INSERT INTO contact_verification_projection (
                contact_identity_commitment, verification_state, safety_number_hash,
                verified_device_set_hash, verified_lineage_head, verified_at,
                verified_by_device_id, last_change_event_id, last_change_seen_at,
                kt_tree_size, kt_tree_root_hash, kt_leaf_index, last_gossip_lineage_head
            ) VALUES (?1, 'verified', ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL, NULL, NULL, NULL)
            ON CONFLICT(contact_identity_commitment)
            DO UPDATE SET verification_state = 'verified',
                          safety_number_hash = excluded.safety_number_hash,
                          verified_device_set_hash = excluded.verified_device_set_hash,
                          verified_lineage_head = excluded.verified_lineage_head,
                          verified_at = excluded.verified_at,
                          verified_by_device_id = excluded.verified_by_device_id,
                          last_change_event_id = NULL,
                          last_change_seen_at = NULL",
            params![
                update.contact_identity_commitment,
                update.safety_number_hash,
                update.device_set_hash,
                update.lineage_head,
                update.verified_at,
                update.verified_by_device_id
            ],
        )?;
        self.contact_verification(update.contact_identity_commitment)?.ok_or_else(|| {
            StorageError::AccountNotFound(update.contact_identity_commitment.to_owned())
        })
    }

    /// # Errors
    /// Returns an error when the observation cannot be persisted.
    pub fn observe_contact_key_state(
        &self,
        observation: ContactKeyObservation<'_>,
    ) -> Result<ContactVerificationRecord, StorageError> {
        let state = match self.contact_verification(observation.contact_identity_commitment)? {
            Some(record)
                if record.verification_state == "verified"
                    && (record.safety_number_hash != observation.safety_number_hash
                        || record.verified_device_set_hash != observation.device_set_hash
                        || record.verified_lineage_head != observation.lineage_head) =>
            {
                "changed"
            }
            Some(record) => {
                return Ok(record);
            }
            None => "unverified",
        };
        self.connection.execute(
            "INSERT INTO contact_verification_projection (
                contact_identity_commitment, verification_state, safety_number_hash,
                verified_device_set_hash, verified_lineage_head, verified_at,
                verified_by_device_id, last_change_event_id, last_change_seen_at,
                kt_tree_size, kt_tree_root_hash, kt_leaf_index, last_gossip_lineage_head
            ) VALUES (?1, ?2, ?3, ?4, ?5, 0, '', ?6, ?7, NULL, NULL, NULL, NULL)
            ON CONFLICT(contact_identity_commitment)
            DO UPDATE SET verification_state = excluded.verification_state,
                          last_change_event_id = excluded.last_change_event_id,
                          last_change_seen_at = excluded.last_change_seen_at",
            params![
                observation.contact_identity_commitment,
                state,
                observation.safety_number_hash,
                observation.device_set_hash,
                observation.lineage_head,
                observation.change_event_id,
                observation.seen_at
            ],
        )?;
        self.contact_verification(observation.contact_identity_commitment)?.ok_or_else(|| {
            StorageError::AccountNotFound(observation.contact_identity_commitment.to_owned())
        })
    }

    /// # Errors
    /// Returns an error when the KT checkpoint cannot be persisted.
    pub fn store_contact_kt_checkpoint(
        &self,
        update: ContactKtCheckpointUpdate<'_>,
    ) -> Result<ContactVerificationRecord, StorageError> {
        let tree_size =
            i64::try_from(update.tree_size).map_err(|_err| StorageError::AuthorizationRejected)?;
        let leaf_index =
            i64::try_from(update.leaf_index).map_err(|_err| StorageError::AuthorizationRejected)?;
        self.connection.execute(
            "UPDATE contact_verification_projection
                SET kt_tree_size = ?2,
                    kt_tree_root_hash = ?3,
                    kt_leaf_index = ?4
              WHERE contact_identity_commitment = ?1",
            params![
                update.contact_identity_commitment,
                tree_size,
                update.tree_root_hash,
                leaf_index
            ],
        )?;
        self.contact_verification(update.contact_identity_commitment)?.ok_or_else(|| {
            StorageError::AccountNotFound(update.contact_identity_commitment.to_owned())
        })
    }

    /// # Errors
    /// Returns an error when the fork warning cannot be persisted.
    pub fn observe_contact_fork(
        &self,
        contact_identity_commitment: &str,
        change_event_id: &str,
        seen_at: i64,
    ) -> Result<ContactVerificationRecord, StorageError> {
        self.connection.execute(
            "UPDATE contact_verification_projection
                SET verification_state = 'changed',
                    last_change_event_id = ?2,
                    last_change_seen_at = ?3
              WHERE contact_identity_commitment = ?1",
            params![contact_identity_commitment, change_event_id, seen_at],
        )?;
        self.contact_verification(contact_identity_commitment)?
            .ok_or_else(|| StorageError::AccountNotFound(contact_identity_commitment.to_owned()))
    }

    /// # Errors
    /// Returns an error when the gossip checkpoint cannot be persisted.
    pub fn observe_contact_gossip(
        &self,
        observation: ContactGossipObservation<'_>,
    ) -> Result<ContactVerificationRecord, StorageError> {
        if observation.reported_lineage_head != observation.expected_lineage_head {
            return self.observe_contact_fork(
                observation.contact_identity_commitment,
                observation.change_event_id,
                observation.seen_at,
            );
        }
        self.connection.execute(
            "UPDATE contact_verification_projection
                SET last_gossip_lineage_head = ?2
              WHERE contact_identity_commitment = ?1",
            params![observation.contact_identity_commitment, observation.reported_lineage_head],
        )?;
        self.contact_verification(observation.contact_identity_commitment)?.ok_or_else(|| {
            StorageError::AccountNotFound(observation.contact_identity_commitment.to_owned())
        })
    }

    /// # Errors
    /// Returns an error when the verification record lookup fails.
    pub fn contact_verification(
        &self,
        contact_identity_commitment: &str,
    ) -> Result<Option<ContactVerificationRecord>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT contact_identity_commitment, verification_state, safety_number_hash,
                        verified_device_set_hash, verified_lineage_head, verified_at,
                        verified_by_device_id, last_change_event_id, last_change_seen_at,
                        kt_tree_size, kt_tree_root_hash, kt_leaf_index, last_gossip_lineage_head
                   FROM contact_verification_projection
                  WHERE contact_identity_commitment = ?1",
                params![contact_identity_commitment],
                contact_verification_from_row,
            )
            .optional()?)
    }
}
