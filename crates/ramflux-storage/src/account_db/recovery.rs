// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::row_mappers::{
    guardian_recovery_share_from_row, pending_recovery_approval_from_row, pending_recovery_from_row,
};
use rusqlite::OptionalExtension;

impl AccountDb {
    pub fn record_guardian_recovery_share(
        &self,
        write: &GuardianRecoveryShareWrite<'_>,
    ) -> Result<GuardianRecoveryShareRecord, StorageError> {
        let now = self.now_unix();
        self.connection.execute(
            "INSERT INTO guardian_recovery_share_projection (
                owner_principal_id, guardian_principal_id, recovery_quorum_id, share_id,
                threshold, total, member_kind, share_value, inviter_device_id,
                inviter_device_public_key_base64url, invite_id, accepted_at,
                accepted_by_device_id, accept_signature, state, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16)
             ON CONFLICT(owner_principal_id, recovery_quorum_id, guardian_principal_id) DO UPDATE SET
                share_id = excluded.share_id,
                threshold = excluded.threshold,
                total = excluded.total,
                member_kind = excluded.member_kind,
                share_value = excluded.share_value,
                inviter_device_id = excluded.inviter_device_id,
                inviter_device_public_key_base64url = excluded.inviter_device_public_key_base64url,
                invite_id = excluded.invite_id,
                accepted_at = excluded.accepted_at,
                accepted_by_device_id = excluded.accepted_by_device_id,
                accept_signature = excluded.accept_signature,
                state = excluded.state,
                updated_at = excluded.updated_at",
            params![
                write.owner_principal_id,
                write.guardian_principal_id,
                write.recovery_quorum_id,
                write.share_id,
                write.threshold,
                write.total,
                write.member_kind,
                write.share_value,
                write.inviter_device_id,
                write.inviter_device_public_key_base64url,
                write.invite_id,
                write.accepted_at,
                write.accepted_by_device_id,
                write.accept_signature,
                write.state,
                now,
            ],
        )?;
        self.guardian_recovery_share(
            write.owner_principal_id,
            write.recovery_quorum_id,
            write.guardian_principal_id,
        )?
        .ok_or_else(|| StorageError::MessageNotFound(write.invite_id.to_owned()))
    }

    pub fn guardian_recovery_share(
        &self,
        owner_principal_id: &str,
        recovery_quorum_id: &str,
        guardian_principal_id: &str,
    ) -> Result<Option<GuardianRecoveryShareRecord>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT owner_principal_id, guardian_principal_id, recovery_quorum_id, share_id,
                        threshold, total, member_kind, share_value, inviter_device_id,
                        inviter_device_public_key_base64url, invite_id, accepted_at,
                        accepted_by_device_id, accept_signature, state, created_at, updated_at
                   FROM guardian_recovery_share_projection
                  WHERE owner_principal_id = ?1
                    AND recovery_quorum_id = ?2
                    AND guardian_principal_id = ?3",
                params![owner_principal_id, recovery_quorum_id, guardian_principal_id],
                guardian_recovery_share_from_row,
            )
            .optional()?)
    }

    pub fn guardian_recovery_shares_for_owner(
        &self,
        owner_principal_id: &str,
    ) -> Result<Vec<GuardianRecoveryShareRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT owner_principal_id, guardian_principal_id, recovery_quorum_id, share_id,
                    threshold, total, member_kind, share_value, inviter_device_id,
                    inviter_device_public_key_base64url, invite_id, accepted_at,
                    accepted_by_device_id, accept_signature, state, created_at, updated_at
               FROM guardian_recovery_share_projection
              WHERE owner_principal_id = ?1
              ORDER BY accepted_at ASC, recovery_quorum_id ASC, guardian_principal_id ASC",
        )?;
        let rows =
            statement.query_map(params![owner_principal_id], guardian_recovery_share_from_row)?;
        let mut shares = Vec::new();
        for row in rows {
            shares.push(row?);
        }
        Ok(shares)
    }

    pub fn create_pending_recovery(
        &self,
        write: &PendingRecoveryWrite<'_>,
    ) -> Result<PendingRecoveryRecord, StorageError> {
        let now = self.now_unix();
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO pending_recovery_projection (
                recovery_id, owner_principal_id, recovery_quorum_id, lifecycle_epoch, lineage_head,
                event_type, timelock_started_at, timelock_until, state, recovery_quorum_json,
                context_json, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, 'initiated', ?8, ?9, ?10, ?10)",
            params![
                write.recovery_id,
                write.owner_principal_id,
                write.recovery_quorum.recovery_quorum_id,
                write.lifecycle_epoch,
                write.lineage_head,
                write.event_type,
                write.timelock_until,
                serde_json::to_vec(write.recovery_quorum)?,
                serde_json::to_vec(write.context)?,
                now,
            ],
        )?;
        if inserted == 0 {
            return Err(StorageError::MessageIdConflict(write.recovery_id.to_owned()));
        }
        self.pending_recovery(write.recovery_id)?
            .ok_or_else(|| StorageError::MessageNotFound(write.recovery_id.to_owned()))
    }

    pub fn pending_recovery(
        &self,
        recovery_id: &str,
    ) -> Result<Option<PendingRecoveryRecord>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT recovery_id, owner_principal_id, recovery_quorum_id, lifecycle_epoch,
                        lineage_head, event_type, timelock_started_at, timelock_until, state,
                        recovery_quorum_json, context_json, created_at, updated_at
                   FROM pending_recovery_projection
                  WHERE recovery_id = ?1",
                params![recovery_id],
                pending_recovery_from_row,
            )
            .optional()?)
    }

    pub fn transition_pending_recovery(
        &self,
        recovery_id: &str,
        expected_state: &str,
        next_state: &str,
        timelock_started_at: Option<i64>,
    ) -> Result<PendingRecoveryRecord, StorageError> {
        let updated = self.connection.execute(
            "UPDATE pending_recovery_projection
                SET state = ?3,
                    timelock_started_at = COALESCE(timelock_started_at, ?4),
                    updated_at = ?5
              WHERE recovery_id = ?1 AND state = ?2",
            params![recovery_id, expected_state, next_state, timelock_started_at, self.now_unix()],
        )?;
        if updated == 0 {
            return Err(StorageError::InvalidRecoveryState {
                recovery_id: recovery_id.to_owned(),
                expected: expected_state.to_owned(),
            });
        }
        self.pending_recovery(recovery_id)?
            .ok_or_else(|| StorageError::MessageNotFound(recovery_id.to_owned()))
    }

    pub fn record_pending_recovery_approval(
        &self,
        write: &PendingRecoveryApprovalWrite<'_>,
    ) -> Result<PendingRecoveryApprovalRecord, StorageError> {
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO pending_recovery_approval_projection (
                recovery_id, signing_key_id, member_kind, approval_json, approved_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                write.recovery_id,
                write.approval.signing_key_id,
                recovery_member_kind_name(&write.approval.member_kind),
                serde_json::to_vec(write.approval)?,
                write.approved_at,
            ],
        )?;
        if inserted == 0 {
            return Err(StorageError::MessageIdConflict(format!(
                "{}:{}",
                write.recovery_id, write.approval.signing_key_id
            )));
        }
        self.pending_recovery_approval(write.recovery_id, &write.approval.signing_key_id)?
            .ok_or_else(|| StorageError::MessageNotFound(write.recovery_id.to_owned()))
    }

    pub fn pending_recovery_approval(
        &self,
        recovery_id: &str,
        signing_key_id: &str,
    ) -> Result<Option<PendingRecoveryApprovalRecord>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT recovery_id, signing_key_id, member_kind, approval_json, approved_at
                   FROM pending_recovery_approval_projection
                  WHERE recovery_id = ?1 AND signing_key_id = ?2",
                params![recovery_id, signing_key_id],
                pending_recovery_approval_from_row,
            )
            .optional()?)
    }

    pub fn pending_recovery_approvals(
        &self,
        recovery_id: &str,
    ) -> Result<Vec<PendingRecoveryApprovalRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT recovery_id, signing_key_id, member_kind, approval_json, approved_at
               FROM pending_recovery_approval_projection
              WHERE recovery_id = ?1
              ORDER BY approved_at ASC, signing_key_id ASC",
        )?;
        let rows = statement.query_map(params![recovery_id], pending_recovery_approval_from_row)?;
        let mut approvals = Vec::new();
        for row in rows {
            approvals.push(row?);
        }
        Ok(approvals)
    }
}

fn recovery_member_kind_name(kind: &ramflux_protocol::RecoveryQuorumMemberKind) -> &'static str {
    match kind {
        ramflux_protocol::RecoveryQuorumMemberKind::RootShare => "root_share",
        ramflux_protocol::RecoveryQuorumMemberKind::DeviceShare => "device_share",
        ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare => "guardian_share",
        ramflux_protocol::RecoveryQuorumMemberKind::HardwareTokenShare => "hardware_token_share",
    }
}
