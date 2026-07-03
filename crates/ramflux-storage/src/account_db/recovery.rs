// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::row_mappers::guardian_recovery_share_from_row;
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
}
