// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use crate::*;
use rusqlite::types::Type;

pub(crate) fn contact_verification_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ContactVerificationRecord> {
    let kt_tree_size_i64: Option<i64> = row.get(9)?;
    let kt_leaf_index_i64: Option<i64> = row.get(11)?;
    Ok(ContactVerificationRecord {
        contact_identity_commitment: row.get(0)?,
        verification_state: row.get(1)?,
        safety_number_hash: row.get(2)?,
        verified_device_set_hash: row.get(3)?,
        verified_lineage_head: row.get(4)?,
        verified_at: row.get(5)?,
        verified_by_device_id: row.get(6)?,
        last_change_event_id: row.get(7)?,
        last_change_seen_at: row.get(8)?,
        kt_tree_size: kt_tree_size_i64.and_then(|value| u64::try_from(value).ok()),
        kt_tree_root_hash: row.get(10)?,
        kt_leaf_index: kt_leaf_index_i64.and_then(|value| u64::try_from(value).ok()),
        last_gossip_lineage_head: row.get(12)?,
    })
}

pub(crate) fn friend_link_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FriendLinkRecord> {
    let blocked: i64 = row.get(5)?;
    Ok(FriendLinkRecord {
        link_id: row.get(0)?,
        requester_id: row.get(1)?,
        target_id: row.get(2)?,
        state: row.get(3)?,
        remove_scope: row.get(4)?,
        blocked: blocked != 0,
        capability_revoked_at: row.get(6)?,
    })
}

pub(crate) fn rejected_inbox_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RejectedInboxRecord> {
    Ok(RejectedInboxRecord {
        conversation_id: row.get(0)?,
        message_id: row.get(1)?,
        sender_id: row.get(2)?,
        reason: row.get(3)?,
        rejected_at: row.get(4)?,
    })
}

pub(crate) fn object_share_grant_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ObjectShareGrantRecord> {
    Ok(ObjectShareGrantRecord {
        object_id: row.get(0)?,
        recipient_principal_id: row.get(1)?,
        recipient_principal_commitment: row.get(2)?,
        recipient_device_id: row.get(3)?,
        conversation_id: row.get(4)?,
        shared_at: row.get(5)?,
        revoked_at: row.get(6)?,
    })
}

pub(crate) fn guardian_recovery_share_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<GuardianRecoveryShareRecord> {
    Ok(GuardianRecoveryShareRecord {
        owner_principal_id: row.get(0)?,
        guardian_principal_id: row.get(1)?,
        recovery_quorum_id: row.get(2)?,
        share_id: row.get(3)?,
        threshold: row.get(4)?,
        total: row.get(5)?,
        member_kind: row.get(6)?,
        share_value: row.get(7)?,
        inviter_device_id: row.get(8)?,
        inviter_device_public_key_base64url: row.get(9)?,
        invite_id: row.get(10)?,
        accepted_at: row.get(11)?,
        accepted_by_device_id: row.get(12)?,
        accept_signature: row.get(13)?,
        state: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

pub(crate) fn pending_recovery_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PendingRecoveryRecord> {
    let recovery_quorum_json: Vec<u8> = row.get(9)?;
    let context_json: Vec<u8> = row.get(10)?;
    Ok(PendingRecoveryRecord {
        recovery_id: row.get(0)?,
        owner_principal_id: row.get(1)?,
        recovery_quorum_id: row.get(2)?,
        lifecycle_epoch: row.get(3)?,
        lineage_head: row.get(4)?,
        event_type: row.get(5)?,
        timelock_started_at: row.get(6)?,
        timelock_until: row.get(7)?,
        state: row.get(8)?,
        recovery_quorum: serde_json::from_slice(&recovery_quorum_json).map_err(|source| {
            rusqlite::Error::FromSqlConversionFailure(9, Type::Blob, Box::new(source))
        })?,
        context: serde_json::from_slice(&context_json).map_err(|source| {
            rusqlite::Error::FromSqlConversionFailure(10, Type::Blob, Box::new(source))
        })?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

pub(crate) fn pending_recovery_approval_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PendingRecoveryApprovalRecord> {
    let approval_json: Vec<u8> = row.get(3)?;
    Ok(PendingRecoveryApprovalRecord {
        recovery_id: row.get(0)?,
        signing_key_id: row.get(1)?,
        member_kind: row.get(2)?,
        approval: serde_json::from_slice(&approval_json).map_err(|source| {
            rusqlite::Error::FromSqlConversionFailure(3, Type::Blob, Box::new(source))
        })?,
        approved_at: row.get(4)?,
    })
}
