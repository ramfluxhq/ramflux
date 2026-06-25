#![allow(clippy::wildcard_imports)]
use crate::*;

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
