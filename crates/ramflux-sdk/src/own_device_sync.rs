// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkOwnDeviceSyncEnvelope {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) principal_commitment: String,
    pub(crate) source_device_id: String,
    pub(crate) target_device_id: String,
    pub(crate) snapshot_id: String,
    pub(crate) snapshot_kind: String,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) nonce: String,
    pub(crate) history_ref: SdkDmAttachmentRef,
    pub(crate) signed: ramflux_protocol::SignedFields,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkOwnDeviceSyncSigningBody<'a> {
    pub(crate) schema: &'a str,
    pub(crate) version: u32,
    pub(crate) principal_commitment: &'a str,
    pub(crate) source_device_id: &'a str,
    pub(crate) target_device_id: &'a str,
    pub(crate) snapshot_id: &'a str,
    pub(crate) snapshot_kind: &'a str,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) nonce: &'a str,
    pub(crate) object_id: &'a str,
    pub(crate) key_slot_conversation_id: &'a str,
    pub(crate) key_slot_recipient_device_id: &'a str,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkOwnDeviceHistoryBundle {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) principal_commitment: String,
    pub(crate) source_device_id: String,
    pub(crate) target_device_id: String,
    pub(crate) snapshot_id: String,
    pub(crate) messages: Vec<DirectMessageRecord>,
    pub(crate) dm_sessions: Vec<SdkOwnDeviceDmSessionSnapshot>,
    pub(crate) groups: Vec<SdkOwnDeviceGroupSnapshot>,
    pub(crate) sender_key_distributions_base64: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkOwnDeviceDmSessionSnapshot {
    pub(crate) conversation_id: String,
    pub(crate) direction: String,
    pub(crate) snapshot: ramflux_crypto::DmSessionSnapshot,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkOwnDeviceGroupSnapshot {
    pub(crate) group_id: String,
    pub(crate) group_epoch: u64,
    pub(crate) max_members: u32,
    pub(crate) new_member_history: String,
    pub(crate) local_role: String,
    pub(crate) local_joined_epoch: u64,
    pub(crate) members: Vec<SdkOwnDeviceGroupMemberSnapshot>,
    pub(crate) routes: Vec<LocalBusGroupMemberRoute>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkOwnDeviceGroupMemberSnapshot {
    pub(crate) member_id: String,
    pub(crate) role: String,
    pub(crate) joined_epoch: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct SdkOwnDeviceSyncExportResponse {
    pub(crate) snapshot_id: String,
    pub(crate) object_id: String,
    pub(crate) transfer: SdkObjectTransferStatus,
    pub(crate) envelope: SdkOwnDeviceSyncEnvelope,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct SdkOwnDeviceSyncImportResponse {
    pub(crate) snapshot_id: String,
    pub(crate) imported_messages: usize,
    pub(crate) imported_dm_sessions: usize,
    pub(crate) imported_groups: usize,
    pub(crate) imported_sender_keys: usize,
}

pub(crate) fn own_device_sync_slot_conversation_id(
    snapshot_id: &str,
    object_id: &str,
    target_device_id: &str,
) -> String {
    format!("own_device.sync.slot:{snapshot_id}:{object_id}:{target_device_id}")
}

pub(crate) fn own_device_sync_signing_body(
    envelope: &SdkOwnDeviceSyncEnvelope,
) -> SdkOwnDeviceSyncSigningBody<'_> {
    SdkOwnDeviceSyncSigningBody {
        schema: &envelope.schema,
        version: envelope.version,
        principal_commitment: &envelope.principal_commitment,
        source_device_id: &envelope.source_device_id,
        target_device_id: &envelope.target_device_id,
        snapshot_id: &envelope.snapshot_id,
        snapshot_kind: &envelope.snapshot_kind,
        created_at: envelope.created_at,
        expires_at: envelope.expires_at,
        nonce: &envelope.nonce,
        object_id: &envelope.history_ref.object_id,
        key_slot_conversation_id: &envelope.history_ref.key_slot.conversation_id,
        key_slot_recipient_device_id: &envelope.history_ref.key_slot.recipient_device_id,
    }
}

pub(crate) fn group_message_epoch(message: &DirectMessageRecord) -> Option<(String, u64)> {
    serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&message.encrypted_body)
        .ok()
        .map(|envelope| (envelope.group_id, envelope.group_key_epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_device_sync_slot_binds_object_snapshot_and_target() {
        let object_id = "object_sync_test";
        let slot_a = own_device_sync_slot_conversation_id("snapshot_a", object_id, "device_b");
        let slot_b = own_device_sync_slot_conversation_id("snapshot_b", object_id, "device_b");
        let slot_c = own_device_sync_slot_conversation_id("snapshot_a", object_id, "device_c");
        assert_ne!(slot_a, slot_b);
        assert_ne!(slot_a, slot_c);
        let ad_a = object_key_slot_associated_data(object_id, &slot_a, "device_b");
        let ad_b = object_key_slot_associated_data(object_id, &slot_b, "device_b");
        let ad_c = object_key_slot_associated_data(object_id, &slot_a, "device_c");
        assert_ne!(ad_a, ad_b);
        assert_ne!(ad_a, ad_c);
        assert!(String::from_utf8(ad_a).unwrap_or_default().contains("device_b"));
    }
}
