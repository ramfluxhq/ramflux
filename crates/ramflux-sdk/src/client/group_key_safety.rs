// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Directory key substitutions are durable safety observations, never group key rotations.
use crate::prelude::*;
impl RamfluxClient {
    pub(crate) fn record_pinned_group_key_changes(
        &self,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for device in &manifest.devices {
            for (group, pinned) in db.pinned_group_device_keys(&device.device_id)? {
                if pinned == device.branch_public_key {
                    continue;
                }
                let binding = ramflux_protocol::canonical_json_bytes(&(
                    &group,
                    &device.device_id,
                    &pinned,
                    &manifest.principal_id,
                    &manifest.principal_commitment,
                    &device.branch_public_key,
                ))?;
                let id = ramflux_crypto::blake3_256_base64url(
                    "ramflux.sdk.group.key_change.v1",
                    &binding,
                );
                let change = serde_json::json!({"id":id,"group_id":group,"device_id":device.device_id,"principal_id":manifest.principal_id,"state":"key_changed","reason":"pinned_group_member_key_changed"});
                let mut record =
                    db.client_record("group", &group)?.unwrap_or_else(|| serde_json::json!({}));
                record["safety_change"] = change.clone();
                db.persist_client_record("group", &group, &record)?;
                db.append_journal(
                    &format!("group-key-change:{id}"),
                    "safety.changed",
                    &change,
                    now_unix_timestamp(),
                    Some(&group),
                )?;
            }
        }
        Ok(())
    }
}
