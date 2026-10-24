// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded key-change observations preserve the first unresolved safety notice.
use crate::prelude::*;
const NOTICE_INTERVAL: i64 = 60;
const NOTICE_HISTORY: usize = 4;
impl RamfluxClient {
    pub(crate) fn record_pinned_group_key_changes(
        &self,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let at = now_unix_timestamp();
        for device in &manifest.devices {
            let identity = Self::device_identity_from_manifest(manifest, &device.device_id)?;
            let reference = identity.storage_key();
            for (group, pinned) in db.pinned_group_device_keys(&identity)? {
                if pinned == device.branch_public_key {
                    continue;
                }
                let bound = db
                    .group_member_key_binding(&group, &identity)?
                    .ok_or_else(|| SdkError::InboundPending("group pin changed".into()))?;
                // Use the pinned owner, never the manifest claimant, as the admission bucket.
                let observed_owner = bound.principal_id.as_deref().unwrap_or(&pinned);
                let owner_key = format!(
                    "safety/member-owner/{}",
                    ramflux_protocol::hash_base64url(
                        "ramflux.sdk.safety.device.v1",
                        reference.as_bytes()
                    )
                );
                let owner = if let Some(owner) = db.load_actor_state::<String>(&owner_key)? {
                    owner
                } else {
                    db.persist_actor_state(&owner_key, &observed_owner)?;
                    observed_owner.to_owned()
                };
                let bucket = format!(
                    "safety/member/{}",
                    ramflux_protocol::hash_base64url(
                        "ramflux.sdk.safety.member.v1",
                        &ramflux_protocol::canonical_json_bytes(&(owner, &reference))?
                    )
                );
                let previous = db.load_actor_state::<serde_json::Value>(&bucket)?;
                let id = ramflux_protocol::hash_base64url(
                    "ramflux.sdk.group.key_change.v1",
                    &ramflux_protocol::canonical_json_bytes(&(
                        &group,
                        &device.device_id,
                        &pinned,
                        &manifest.principal_id,
                        &manifest.principal_commitment,
                        &device.branch_public_key,
                    ))?,
                );
                let change = serde_json::json!({"id":id,"group_id":group,"device_id":device.device_id,"principal_id":manifest.principal_id,"state":"key_changed","reason":"pinned_group_member_key_changed"});
                let mut record =
                    db.client_record("group", &group)?.unwrap_or_else(|| serde_json::json!({}));
                if record.get("safety_change").is_none_or(serde_json::Value::is_null) {
                    record["safety_change"] = change.clone();
                    db.persist_client_record("group", &group, &record)?;
                }
                if previous
                    .as_ref()
                    .and_then(|value| value["at"].as_i64())
                    .is_some_and(|last| at < last.saturating_add(NOTICE_INTERVAL))
                {
                    continue;
                }
                let mut history = previous
                    .as_ref()
                    .and_then(|value| value["history"].as_array())
                    .cloned()
                    .unwrap_or_default();
                if history.iter().any(|old| old["id"] == id) {
                    continue;
                }
                history.push(change.clone());
                if history.len() > NOTICE_HISTORY {
                    history.remove(1);
                }
                db.persist_actor_state(&bucket, &serde_json::json!({"at":at,"history":history}))?;
                record["safety_changes"] = serde_json::json!(history);
                db.persist_client_record("group", &group, &record)?;
                db.append_journal(
                    &format!("group-key-change:{id}"),
                    "safety.changed",
                    &change,
                    at,
                    Some(&group),
                )?;
            }
        }
        Ok(())
    }
}
