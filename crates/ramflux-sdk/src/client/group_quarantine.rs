// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy retries preserve ciphertext; only immutable failures authorize rejection ACKs.
use crate::prelude::*;
pub(crate) enum LegacyGroupDelivery {
    Applied(GroupGatewayDeliveryResult),
    Held,
    Rejected,
}
pub(crate) fn legacy_key(entry: &GatewayInboxEntry) -> Result<String, SdkError> {
    // Match sender authentication: gateway-added receipt fields do not identify a new message.
    let mut envelope = entry.envelope.clone();
    if let Some(receipt) =
        envelope.ext.ext.get_mut("franking").and_then(serde_json::Value::as_object_mut)
    {
        for field in ["franking_tag", "node_id", "accepted_at"] {
            receipt.remove(field);
        }
    }
    Ok(format!(
        "legacy:{}",
        ramflux_protocol::hash_base64url(
            "ramflux.legacy.inbox.v1",
            &ramflux_protocol::canonical_json_bytes(&envelope)?,
        )
    ))
}
impl RamfluxClient {
    pub(crate) fn retain_legacy_group_entry(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let key = legacy_key(entry)?;
        let db = self.account_db()?;
        db.hold_unrouted(&key, entry.inbox_seq, &serde_json::to_vec(entry)?, now_unix_timestamp())?;
        db.retain_legacy_inbox(&key)?;
        Ok(())
    }
    pub(crate) fn legacy_group_retry_ready(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        let now = now_unix_timestamp();
        let key = legacy_key(entry)?;
        let db = self.account_db()?;
        db.redrive_inbox_changes(now)?;
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id;
        if !super::inbox_failure::set_failure_policy(
            self,
            local,
            entry,
            &key,
            &serde_json::to_vec(entry)?,
            now,
        )? {
            return Ok(false);
        }
        Ok(db.inbox_retry_ready(&key, now)?)
    }
    pub(crate) fn isolate_legacy_group_delivery(
        &self,
        entry: &GatewayInboxEntry,
        result: Result<GroupGatewayDeliveryResult, SdkError>,
    ) -> Result<LegacyGroupDelivery, SdkError> {
        self.retain_legacy_group_entry(entry)?;
        let db = self.account_db()?;
        let key = legacy_key(entry)?;
        match result {
            Ok(delivery) => {
                db.remove_inbox_retry(&key)?;
                Ok(LegacyGroupDelivery::Applied(delivery))
            }
            Err(SdkError::Storage(error))
                if !matches!(error, StorageError::GroupPermissionDenied) =>
            {
                Err(SdkError::Storage(error))
            }
            Err(SdkError::Io(error)) => Err(SdkError::Io(error)),
            Err(error) => {
                let error = super::inbox_failure::wire_signature_error(entry).unwrap_or(error);
                let bytes = serde_json::to_vec(entry)?;
                let now = now_unix_timestamp();
                if let Some(code) = super::inbox_failure::deterministic(&error) {
                    db.write_transaction(|| {
                        db.dead_letter_inbox(&key, &bytes, &serde_json::json!({"envelope_id":entry.envelope.envelope_id,"claimed_source_device_id":entry.envelope.source_device_id,"error_code":code}), now)?;
                        db.remove_unrouted(&key)?;
                        Ok::<_,SdkError>(())
                    })?;
                    return Ok(LegacyGroupDelivery::Rejected);
                }
                let local =
                    &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id;
                let admitted = super::inbox_failure::set_failure_policy(
                    self, local, entry, &key, &bytes, now,
                )?;
                if admitted
                    && db.inbox_retry_ready(&key, now)?
                    && db.defer_inbox_entry(&key, &bytes, now)? == 0
                {
                    db.park_legacy_inbox_retry(&key)?;
                }
                Ok(LegacyGroupDelivery::Held)
            }
        }
    }
}
