// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy retries preserve ciphertext; only immutable failures authorize rejection ACKs.
use crate::client::identity_authority::HeadUse;
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
        let now = now_unix_timestamp();
        db.write_transaction(|| {
            db.hold_unrouted(&key,entry.inbox_seq,&serde_json::to_vec(entry)?,now)?;
            db.retain_legacy_inbox(&key)?;
            db.append_journal(&format!("unrouted:{key}"),"message.unrouted",&serde_json::json!({"envelope_id":entry.envelope.envelope_id,"claimed_source_device_id":entry.envelope.source_device_id,"payload_hash":entry.envelope.payload_hash,"inbox_seq":entry.inbox_seq,"legacy_group":true}),now,None)?;
            Ok::<_,SdkError>(())
        })
    }
    pub(crate) fn legacy_group_retry_ready(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        let now = now_unix_timestamp();
        let key = legacy_key(entry)?;
        let db = self.account_db()?;
        db.redrive_inbox_changes(now)?;
        if db.legacy_inbox_parked(&key)? {
            return Ok(db.legacy_inbox_lookup_recoverable(&key)?
                && self.cached_legacy_group_ready(entry)?);
        }
        let retrying = db.has_inbox_retry(&key)?;
        if !retrying && !db.legacy_inbox_quota_blocked(&key)? {
            return Ok(true);
        }
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id;
        let admitted = super::inbox_failure::set_failure_policy(
            self,
            local,
            entry,
            &key,
            &serde_json::to_vec(entry)?,
            now,
        )?;
        let scheduled = retrying
            || (admitted && db.defer_inbox_entry(&key, &serde_json::to_vec(entry)?, now)? != 0);
        if admitted && scheduled && (!retrying || db.inbox_retry_ready(&key, now)?) {
            return Ok(true);
        }
        Ok(db.legacy_inbox_lookup_recoverable(&key)? && self.cached_legacy_group_ready(entry)?)
    }
    fn cached_legacy_group_ready(&self, entry: &GatewayInboxEntry) -> Result<bool, SdkError> {
        let parsed = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&bytes).ok());
        let Some(group) = parsed
            .filter(|g| g.schema == "ramflux.sdk.group_sender_key.message.v1" && g.version == 1)
        else {
            return Ok(false);
        };
        let Ok(source) = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)
        else {
            return Ok(false);
        };
        let cached = self.account_db()?.client_device_record(&source).ok().flatten();
        if cached.is_none_or(|record| record.get("x25519_identity_public").is_none()) {
            return Ok(false);
        }
        Ok(self.require_group_payload_sender(&group.group_id, &group.sender_id, entry).is_ok())
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
                let mut blocked = !admitted;
                if admitted
                    && db.inbox_retry_ready(&key, now)?
                    && db.defer_inbox_entry(&key, &bytes, now)? == 0
                {
                    db.park_legacy_inbox_retry(&key)?;
                    blocked = true;
                }
                db.record_legacy_inbox_failure(
                    &key,
                    matches!(
                        error,
                        SdkError::InboundPending(_)
                            | SdkError::SenderManifestRequired { .. }
                            | SdkError::FreshHeadRequired { .. }
                            | SdkError::GatewaySessionRejected(_)
                            | SdkError::Transport(_)
                            | SdkError::LocalBus(_)
                    ),
                    blocked,
                )?;
                Ok(LegacyGroupDelivery::Held)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_group_key_is_stable_for_the_same_envelope() -> Result<(), SdkError> {
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: "t".into(),
            envelope: ramflux_protocol::Envelope {
                schema: "ramflux.envelope.v1".into(),
                version: 1,
                domain: "test".into(),
                ext: ramflux_protocol::Ext::default(),
                signed: crate::prelude::sdk_device_signed_fields("device", ""),
                envelope_id: "env".into(),
                source_principal_id: "source".into(),
                source_device_id: "device".into(),
                target_delivery_id: "t".into(),
                routing_set_id: None,
                delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
                priority: ramflux_protocol::Priority::Normal,
                ttl: 60,
                created_at: 1,
                encrypted_payload: "cipher".into(),
                payload_hash: "hash".into(),
                delivery_mode: None,
                collapse_tag: None,
                report_commitment: None,
            },
        };
        let first = legacy_key(&entry)?;
        let second = legacy_key(&entry)?;
        assert_eq!(first, second);
        assert!(first.starts_with("legacy:"));
        Ok(())
    }
}
