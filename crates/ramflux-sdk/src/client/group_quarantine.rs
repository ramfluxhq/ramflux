// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Isolate legacy group failures before acknowledging terminal rejected entries.
use crate::prelude::*;
impl RamfluxClient {
    pub(crate) fn isolate_legacy_group_delivery(
        &self,
        entry: &GatewayInboxEntry,
        result: Result<GroupGatewayDeliveryResult, SdkError>,
    ) -> Result<Option<GroupGatewayDeliveryResult>, SdkError> {
        let db = self.account_db()?;
        let key = crate::client::routed::committed_key(entry)?;
        match result {
            Ok(delivery) => {
                db.remove_inbox_retry(&key)?;
                Ok(Some(delivery))
            }
            Err(SdkError::Storage(error))
                if !matches!(error, StorageError::GroupPermissionDenied) =>
            {
                Err(SdkError::Storage(error))
            }
            Err(SdkError::Io(error)) => Err(SdkError::Io(error)),
            Err(error) => {
                let bytes = serde_json::to_vec(entry)?;
                let now = now_unix_timestamp();
                if matches!(error, SdkError::InboundPending(_) | SdkError::Transport(_))
                    && bytes.len() <= 1024 * 1024
                    && db.defer_inbox_entry(&key, &bytes, now)? != 0
                {
                    return Ok(None);
                }
                db.write_transaction(|| {
                    db.dead_letter_inbox(
                        &key,
                        &bytes,
                        &serde_json::json!({
                            "envelope_id": entry.envelope.envelope_id,
                            "claimed_source_device_id": entry.envelope.source_device_id,
                            "error_code": "legacy_group_rejected",
                        }),
                        now,
                    )?;
                    db.remove_unrouted(&key)?;
                    db.remove_unrouted(&entry.envelope.envelope_id)?;
                    Ok::<_, SdkError>(())
                })?;
                Ok(None)
            }
        }
    }
}
