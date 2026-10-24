// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Disposable own-history import acknowledgements use their actor namespace, not surface storage.
use crate::own_device_sync::{SdkOwnDeviceSyncEnvelope, SdkOwnDeviceSyncImportResponse};
use crate::{RamfluxClient, SdkError};
const PREFIX: &str = "own-device/imported/";
const MAX_ROWS: u32 = 512;
const MAX_BYTES: u64 = 256 * 1024;
impl RamfluxClient {
    pub(crate) fn cache_own_sync_import_receipt(
        &self,
        envelope: &SdkOwnDeviceSyncEnvelope,
        result: &SdkOwnDeviceSyncImportResponse,
    ) -> Result<(), SdkError> {
        let id = Self::own_sync_receipt_key(envelope)?;
        let mut row = serde_json::to_value(result)?;
        row["expires_at"] = serde_json::json!(envelope.expires_at.saturating_add(300));
        let size = u64::try_from(serde_json::to_vec(&row)?.len())
            .map_err(|_| SdkError::LocalBus("own-history receipt size overflow".into()))?;
        if size > MAX_BYTES {
            return Err(SdkError::LocalBus("own-history receipt byte budget exceeded".into()));
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            // Keep room for this exact receipt; an eviction cannot drop the just-committed ACK.
            db.remove_actor_state(&id)?;
            db.retain_expiring_actor_states(
                PREFIX,
                crate::prelude::now_unix_timestamp(),
                MAX_ROWS - 1,
            )?;
            let (_, mut bytes) = db.actor_state_usage(PREFIX)?;
            for key in db.actor_state_key_page(PREFIX, MAX_ROWS - 1)? {
                if bytes.saturating_add(size) <= MAX_BYTES {
                    break;
                }
                if let Some(old) = db.load_actor_state::<serde_json::Value>(&key)? {
                    let old_size =
                        u64::try_from(serde_json::to_vec(&old)?.len()).map_err(|_| {
                            SdkError::LocalBus("own-history receipt size overflow".into())
                        })?;
                    db.remove_actor_state(&key)?;
                    bytes = bytes.saturating_sub(old_size);
                }
            }
            db.persist_actor_state(&id, &row)?;
            Ok::<_, SdkError>(())
        })
    }
}
