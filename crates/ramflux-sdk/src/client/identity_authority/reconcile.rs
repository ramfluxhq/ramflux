// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adopt an own-root publication fork while retaining unacknowledged revocation intent.
use super::invalid;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{DeviceSetStatus, SignedDeviceSetEntry, SignedDeviceSetRecord};
use serde_json::json;
const INTENTS: &str = "identity/owned_revocation_intents";
impl RamfluxClient {
    pub(super) fn reconcile_owned_pending(
        &self,
        record: &SignedDeviceSetRecord,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let mut intents = db.load_actor_state::<Vec<String>>(INTENTS)?.unwrap_or_default();
        if let Some(pending) =
            db.load_actor_state::<SignedDeviceSetRecord>("identity/owned_pending_set")?
        {
            if record.device_set_epoch < pending.device_set_epoch {
                ramflux_crypto::validate_device_set_transition(record, &pending)?;
                return Ok(());
            }
            if ramflux_crypto::validate_device_set_transition(&pending, record).is_err() {
                // The caller already authenticated this remote record under our own root and
                // checked it against the last acknowledged epoch. A proposed fork is not an ACK.
                intents.extend(
                    pending
                        .devices
                        .iter()
                        .filter(|entry| entry.status == DeviceSetStatus::Revoked)
                        .map(|entry| entry.device_id.clone()),
                );
                db.append_journal(&format!("owned-proposal-discarded:{}:{}",pending.device_set_epoch,record.device_set_epoch),"safety.changed",&json!({"reason":"own_publication_fork_rebased","discarded_epoch":pending.device_set_epoch,"adopted_epoch":record.device_set_epoch}),crate::prelude::now_unix_timestamp(),None)?;
            }
            db.remove_actor_state("identity/owned_pending_set")?;
        }
        intents.sort();
        intents.dedup();
        intents.retain(|id| {
            !record
                .devices
                .iter()
                .any(|entry| entry.device_id == *id && entry.status == DeviceSetStatus::Revoked)
        });
        db.persist_actor_state(INTENTS, &intents)?;
        Ok(())
    }
    pub(super) fn apply_owned_revocation_intents(
        &self,
        entries: &mut [SignedDeviceSetEntry],
    ) -> Result<(), SdkError> {
        let intents =
            self.account_db()?.load_actor_state::<Vec<String>>(INTENTS)?.unwrap_or_default();
        for id in intents {
            let entry = entries
                .iter_mut()
                .find(|entry| entry.device_id == id)
                .ok_or_else(|| invalid("pending revocation target missing from remote record"))?;
            if entry.status != DeviceSetStatus::Revoked {
                entry.status = DeviceSetStatus::Revoked;
                entry.revoked_at = Some(crate::prelude::now_unix_timestamp());
            }
        }
        Ok(())
    }
}
