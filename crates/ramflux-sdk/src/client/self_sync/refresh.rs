// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Roster refresh barrier: private registers never cross a device-set change out of order.
//!
//! The barrier is the highest verified own-root roster generation under which this
//! device applied or emitted a register. A roster older than the barrier parks both
//! directions. Crossing to a newer roster retires envelopes sealed for the previous one,
//! and a new local incarnation (re-enrollment or restore activation) retires every send
//! queue so the courier rebuilds them from the current registers and the current roster.
use super::{RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};

const BARRIER: &str = "self-sync/refresh/barrier";

/// One verified own-root roster generation as seen by the local incarnation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Generation {
    device_set_epoch: u64,
    head: String,
    local_epoch: u64,
}

fn parked(reason: &str) -> SdkError {
    SdkError::InboundPending(format!("self sync: {reason}"))
}

impl RamfluxClient {
    /// The current verified roster generation; `None` for an account without native custody.
    pub(super) fn self_sync_refresh_generation(&self) -> Result<Option<Generation>, SdkError> {
        let local = self.owned_device_identity()?;
        let now = crate::custody::network_now()?;
        let Some(authority) = self.current_custody_authority(local.root_commitment(), now)? else {
            return Ok(None);
        };
        let body = &authority.envelope().body;
        let local_epoch = body
            .devices
            .iter()
            .find(|entry| entry.device_id == local.device_id())
            .map(|entry| entry.device_epoch)
            .ok_or_else(|| parked("local device absent from the refreshed roster"))?;
        Ok(Some(Generation {
            device_set_epoch: body.device_set_epoch,
            head: ramflux_protocol::custody::object_hash(authority.envelope())?,
            local_epoch,
        }))
    }

    /// Enter the current generation before applying or emitting a register.
    /// Returns the generation the caller must still observe when it commits.
    pub(super) fn enter_self_sync_refresh(&self) -> Result<Option<Generation>, SdkError> {
        let Some(current) = self.self_sync_refresh_generation()? else {
            return Ok(None);
        };
        let db = self.account_db()?;
        let stored = db.load_actor_state::<Generation>(BARRIER)?;
        if stored.as_ref() == Some(&current) {
            return Ok(Some(current));
        }
        if stored.as_ref().is_some_and(|stored| current.device_set_epoch < stored.device_set_epoch)
        {
            return Err(parked("roster is behind the refresh barrier"));
        }
        let reincarnated =
            stored.as_ref().is_some_and(|stored| stored.local_epoch != current.local_epoch);
        db.write_transaction(|| {
            if stored.is_some() {
                self.retire_self_sync_refresh_crossing(reincarnated)?;
            }
            db.persist_actor_state(BARRIER, &current)?;
            Ok::<(), SdkError>(())
        })?;
        Ok(Some(current))
    }

    fn retire_self_sync_refresh_crossing(&self, reincarnated: bool) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for key in db.actor_state_keys("self-sync/pending/")? {
            let Some(row) = db.load_actor_state::<serde_json::Value>(&key)? else {
                continue;
            };
            // Courier rows end in their slot; caller-submitted deliveries do not.
            let courier = key.ends_with("/register") || key.ends_with("/read");
            if reincarnated || (courier && !row["envelope"].is_null()) {
                db.retire_self_sync_actor(&key)?;
            }
        }
        if reincarnated {
            for prefix in ["self-sync/repair/", "self-sync/repair-sent/"] {
                for key in db.actor_state_keys(prefix)? {
                    db.retire_self_sync_actor(&key)?;
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn force_self_sync_refresh_barrier(
        &self,
        change: impl FnOnce(&mut u64, &mut String, &mut u64),
    ) -> Result<(), SdkError> {
        let mut barrier = self
            .account_db()?
            .load_actor_state::<Generation>(BARRIER)?
            .ok_or_else(|| parked("no barrier recorded"))?;
        change(&mut barrier.device_set_epoch, &mut barrier.head, &mut barrier.local_epoch);
        self.account_db()?.persist_actor_state(BARRIER, &barrier)?;
        Ok(())
    }
}
