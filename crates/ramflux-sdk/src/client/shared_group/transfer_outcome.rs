// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded outcome fences keep delayed probes from recreating completed reservations.
use super::transfer::requires_sync_reason;
use super::transfer_wire::{TransferDevice, TransferProbe};
use crate::prelude::*;
use serde::{Deserialize, Serialize};
const PREFIX: &str = "group-transfer/outcome/";
#[derive(Deserialize, Serialize)]
struct Outcome {
    issuer: TransferDevice,
    cancelled: bool,
    expires_at: i64,
}
fn key(group: &str, proposal: &str) -> String {
    format!("{PREFIX}{}/{}", ramflux_protocol::encode_base64url(group), proposal)
}
impl RamfluxClient {
    pub(super) fn reserve_group_transfer_outcome(
        &self,
        probe: &TransferProbe,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.retain_expiring_actor_states(PREFIX, now_unix_timestamp(), 4096)?;
        let id = key(&probe.base.group_id, &probe.id);
        let issuer = TransferDevice {
            root: probe.actor.identity.root_commitment.clone(),
            device: probe.actor.identity.device_id.clone(),
        };
        if let Some(old) = db.load_actor_state::<Outcome>(&id)? {
            if old.issuer != issuer || old.cancelled {
                return Err(requires_sync_reason("proposal_already_completed"));
            }
        } else if db.actor_state_usage(PREFIX)?.0 >= 4096 {
            return Err(requires_sync_reason("transfer_outcome_capacity"));
        }
        db.persist_actor_state(
            &id,
            &Outcome {
                issuer,
                cancelled: false,
                expires_at: ramflux_protocol::MAX_SAFE_JSON_INTEGER.cast_signed(),
            },
        )?;
        Ok(())
    }
    pub(super) fn remember_group_transfer_outcome(
        &self,
        group: &str,
        proposal: &str,
        issuer: TransferDevice,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.retain_expiring_actor_states(PREFIX, now_unix_timestamp(), 4096)?;
        let id = key(group, proposal);
        if let Some(old) = db.load_actor_state::<Outcome>(&id)? {
            if old.issuer != issuer {
                return Err(StorageError::GroupPermissionDenied.into());
            }
        } else if db.actor_state_usage(PREFIX)?.0 >= 4096 {
            return Err(requires_sync_reason("transfer_outcome_capacity"));
        }
        // Probes live for 60 s with ±300 s relative skew. Retain the outcome
        // beyond every remaining valid delivery even if cancellation arrived first.
        db.persist_actor_state(
            &id,
            &Outcome {
                issuer,
                cancelled: true,
                expires_at: now_unix_timestamp().saturating_add(720),
            },
        )?;
        Ok(())
    }
    pub(super) fn finish_group_transfer_outcome(
        &self,
        group: &str,
        proposal: &str,
    ) -> Result<(), SdkError> {
        if let Some(old) = self.account_db()?.load_actor_state::<Outcome>(&key(group, proposal))? {
            self.remember_group_transfer_outcome(group, proposal, old.issuer)?;
        }
        Ok(())
    }
}
