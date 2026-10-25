// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deferred same-root group metadata; only verified manifests can create device identity pins.
use crate::own_device_sync::SdkOwnDeviceGroupMemberPin;
use crate::{RamfluxClient, SdkError};
const PREFIX: &str = "own-group/pending-pins/";
#[derive(serde::Serialize, serde::Deserialize)]
struct PendingGroup {
    group_id: String,
    epoch: u64,
    pins: Vec<SdkOwnDeviceGroupMemberPin>,
}
fn group_record(group: &str) -> String {
    format!(
        "{PREFIX}{}",
        ramflux_protocol::hash_base64url("ramflux.own_group.lazy_group.v1", group.as_bytes())
    )
}
impl RamfluxClient {
    pub(super) fn park_own_group_pin(
        &self,
        pin: &SdkOwnDeviceGroupMemberPin,
    ) -> Result<(), SdkError> {
        if pin.principal_commitment.is_none() {
            return Ok(());
        }
        let db = self.account_db()?;
        let key = group_record(&pin.group_id);
        let previous = db.load_actor_state::<PendingGroup>(&key)?;
        let old_len = previous.as_ref().map(serde_json::to_vec).transpose()?.map_or(0, |v| v.len());
        let epoch = db
            .group_snapshot_epoch(&pin.group_id)?
            .ok_or_else(|| SdkError::InboundRejected("lazy group snapshot missing".into()))?;
        let mut pending = previous.filter(|old| old.epoch == epoch).unwrap_or_else(|| {
            PendingGroup { group_id: pin.group_id.clone(), epoch, pins: Vec::new() }
        });
        let pins = &mut pending.pins;
        if let Some(old) = pins.iter().find(|old| old.device_id == pin.device_id) {
            if serde_json::to_vec(old)? != serde_json::to_vec(pin)? {
                return Err(SdkError::InboundRejected("lazy group pin conflict".into()));
            }
            return Ok(());
        }
        pins.push(pin.clone());
        let (groups, bytes) = db.actor_state_usage(PREFIX)?;
        if pins.len() > 1024
            || groups >= 4096
            || bytes
                .saturating_sub(old_len as u64)
                .saturating_add(serde_json::to_vec(&pending)?.len() as u64)
                > 2 * 1024 * 1024
        {
            return Err(SdkError::InboundPending("lazy group pin capacity".into()));
        }
        db.persist_actor_state(&key, &pending)?;
        Ok(())
    }
    pub(crate) fn pending_own_group_names_root(
        &self,
        principal: &str,
        root: &str,
        device: &str,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        for pending in db.list_actor_states::<PendingGroup>(PREFIX)? {
            if db.group_snapshot_epoch(&pending.group_id)? != Some(pending.epoch) {
                continue;
            }
            for pin in pending.pins {
                if pin.principal_id.as_deref() == Some(principal)
                    && pin.principal_commitment.as_deref() == Some(root)
                    && pin.device_id == device
                    && db.group_member_role_metadata(&pin.group_id, device)?.is_some()
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    pub(crate) fn finish_lazy_own_group_pins(
        &self,
        principal: &str,
        root: &str,
        device: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for mut pending in db.list_actor_states::<PendingGroup>(PREFIX)? {
            let key = group_record(&pending.group_id);
            if db.group_snapshot_epoch(&pending.group_id)? != Some(pending.epoch) {
                db.remove_actor_state(&key)?;
                continue;
            }
            let mut retained = Vec::new();
            let mut changed = false;
            db.write_transaction(|| {
                for pin in &pending.pins {
                    if pin.principal_id.as_deref() != Some(principal)
                        || pin.principal_commitment.as_deref() != Some(root)
                        || pin.device_id != device
                    {
                        retained.push(pin.clone());
                        continue;
                    }
                    if db.group_member_role_metadata(&pin.group_id, device)?.is_some() {
                        let identity = self.device_identity_for_root(root, device)?;
                        let record = self.trusted_device(&identity)?;
                        if record["signing_public_key"] != pin.signing_public_key {
                            return Err(SdkError::InboundRejected(
                                "lazy group pin differs from verified root".into(),
                            ));
                        }
                        self.restore_own_member_pin(pin)?;
                    }
                    changed = true;
                }
                if changed {
                    if retained.is_empty() {
                        db.remove_actor_state(&key)?;
                    } else {
                        pending.pins = std::mem::take(&mut retained);
                        db.persist_actor_state(&key, &pending)?;
                    }
                }
                Ok::<(), SdkError>(())
            })?;
        }
        Ok(())
    }
}
