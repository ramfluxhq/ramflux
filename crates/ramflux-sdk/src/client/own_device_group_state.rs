// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native signed group-state admission from authenticated same-root controls.
use crate::own_device_sync::SdkOwnDeviceGroupSnapshot;
use crate::prelude::*;

impl RamfluxClient {
    pub(super) fn restore_own_shared_group(
        &self,
        group: &SdkOwnDeviceGroupSnapshot,
        snapshot: &ramflux_protocol::group_state::GroupStateSnapshot,
    ) -> Result<Option<u64>, SdkError> {
        let state = ramflux_crypto::verify_group_state_snapshot(snapshot.clone())?;
        if state.view().group_id != group.group_id || state.view().epoch != group.group_epoch {
            return Err(SdkError::InboundRejected("own group state header mismatch".into()));
        }
        let local = self.owned_device_identity()?;
        let db = self.account_db()?;
        if db.group_snapshot_epoch(&group.group_id)?.is_some_and(|epoch| epoch > state.view().epoch)
        {
            return Ok(None);
        }
        let target = db
            .client_record("device", local.storage_key())?
            .and_then(|record| record["target_delivery_id"].as_str().map(str::to_owned))
            .ok_or_else(|| SdkError::InboundPending("own group local target missing".into()))?;
        // The enclosing history is authenticated to this owned account root. A removal fence
        // may be restored without first granting this device the membership it removes.
        db.commit_shared_group_state(&state, &self.owned_group_actor(&target)?)?;
        self.observe_native_task_roster(&state)?;
        if state.view().effective_role(local.root_commitment(), local.device_id()).is_none() {
            return Ok(None);
        }
        Ok(db.group_member_joined_epoch(&group.group_id, &local)?)
    }
}
