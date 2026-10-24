// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Locally validated group epochs take precedence over same-root membership claims.
use super::{carrier::Carrier, invalid, scoped};
use crate::{RamfluxClient, SdkError};
use ramflux_storage::GroupState;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
struct Roster {
    members: std::collections::BTreeSet<String>,
}
impl RamfluxClient {
    pub(crate) fn observe_verified_task_roster(
        &self,
        event: &ramflux_protocol::GroupEvent,
        state: &GroupState,
    ) {
        if let Err(error) = self.store_verified_task_roster(event, state) {
            tracing::warn!(%error,group=%state.group_id,"task roster observation deferred after verified group control");
        }
    }
    fn store_verified_task_roster(
        &self,
        event: &ramflux_protocol::GroupEvent,
        state: &GroupState,
    ) -> Result<(), SdkError> {
        use ramflux_protocol::GroupEventBody as E;
        let previous_epoch = match &event.body {
            E::RoleChanged { previous_epoch, .. }
            | E::MemberRemoved { previous_epoch, .. }
            | E::MemberBanned { previous_epoch, .. }
            | E::MemberAccepted { previous_epoch, .. }
            | E::MemberJoined { previous_epoch, .. } => Some(*previous_epoch),
            _ => return Ok(()),
        };
        let db = self.account_db()?;
        let mut members = if let Some(epoch) = previous_epoch {
            db.load_actor_state::<Roster>(&scoped(
                "verified_roster_v2",
                &state.group_id,
                &epoch.to_string(),
            )?)?
            .map_or_else(|| state.members.clone(), |r| r.members)
        } else {
            state.members.clone()
        };
        match &event.body {
            E::MemberRemoved { removed_identity, .. } => {
                members.remove(removed_identity);
            }
            E::MemberBanned { banned_identity, .. } => {
                members.remove(banned_identity);
            }
            E::MemberAccepted { invitee_identity, .. } => {
                members.insert(invitee_identity.clone());
            }
            E::MemberJoined { joined_identity, .. } => {
                members.insert(joined_identity.clone());
            }
            _ => {}
        }
        let key = scoped("verified_roster_v2", &state.group_id, &state.group_epoch.to_string())?;
        if let Some(old) = db.load_actor_state::<Roster>(&key)? {
            if old.members != members {
                tracing::warn!(group=%state.group_id,epoch=state.group_epoch,"verified task roster retained over conflicting snapshot");
            }
        } else {
            db.persist_actor_state(&key, &Roster { members })?;
            db.prune_task_diagnostics("task/verified_roster_v2/", 256)?;
        }
        Ok(())
    }
    pub(super) fn task_current_roster(
        &self,
        state: &GroupState,
    ) -> std::collections::BTreeSet<String> {
        let result = (|| -> Result<Option<Roster>, SdkError> {
            Ok(self.account_db()?.load_actor_state(&scoped(
                "verified_roster_v2",
                &state.group_id,
                &state.group_epoch.to_string(),
            )?)?)
        })();
        match result {
            Ok(Some(roster)) => {
                if roster.members != state.members {
                    tracing::warn!(group=%state.group_id,epoch=state.group_epoch,"task uses verified roster over snapshot membership");
                }
                roster.members
            }
            Ok(None) => state.members.clone(),
            Err(error) => {
                tracing::warn!(%error,"task roster cache unavailable");
                state.members.clone()
            }
        }
    }
    pub(super) fn check_verified_task_roster(
        &self,
        c: &Carrier,
        group: &str,
        epoch: u64,
        assignee: &str,
    ) -> Result<(), SdkError> {
        let Some(roster) = self.account_db()?.load_actor_state::<Roster>(&scoped(
            "verified_roster_v2",
            group,
            &epoch.to_string(),
        )?)?
        else {
            return Ok(());
        };
        if !roster.members.contains(&c.device_id) {
            return Err(invalid("historical task actor absent from locally validated roster"));
        }
        for device in &roster.members {
            if self
                .device_branch
                .as_ref()
                .is_some_and(|d| d.device_id == *device && d.principal_id == assignee)
            {
                return Ok(());
            }
            if self
                .peer_device_identity(assignee, device)
                .ok()
                .and_then(|identity| {
                    self.account_db().ok()?.client_device_record(&identity).ok().flatten()
                })
                .is_some_and(|r| r["principal_id"] == assignee)
            {
                return Ok(());
            }
        }
        Err(invalid("historical task assignee absent from locally validated roster"))
    }
}
