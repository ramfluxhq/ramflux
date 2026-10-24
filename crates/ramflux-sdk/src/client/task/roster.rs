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
    pub(crate) fn record_verified_task_roster(&self, state: &GroupState) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let key = scoped("verified_roster", &state.group_id, &state.group_epoch.to_string())?;
        let members = state.members.clone();
        if let Some(old) = db.load_actor_state::<Roster>(&key)? {
            if old.members != members {
                return Err(invalid("locally validated group epoch roster differs"));
            }
        } else {
            db.persist_actor_state(&key, &Roster { members })?;
            db.prune_task_diagnostics("task/verified_roster/", 256)?;
        }
        Ok(())
    }
    pub(super) fn check_verified_task_roster(
        &self,
        c: &Carrier,
        group: &str,
        epoch: u64,
        assignee: &str,
    ) -> Result<(), SdkError> {
        let Some(roster) = self.account_db()?.load_actor_state::<Roster>(&scoped(
            "verified_roster",
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
                .account_db()?
                .client_record("device", device)?
                .is_some_and(|r| r["principal_id"] == assignee)
            {
                return Ok(());
            }
        }
        Err(invalid("historical task assignee absent from locally validated roster"))
    }
}
