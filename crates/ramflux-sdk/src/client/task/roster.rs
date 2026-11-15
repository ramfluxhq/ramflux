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
    native: NativeRoster,
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
struct NativeRoster {
    roots: std::collections::BTreeMap<String, String>,
    excluded: std::collections::BTreeSet<(String, String)>,
}
impl RamfluxClient {
    pub(crate) fn observe_native_task_roster(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
    ) -> Result<(), SdkError> {
        if state.snapshot().issuer.native_authority.is_none() {
            return Err(invalid("task roster requires native signed group authority"));
        }
        let view = state.view();
        let native = NativeRoster {
            roots: view
                .members
                .iter()
                .map(|member| {
                    (member.identity.root_commitment.clone(), member.identity.principal_id.clone())
                })
                .collect(),
            excluded: view
                .excluded
                .iter()
                .map(|entry| (entry.root_commitment.clone(), entry.device_id.clone()))
                .collect(),
        };
        let members = view.members.iter().map(|member| member.identity.device_id.clone()).collect();
        let key = scoped("verified_roster_v2", &view.group_id, &view.epoch.to_string())?;
        let db = self.account_db()?;
        if let Some(old) = db.load_actor_state::<Roster>(&key)? {
            if old.native != native {
                return Err(invalid("native task roster conflicts at a validated group epoch"));
            }
        } else {
            db.persist_actor_state(&key, &Roster { members, native })?;
            db.prune_task_diagnostics("task/verified_roster_v2/", 256)?;
        }
        Ok(())
    }

    fn check_native_task_roster(
        &self,
        roster: &NativeRoster,
        carrier: &Carrier,
        assignee: &str,
    ) -> Result<(), SdkError> {
        let actor = self.peer_device_identity(&carrier.principal_id, &carrier.device_id)?;
        if roster.roots.get(actor.root_commitment()).map(String::as_str)
            != Some(carrier.principal_id.as_str())
            || roster.excluded.contains(&(actor.root_commitment().into(), actor.device_id().into()))
        {
            return Err(invalid("historical task actor absent from validated native group epoch"));
        }
        let root =
            if self.device_branch.as_ref().is_some_and(|branch| branch.principal_id == assignee) {
                self.own_account_anchor()?
            } else {
                self.account_db()?
                    .client_record("identity", assignee)?
                    .and_then(|row| row["contact_identity_commitment"].as_str().map(str::to_owned))
                    .ok_or_else(|| invalid("historical task assignee root missing"))?
            };
        if roster.roots.get(&root).map(String::as_str) != Some(assignee) {
            return Err(invalid(
                "historical task assignee absent from validated native group epoch",
            ));
        }
        Ok(())
    }

    pub(super) fn task_current_roster(
        &self,
        state: &GroupState,
    ) -> Result<std::collections::BTreeSet<String>, SdkError> {
        let roster = self
            .account_db()?
            .load_actor_state::<Roster>(&scoped(
                "verified_roster_v2",
                &state.group_id,
                &state.group_epoch.to_string(),
            )?)?
            .ok_or_else(|| invalid("task group epoch lacks a verified native roster"))?;
        Ok(roster.members)
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
        self.check_native_task_roster(&roster.native, c, assignee)
    }
}
