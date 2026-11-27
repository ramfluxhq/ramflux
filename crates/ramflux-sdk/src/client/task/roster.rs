// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Locally validated group epochs take precedence over same-root membership claims.
use super::{invalid, scoped};
use crate::{RamfluxClient, SdkError};
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
}
