// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded no-role tombstones keep unrelated conversation traffic out of peer holdback.
use super::{carrier::Carrier, scoped};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::TaskEventBody;
use serde_json::{Value, json};
impl RamfluxClient {
    pub(super) fn remember_task_no_role(&self, c: &Carrier) -> Result<(), SdkError> {
        if !matches!(c.event()?.event(), TaskEventBody::Start(_)) {
            return Ok(());
        }
        let db = self.account_db()?;
        let key = scoped(
            "no_role",
            &c.conversation_id,
            &serde_json::to_string(&(c.event()?.event().task_id(), &c.principal_id))?,
        )?;
        if db.load_actor_state::<Value>(&key)?.is_none() {
            db.persist_actor_state(
                &key,
                &json!({"source":c.principal_id,"at":crate::time::now_unix_timestamp()}),
            )?;
        }
        db.prune_task_no_role(crate::time::now_unix_timestamp())?;
        Ok(())
    }
    pub(super) fn task_has_no_local_role(&self, c: &Carrier) -> Result<bool, SdkError> {
        if self
            .task_history(&c.conversation_id, c.event()?.event().task_id())?
            .state()?
            .task()
            .is_some()
        {
            return Ok(false);
        }
        Ok(self
            .account_db()?
            .load_actor_state::<Value>(&scoped(
                "no_role",
                &c.conversation_id,
                &serde_json::to_string(&(c.event()?.event().task_id(), &c.principal_id))?,
            )?)?
            .is_some_and(|v| {
                v["at"].as_i64().is_some_and(|at| {
                    crate::time::now_unix_timestamp().saturating_sub(at) < 7 * 86400
                })
            }))
    }
}
