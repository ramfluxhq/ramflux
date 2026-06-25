// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn create_group(&self, group_id: &str, creator_id: &str) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.create_group(group_id, creator_id)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the member cannot be added.
    pub fn add_group_member(
        &self,
        group_id: &str,
        member_id: &str,
        role: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.add_group_member(group_id, member_id, role)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the member cannot be removed.
    pub fn remove_group_member(
        &self,
        group_id: &str,
        actor_id: &str,
        target_member_id: &str,
    ) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.remove_group_member(group_id, actor_id, target_member_id)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or group state cannot be read.
    pub fn group_state(&self, group_id: &str) -> Result<GroupState, SdkError> {
        Ok(self.account_db()?.group_state(group_id)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or groups cannot be read.
    pub fn groups(&self) -> Result<Vec<GroupState>, SdkError> {
        Ok(self.account_db()?.groups()?)
    }

    /// # Errors
    /// Returns an error when the account DB is locked or the route cannot be persisted.
    pub fn persist_group_member_route(
        &self,
        group_id: &str,
        route: &LocalBusGroupMemberRoute,
    ) -> Result<(), SdkError> {
        let event_id = group_member_route_event_id(group_id, &route.member_id);
        if self.event_body(&event_id)?.is_some() {
            return Ok(());
        }
        self.append_event(&event_id, "group.member.route", &serde_json::to_vec(route)?)
    }

    /// # Errors
    /// Returns an error when group state or a stored member route cannot be read.
    pub fn group_member_routes(
        &self,
        group_id: &str,
    ) -> Result<Vec<LocalBusGroupMemberRoute>, SdkError> {
        let group = self.group_state(group_id)?;
        let mut routes = Vec::new();
        for member_id in group.members {
            let event_id = group_member_route_event_id(group_id, &member_id);
            if let Some(bytes) = self.event_body(&event_id)? {
                routes.push(serde_json::from_slice(&bytes)?);
            }
        }
        Ok(routes)
    }
}
