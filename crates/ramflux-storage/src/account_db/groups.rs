#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::group_permissions::{
    can_mute_group_member, can_remove_group_member, is_group_admin_role, validate_group_role,
};
use rusqlite::OptionalExtension;
use std::collections::BTreeSet;

impl AccountDb {
    pub fn create_group(
        &self,
        group_id: &str,
        creator_id: &str,
    ) -> Result<GroupState, StorageError> {
        let now = self.now_unix();
        self.connection.execute(
            "INSERT OR REPLACE INTO group_projection
                (group_id, group_epoch, max_members, new_member_history, created_at, updated_at)
             VALUES (?1, 1, 1000, 'no_history', ?2, ?2)",
            params![group_id, now],
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_member_projection
                (group_id, member_principal_id, member_id, role, joined_epoch, active, updated_at)
             VALUES (?1, ?2, ?2, 'owner', 1, 1, ?3)",
            params![group_id, creator_id, now],
        )?;
        self.group_state(group_id)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn add_group_member(
        &self,
        group_id: &str,
        member_id: &str,
        role: &str,
    ) -> Result<GroupState, StorageError> {
        validate_group_role(role)?;
        let state = self.group_state(group_id)?;
        let max_members = match usize::try_from(state.max_members) {
            Ok(value) => value,
            Err(_err) => return Err(StorageError::GroupMemberLimitExceeded),
        };
        if state.members.len() >= max_members {
            return Err(StorageError::GroupMemberLimitExceeded);
        }
        let new_epoch = state.group_epoch + 1;
        self.connection.execute(
            "UPDATE group_projection SET group_epoch = ?2 WHERE group_id = ?1",
            params![group_id, new_epoch],
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_member_projection
                (group_id, member_principal_id, member_id, role, joined_epoch, active, updated_at)
             VALUES (?1, ?2, ?2, ?3, ?4, 1, ?5)",
            params![group_id, member_id, role, new_epoch, self.now_unix()],
        )?;
        self.group_state(group_id)
    }

    /// # Errors
    /// Returns an error when role permissions or storage operations fail.
    pub fn remove_group_member(
        &self,
        group_id: &str,
        actor_id: &str,
        target_member_id: &str,
    ) -> Result<GroupState, StorageError> {
        let actor_role = self
            .group_member_role(group_id, actor_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let target_role = self
            .group_member_role(group_id, target_member_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        if !can_remove_group_member(&actor_role, &target_role) {
            return Err(StorageError::GroupPermissionDenied);
        }
        let state = self.group_state(group_id)?;
        let new_epoch = state.group_epoch + 1;
        self.connection.execute(
            "UPDATE group_projection SET group_epoch = ?2 WHERE group_id = ?1",
            params![group_id, new_epoch],
        )?;
        self.connection.execute(
            "UPDATE group_member_projection
                SET active = 0,
                    removed_epoch = ?3,
                    updated_at = ?4
              WHERE group_id = ?1 AND member_id = ?2",
            params![group_id, target_member_id, new_epoch, self.now_unix()],
        )?;
        self.group_state(group_id)
    }

    /// # Errors
    /// Returns an error when the group role lookup fails or the actor cannot send.
    pub fn ensure_group_member_can_send(
        &self,
        group_id: &str,
        actor_id: &str,
        announcement_only: bool,
    ) -> Result<(), StorageError> {
        let actor_role = self
            .group_member_role(group_id, actor_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        if announcement_only && !is_group_admin_role(&actor_role) {
            return Err(StorageError::GroupPermissionDenied);
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when the group role lookup fails or the actor cannot mute.
    pub fn ensure_group_member_can_mute(
        &self,
        group_id: &str,
        actor_id: &str,
        target_member_id: &str,
    ) -> Result<(), StorageError> {
        let actor_role = self
            .group_member_role(group_id, actor_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let target_role = self
            .group_member_role(group_id, target_member_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        if !can_mute_group_member(&actor_role, &target_role) {
            return Err(StorageError::GroupPermissionDenied);
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when storage lookup fails.
    pub fn group_member_role(
        &self,
        group_id: &str,
        member_id: &str,
    ) -> Result<Option<String>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT role
                   FROM group_member_projection
                  WHERE group_id = ?1 AND member_id = ?2 AND active = 1",
                params![group_id, member_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn group_state(&self, group_id: &str) -> Result<GroupState, StorageError> {
        let (group_epoch, max_members, new_member_history) = self.connection.query_row(
            "SELECT group_epoch, max_members, new_member_history
               FROM group_projection
              WHERE group_id = ?1",
            params![group_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let mut statement = self.connection.prepare(
            "SELECT member_id, role
               FROM group_member_projection
              WHERE group_id = ?1 AND active = 1
              ORDER BY member_id ASC",
        )?;
        let rows = statement.query_map(params![group_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut members = BTreeSet::new();
        let mut roles = BTreeMap::new();
        for row in rows {
            let (member_id, role) = row?;
            members.insert(member_id.clone());
            roles.insert(member_id, role);
        }
        Ok(GroupState {
            group_id: group_id.to_owned(),
            group_epoch,
            max_members,
            new_member_history,
            members,
            roles,
        })
    }

    /// # Errors
    /// Returns an error when storage lookup fails.
    pub fn groups(&self) -> Result<Vec<GroupState>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT group_id
               FROM group_projection
              ORDER BY created_at ASC, group_id ASC",
        )?;
        let group_ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        group_ids.into_iter().map(|group_id| self.group_state(&group_id)).collect()
    }
}
