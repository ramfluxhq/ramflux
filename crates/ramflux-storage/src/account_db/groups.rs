// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::group_permissions::{
    can_change_group_member_role, can_delete_group_message, can_invite_group_member,
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
        if self.group_member_banned(group_id, member_id)? {
            return Err(StorageError::GroupPermissionDenied);
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
    /// Returns an error when the signed direct-add onboarding event is unauthorized, replayed, or
    /// cannot be applied to the local projection.
    pub fn apply_group_member_join(
        &self,
        join: &GroupMemberJoinWrite,
    ) -> Result<GroupState, StorageError> {
        validate_group_role(&join.joined_role)?;
        validate_group_role(&join.actor_role)?;
        self.ensure_group_control_not_seen(&join.group_id, &join.event_id)?;
        if !is_group_admin_role(&join.actor_role) {
            return Err(StorageError::GroupPermissionDenied);
        }
        if join.new_group_epoch != join.previous_epoch.saturating_add(1) {
            return Err(StorageError::GroupControlEpochMismatch {
                expected: join.previous_epoch.saturating_add(1),
                actual: join.new_group_epoch,
            });
        }
        if self.group_member_banned(&join.group_id, &join.joined_identity)? {
            return Err(StorageError::GroupPermissionDenied);
        }
        let applied_at = self.now_unix();
        self.insert_group_control_seen(
            &join.group_id,
            &join.event_id,
            "member_joined",
            &join.actor_device_id,
            &join.joined_identity,
            join.previous_epoch,
            join.new_group_epoch,
            applied_at,
        )?;
        self.connection.execute(
            "INSERT INTO group_projection
                (group_id, group_epoch, max_members, new_member_history, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(group_id)
             DO UPDATE SET
                group_epoch = MAX(group_epoch, excluded.group_epoch),
                max_members = excluded.max_members,
                new_member_history = excluded.new_member_history,
                updated_at = excluded.updated_at",
            params![
                join.group_id,
                i64::try_from(join.new_group_epoch)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?,
                join.max_members,
                join.new_member_history,
                applied_at
            ],
        )?;
        self.persist_group_member_device_key(
            &join.group_id,
            &join.actor_device_id,
            &join.actor_device_signing_public_key,
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_member_projection
                (group_id, member_principal_id, member_id, role, joined_epoch, active, updated_at)
             VALUES (?1, ?2, ?2, ?3, ?4, 1, ?5)",
            params![
                join.group_id,
                join.actor_device_id,
                join.actor_role,
                i64::try_from(join.previous_epoch)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?,
                applied_at
            ],
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_member_projection
                (group_id, member_principal_id, member_id, role, joined_epoch, active, updated_at)
             VALUES (?1, ?2, ?2, ?3, ?4, 1, ?5)",
            params![
                join.group_id,
                join.joined_identity,
                join.joined_role,
                i64::try_from(join.new_group_epoch)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?,
                applied_at
            ],
        )?;
        self.group_state(&join.group_id)
    }

    /// # Errors
    /// Returns an error when validation or storage updates fail.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_group_local_membership_snapshot(
        &self,
        group_id: &str,
        group_epoch: u64,
        max_members: u32,
        new_member_history: &str,
        local_member_id: &str,
        local_role: &str,
        joined_epoch: u64,
    ) -> Result<GroupState, StorageError> {
        validate_group_role(local_role)?;
        let now = self.now_unix();
        let group_epoch_i64 = i64::try_from(group_epoch)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let joined_epoch_i64 = i64::try_from(joined_epoch)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        self.connection.execute(
            "INSERT INTO group_projection
                (group_id, group_epoch, max_members, new_member_history, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(group_id)
             DO UPDATE SET
                group_epoch = MAX(group_epoch, excluded.group_epoch),
                max_members = excluded.max_members,
                new_member_history = excluded.new_member_history,
                updated_at = excluded.updated_at",
            params![group_id, group_epoch_i64, max_members, new_member_history, now],
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_member_projection
                (group_id, member_principal_id, member_id, role, joined_epoch, active, updated_at)
             VALUES (?1, ?2, ?2, ?3, ?4, 1, ?5)",
            params![group_id, local_member_id, local_role, joined_epoch_i64, now],
        )?;
        self.group_state(group_id)
    }

    /// # Errors
    /// Returns an error when validation or storage updates fail.
    pub fn upsert_group_member_snapshot(
        &self,
        group_id: &str,
        member_id: &str,
        role: &str,
        joined_epoch: u64,
    ) -> Result<(), StorageError> {
        validate_group_role(role)?;
        let joined_epoch_i64 = i64::try_from(joined_epoch)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_member_projection
                (group_id, member_principal_id, member_id, role, joined_epoch, active, updated_at)
             VALUES (?1, ?2, ?2, ?3, ?4, 1, ?5)",
            params![group_id, member_id, role, joined_epoch_i64, self.now_unix()],
        )?;
        Ok(())
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
    /// Returns an error when the trusted device key cannot be persisted.
    pub fn persist_group_member_device_key(
        &self,
        group_id: &str,
        member_id: &str,
        device_signing_public_key: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT OR REPLACE INTO group_member_device_key
                (group_id, member_id, device_signing_public_key, verified_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![group_id, member_id, device_signing_public_key, self.now_unix()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the trusted device key lookup fails.
    pub fn group_member_device_key(
        &self,
        group_id: &str,
        member_id: &str,
    ) -> Result<Option<String>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT device_signing_public_key
                   FROM group_member_device_key
                  WHERE group_id = ?1 AND member_id = ?2",
                params![group_id, member_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// # Errors
    /// Returns an error when the role change is unauthorized, replayed, or cannot be applied.
    pub fn apply_group_role_change(
        &self,
        change: &GroupRoleChangeWrite,
    ) -> Result<GroupState, StorageError> {
        validate_group_role(&change.new_role)?;
        self.ensure_group_control_not_seen(&change.group_id, &change.event_id)?;
        let state = self.group_state(&change.group_id)?;
        if state.group_epoch != change.previous_epoch {
            return Err(StorageError::GroupControlEpochMismatch {
                expected: state.group_epoch,
                actual: change.previous_epoch,
            });
        }
        if change.new_group_epoch != change.previous_epoch.saturating_add(1) {
            return Err(StorageError::GroupControlEpochMismatch {
                expected: change.previous_epoch.saturating_add(1),
                actual: change.new_group_epoch,
            });
        }
        let actor_role = self
            .group_member_role(&change.group_id, &change.actor_device_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let target_role = self
            .group_member_role(&change.group_id, &change.target_member_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        if !can_change_group_member_role(&actor_role, &target_role, &change.new_role) {
            return Err(StorageError::GroupPermissionDenied);
        }
        let applied_at = self.now_unix();
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO group_control_event_seen
                (group_id, event_id, event_kind, actor_device_id, target_member_id,
                 previous_epoch, new_group_epoch, applied_at)
             VALUES (?1, ?2, 'role_changed', ?3, ?4, ?5, ?6, ?7)",
            params![
                change.group_id,
                change.event_id,
                change.actor_device_id,
                change.target_member_id,
                change.previous_epoch,
                change.new_group_epoch,
                applied_at
            ],
        )?;
        if inserted == 0 {
            return Err(StorageError::GroupControlReplay(change.event_id.clone()));
        }
        self.connection.execute(
            "UPDATE group_projection SET group_epoch = ?2, updated_at = ?3 WHERE group_id = ?1",
            params![change.group_id, change.new_group_epoch, applied_at],
        )?;
        self.connection.execute(
            "UPDATE group_member_projection
                SET role = ?3, updated_at = ?4
              WHERE group_id = ?1 AND member_id = ?2 AND active = 1",
            params![change.group_id, change.target_member_id, change.new_role, applied_at],
        )?;
        self.group_state(&change.group_id)
    }

    /// # Errors
    /// Returns an error when the kick is unauthorized, replayed, or cannot be applied.
    pub fn apply_group_member_kick(
        &self,
        kick: &GroupMemberKickWrite,
    ) -> Result<GroupState, StorageError> {
        self.apply_group_member_removal_control(
            "member_kicked",
            &kick.group_id,
            &kick.event_id,
            &kick.actor_device_id,
            &kick.target_member_id,
            kick.previous_epoch,
            kick.new_group_epoch,
            None,
        )
    }

    /// # Errors
    /// Returns an error when the ban is unauthorized, replayed, or cannot be applied.
    pub fn apply_group_member_ban(
        &self,
        ban: &GroupMemberBanWrite,
    ) -> Result<GroupState, StorageError> {
        self.apply_group_member_removal_control(
            "member_banned",
            &ban.group_id,
            &ban.event_id,
            &ban.actor_device_id,
            &ban.target_member_id,
            ban.previous_epoch,
            ban.new_group_epoch,
            Some((&ban.ban_id, &ban.reason)),
        )
    }

    /// # Errors
    /// Returns an error when the delete is unauthorized, replayed, or cannot be applied.
    pub fn apply_group_message_delete(
        &self,
        delete: &GroupMessageDeleteWrite,
    ) -> Result<GroupState, StorageError> {
        self.ensure_group_control_not_seen(&delete.group_id, &delete.event_id)?;
        let state = self.group_state(&delete.group_id)?;
        if state.group_epoch != delete.group_epoch {
            return Err(StorageError::GroupControlEpochMismatch {
                expected: state.group_epoch,
                actual: delete.group_epoch,
            });
        }
        let actor_role = self
            .group_member_role(&delete.group_id, &delete.actor_device_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let author_id: String = self.connection.query_row(
            "SELECT sender_id
               FROM direct_message_projection
              WHERE conversation_id = ?1 AND message_id = ?2",
            params![delete.group_id, delete.target_message_id],
            |row| row.get(0),
        )?;
        let author_role = self
            .group_member_role(&delete.group_id, &author_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        if !can_delete_group_message(&actor_role, &author_role, delete.actor_device_id == author_id)
        {
            return Err(StorageError::GroupPermissionDenied);
        }
        let applied_at = self.now_unix();
        self.insert_group_control_seen(
            &delete.group_id,
            &delete.event_id,
            "message_deleted",
            &delete.actor_device_id,
            &delete.target_message_id,
            delete.group_epoch,
            delete.group_epoch,
            applied_at,
        )?;
        self.connection.execute(
            "UPDATE direct_message_projection
                SET deleted = 1, encrypted_body = x''
              WHERE conversation_id = ?1 AND message_id = ?2 AND deleted = 0",
            params![delete.group_id, delete.target_message_id],
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_message_tombstone_projection
                (group_id, message_id, tombstone_id, actor_device_id, delete_scope,
                 deleted_epoch, reason, deleted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                delete.group_id,
                delete.target_message_id,
                delete.tombstone_id,
                delete.actor_device_id,
                delete.delete_scope,
                delete.group_epoch,
                delete.reason,
                applied_at
            ],
        )?;
        self.group_state(&delete.group_id)
    }

    /// # Errors
    /// Returns an error when the invite is unauthorized, replayed, or cannot be applied.
    pub fn apply_group_member_invite(
        &self,
        invite: &GroupInviteWrite,
    ) -> Result<GroupState, StorageError> {
        validate_group_role(&invite.invited_role)?;
        self.ensure_group_control_not_seen(&invite.group_id, &invite.event_id)?;
        let state = self.group_state(&invite.group_id)?;
        if state.group_epoch > invite.group_epoch
            || (state.group_epoch < invite.group_epoch
                && self.group_member_role(&invite.group_id, &invite.invitee_identity)?.is_some())
        {
            return Err(StorageError::GroupControlEpochMismatch {
                expected: state.group_epoch,
                actual: invite.group_epoch,
            });
        }
        let actor_role = self
            .group_member_role(&invite.group_id, &invite.actor_device_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        if !can_invite_group_member(&actor_role, &invite.invited_role) {
            return Err(StorageError::GroupPermissionDenied);
        }
        if self.group_member_banned(&invite.group_id, &invite.invitee_identity)? {
            return Err(StorageError::GroupPermissionDenied);
        }
        let applied_at = self.now_unix();
        if state.group_epoch < invite.group_epoch {
            self.connection.execute(
                "UPDATE group_projection SET group_epoch = ?2, updated_at = ?3 WHERE group_id = ?1",
                params![invite.group_id, invite.group_epoch, applied_at],
            )?;
        }
        self.insert_group_control_seen(
            &invite.group_id,
            &invite.event_id,
            "member_invited",
            &invite.actor_device_id,
            &invite.invitee_identity,
            invite.group_epoch,
            invite.group_epoch,
            applied_at,
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_invite_projection
                (group_id, invite_id, invitee_identity, invitee_signing_public_key,
                 invited_role, inviter_device_id, invite_epoch, expires_at, state,
                 reason, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10, ?10)",
            params![
                invite.group_id,
                invite.invite_id,
                invite.invitee_identity,
                invite.invitee_signing_public_key,
                invite.invited_role,
                invite.actor_device_id,
                invite.group_epoch,
                invite.expires_at,
                invite.reason,
                applied_at
            ],
        )?;
        self.group_state(&invite.group_id)
    }

    /// # Errors
    /// Returns an error when the accept is unauthorized, replayed, expired, or cannot be applied.
    pub fn apply_group_member_accept(
        &self,
        accept: &GroupInviteAcceptWrite,
    ) -> Result<GroupState, StorageError> {
        validate_group_role(&accept.accepted_role)?;
        self.ensure_group_control_not_seen(&accept.group_id, &accept.event_id)?;
        let invite = self.group_invite(&accept.group_id, &accept.invite_id)?;
        if invite.state != "pending" {
            return Err(StorageError::GroupInviteInvalidState {
                invite_id: accept.invite_id.clone(),
                expected: "pending".to_owned(),
                actual: invite.state,
            });
        }
        if accept.now > invite.expires_at {
            return Err(StorageError::GroupInviteExpired(accept.invite_id.clone()));
        }
        if accept.invitee_identity != invite.invitee_identity
            || accept.actor_device_id != invite.invitee_identity
        {
            return Err(StorageError::GroupInviteAcceptorMismatch(accept.invite_id.clone()));
        }
        if accept.accepted_role != invite.invited_role {
            return Err(StorageError::GroupPermissionDenied);
        }
        if self.group_member_banned(&accept.group_id, &accept.invitee_identity)? {
            return Err(StorageError::GroupPermissionDenied);
        }
        let state = self.group_state(&accept.group_id)?;
        if state.group_epoch != accept.previous_epoch {
            return Err(StorageError::GroupControlEpochMismatch {
                expected: state.group_epoch,
                actual: accept.previous_epoch,
            });
        }
        if accept.new_group_epoch != accept.previous_epoch.saturating_add(1) {
            return Err(StorageError::GroupControlEpochMismatch {
                expected: accept.previous_epoch.saturating_add(1),
                actual: accept.new_group_epoch,
            });
        }
        let max_members = usize::try_from(state.max_members)
            .map_err(|_err| StorageError::GroupMemberLimitExceeded)?;
        if state.members.len() >= max_members {
            return Err(StorageError::GroupMemberLimitExceeded);
        }
        let applied_at = self.now_unix();
        self.insert_group_control_seen(
            &accept.group_id,
            &accept.event_id,
            "member_accepted",
            &accept.actor_device_id,
            &accept.invitee_identity,
            accept.previous_epoch,
            accept.new_group_epoch,
            applied_at,
        )?;
        self.connection.execute(
            "UPDATE group_projection SET group_epoch = ?2, updated_at = ?3 WHERE group_id = ?1",
            params![accept.group_id, accept.new_group_epoch, applied_at],
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_member_projection
                (group_id, member_principal_id, member_id, role, joined_epoch, active, updated_at)
             VALUES (?1, ?2, ?2, ?3, ?4, 1, ?5)",
            params![
                accept.group_id,
                accept.invitee_identity,
                accept.accepted_role,
                accept.new_group_epoch,
                applied_at
            ],
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_member_device_key
                (group_id, member_id, device_signing_public_key, verified_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                accept.group_id,
                invite.invitee_identity,
                invite.invitee_signing_public_key,
                applied_at
            ],
        )?;
        self.connection.execute(
            "UPDATE group_invite_projection
                SET state = 'accepted', updated_at = ?3
              WHERE group_id = ?1 AND invite_id = ?2 AND state = 'pending'",
            params![accept.group_id, accept.invite_id, applied_at],
        )?;
        self.group_state(&accept.group_id)
    }

    /// # Errors
    /// Returns an error when invite lookup fails or the invite does not exist.
    pub fn group_invite(
        &self,
        group_id: &str,
        invite_id: &str,
    ) -> Result<GroupInviteRecord, StorageError> {
        self.connection
            .query_row(
                "SELECT group_id, invite_id, invitee_identity, invitee_signing_public_key,
                        invited_role, inviter_device_id, invite_epoch, expires_at, state
                   FROM group_invite_projection
                  WHERE group_id = ?1 AND invite_id = ?2",
                params![group_id, invite_id],
                |row| {
                    Ok(GroupInviteRecord {
                        group_id: row.get(0)?,
                        invite_id: row.get(1)?,
                        invitee_identity: row.get(2)?,
                        invitee_signing_public_key: row.get(3)?,
                        invited_role: row.get(4)?,
                        inviter_device_id: row.get(5)?,
                        invite_epoch: row.get(6)?,
                        expires_at: row.get(7)?,
                        state: row.get(8)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::GroupInviteMissing(invite_id.to_owned()))
    }

    /// # Errors
    /// Returns an error when the ban lookup fails.
    pub fn group_member_banned(
        &self,
        group_id: &str,
        member_id: &str,
    ) -> Result<bool, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT 1
                   FROM group_ban_projection
                  WHERE group_id = ?1 AND member_id = ?2 AND active = 1",
                params![group_id, member_id],
                |_row| Ok(()),
            )
            .optional()?
            .is_some())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_group_member_removal_control(
        &self,
        event_kind: &str,
        group_id: &str,
        event_id: &str,
        actor_device_id: &str,
        target_member_id: &str,
        previous_epoch: u64,
        new_group_epoch: u64,
        ban: Option<(&str, &str)>,
    ) -> Result<GroupState, StorageError> {
        self.ensure_group_control_not_seen(group_id, event_id)?;
        let state = self.group_state(group_id)?;
        if state.group_epoch != previous_epoch {
            return Err(StorageError::GroupControlEpochMismatch {
                expected: state.group_epoch,
                actual: previous_epoch,
            });
        }
        if new_group_epoch != previous_epoch.saturating_add(1) {
            return Err(StorageError::GroupControlEpochMismatch {
                expected: previous_epoch.saturating_add(1),
                actual: new_group_epoch,
            });
        }
        let actor_role = self
            .group_member_role(group_id, actor_device_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        let target_role = self
            .group_member_role(group_id, target_member_id)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        if !can_remove_group_member(&actor_role, &target_role) {
            return Err(StorageError::GroupPermissionDenied);
        }
        let applied_at = self.now_unix();
        self.insert_group_control_seen(
            group_id,
            event_id,
            event_kind,
            actor_device_id,
            target_member_id,
            previous_epoch,
            new_group_epoch,
            applied_at,
        )?;
        self.connection.execute(
            "UPDATE group_projection SET group_epoch = ?2, updated_at = ?3 WHERE group_id = ?1",
            params![group_id, new_group_epoch, applied_at],
        )?;
        self.connection.execute(
            "UPDATE group_member_projection
                SET active = 0,
                    removed_epoch = ?3,
                    updated_at = ?4
              WHERE group_id = ?1 AND member_id = ?2",
            params![group_id, target_member_id, new_group_epoch, applied_at],
        )?;
        if let Some((ban_id, reason)) = ban {
            self.connection.execute(
                "INSERT OR REPLACE INTO group_ban_projection
                    (group_id, member_id, ban_id, actor_device_id, banned_epoch, reason, active, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
                params![
                    group_id,
                    target_member_id,
                    ban_id,
                    actor_device_id,
                    new_group_epoch,
                    reason,
                    applied_at
                ],
            )?;
        }
        self.group_state(group_id)
    }

    fn ensure_group_control_not_seen(
        &self,
        group_id: &str,
        event_id: &str,
    ) -> Result<(), StorageError> {
        let seen = self.connection.query_row(
            "SELECT 1 FROM group_control_event_seen WHERE group_id = ?1 AND event_id = ?2",
            params![group_id, event_id],
            |_row| Ok(()),
        );
        if matches!(seen, Ok(())) {
            return Err(StorageError::GroupControlReplay(event_id.to_owned()));
        }
        if !matches!(seen, Err(rusqlite::Error::QueryReturnedNoRows)) {
            seen?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_group_control_seen(
        &self,
        group_id: &str,
        event_id: &str,
        event_kind: &str,
        actor_device_id: &str,
        target_member_id: &str,
        previous_epoch: u64,
        new_group_epoch: u64,
        applied_at: i64,
    ) -> Result<(), StorageError> {
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO group_control_event_seen
                (group_id, event_id, event_kind, actor_device_id, target_member_id,
                 previous_epoch, new_group_epoch, applied_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                group_id,
                event_id,
                event_kind,
                actor_device_id,
                target_member_id,
                previous_epoch,
                new_group_epoch,
                applied_at
            ],
        )?;
        if inserted == 0 {
            return Err(StorageError::GroupControlReplay(event_id.to_owned()));
        }
        Ok(())
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
    /// Returns an error when storage lookup fails.
    pub fn group_member_joined_epoch(
        &self,
        group_id: &str,
        member_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        let joined_epoch = self
            .connection
            .query_row(
                "SELECT joined_epoch
                   FROM group_member_projection
                  WHERE group_id = ?1 AND member_id = ?2 AND active = 1",
                params![group_id, member_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        joined_epoch
            .map(|value| {
                u64::try_from(value).map_err(|err| {
                    StorageError::from(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Integer,
                        Box::new(err),
                    ))
                })
            })
            .transpose()
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
