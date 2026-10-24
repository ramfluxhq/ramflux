// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use crate::*;

pub(crate) fn validate_group_role(role: &str) -> Result<(), StorageError> {
    match role {
        "owner" | "admin" | "member" | "bot" => Ok(()),
        unknown => Err(StorageError::InvalidGroupRole(unknown.to_owned())),
    }
}

pub(crate) use ramflux_protocol::group_permissions::{
    can_change_group_member_role, can_delete_group_message, can_invite_group_member,
    can_mute_group_member, can_remove_group_member, is_group_admin_role,
};
