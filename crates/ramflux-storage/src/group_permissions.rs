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

pub(crate) fn is_group_admin_role(role: &str) -> bool {
    matches!(role, "owner" | "admin")
}

pub(crate) fn can_remove_group_member(actor_role: &str, target_role: &str) -> bool {
    match (actor_role, target_role) {
        ("owner", "owner") => false,
        ("owner", _) | ("admin", "member" | "bot") => true,
        _ => false,
    }
}

pub(crate) fn can_mute_group_member(actor_role: &str, target_role: &str) -> bool {
    can_remove_group_member(actor_role, target_role)
}
