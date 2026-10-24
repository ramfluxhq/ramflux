// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared group role permission table for storage and authenticated state transitions.
#[must_use]
pub fn is_group_admin_role(role: &str) -> bool {
    matches!(role, "owner" | "admin")
}

#[must_use]
pub fn can_remove_group_member(actor_role: &str, target_role: &str) -> bool {
    match (actor_role, target_role) {
        ("owner", "owner") => false,
        ("owner", _) | ("admin", "member" | "bot") => true,
        _ => false,
    }
}

#[must_use]
pub fn can_mute_group_member(actor_role: &str, target_role: &str) -> bool {
    can_remove_group_member(actor_role, target_role)
}

#[must_use]
pub fn can_invite_group_member(actor_role: &str, invited_role: &str) -> bool {
    matches!(
        (actor_role, invited_role),
        ("owner", "admin" | "member" | "bot") | ("admin", "member" | "bot")
    )
}

#[must_use]
pub fn can_delete_group_message(
    actor_role: &str,
    message_author_role: &str,
    is_own_message: bool,
) -> bool {
    if is_own_message {
        return matches!(actor_role, "owner" | "admin" | "member" | "bot");
    }
    match (actor_role, message_author_role) {
        ("owner", "owner") => false,
        ("owner", _) | ("admin", "member" | "bot") => true,
        _ => false,
    }
}

#[must_use]
pub fn can_change_group_member_role(actor_role: &str, target_role: &str, new_role: &str) -> bool {
    if target_role == new_role {
        return matches!(actor_role, "owner" | "admin");
    }
    matches!(
        (actor_role, target_role, new_role),
        ("owner", "admin" | "member" | "bot", "admin" | "member" | "bot")
            | ("admin", "member" | "bot", "member" | "bot")
    )
}
