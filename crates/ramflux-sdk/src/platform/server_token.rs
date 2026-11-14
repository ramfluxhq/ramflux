// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Extra check on a named-pipe server after the owner SID has already matched.
//!
//! A medium client often cannot open an elevated daemon's process token. The
//! design accepts that same-user case, so an unreadable token is not a refusal.

/// `Some(true)` is the same user, `Some(false)` is a different user, and
/// `None` means the token could not be read.
#[must_use]
pub(crate) const fn server_token_acceptable(same_user: Option<bool>) -> bool {
    match same_user {
        Some(same) => same,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::server_token_acceptable;

    #[test]
    fn matching_server_token_is_accepted() {
        assert!(server_token_acceptable(Some(true)));
    }

    #[test]
    fn different_server_token_is_refused() {
        assert!(!server_token_acceptable(Some(false)));
    }

    #[test]
    fn unreadable_server_token_is_accepted() {
        assert!(server_token_acceptable(None));
    }
}
