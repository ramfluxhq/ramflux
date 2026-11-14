// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One common group profile for producer, ingress, own-copy and reparse.
use super::{Reason, invalid};
use crate::{ProtocolError, message::EventIdentity};
/// Keep the signed snapshot's existing group identifier validator.
/// # Errors
/// Refuses blank, oversized or unsafe single-line identifiers.
pub fn validate_group_id(group_id: &str) -> Result<(), ProtocolError> {
    if group_id.trim().is_empty()
        || group_id.len() > 256
        || !crate::text_safety::single_line_is_safe(group_id)
    {
        return Err(invalid("invalid signed group id"));
    }
    Ok(())
}
/// Apply FINAL r4f's common profile before any sealing or inner effects.
/// `signed_state_present` comes from a verified candidate/adopted state, never a W assertion.
/// # Errors
/// Returns the closed typed refusal for legacy groups, group optional signals/calls/`SelfSync`,
/// or a grouped Control outside `GroupState`/`GroupKey`.
pub fn check(
    identity: &EventIdentity,
    kind: u32,
    control_operation: Option<i32>,
    signed_state_present: bool,
) -> Result<(), Reason> {
    let Some(group) = identity.group_id.as_deref() else {
        return if identity.group_epoch.is_none() {
            Ok(())
        } else {
            Err(Reason::ReachRouteInvalid)
        };
    };
    if !signed_state_present
        || validate_group_id(group).is_err()
        || crate::message::dm_scope::validate_group(&identity.conversation_id).is_err()
        || identity
            .group_epoch
            .is_none_or(|epoch| epoch == 0 || epoch > crate::MAX_SAFE_JSON_INTEGER)
        || matches!(kind, 6 | 7 | 11 | 12)
        || kind == 8 && !matches!(control_operation, Some(4 | 5))
    {
        return Err(Reason::ReachRouteInvalid);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr_group_profile_guard() {
        let identity = EventIdentity {
            conversation_id: "signed-thread".into(),
            group_id: Some("group".into()),
            group_epoch: Some(1),
            ..Default::default()
        };
        for kind in [1, 2, 3, 4, 5, 9, 10] {
            assert_eq!(
                check(&identity, kind, None, true),
                Ok(()),
                "signed group content stays in the common profile"
            );
        }
        for operation in [4, 5] {
            assert_eq!(
                check(&identity, 8, Some(operation), true),
                Ok(()),
                "both signed group control arms remain available"
            );
        }
        for kind in [6, 7, 11, 12] {
            assert_eq!(
                check(&identity, kind, None, true),
                Err(Reason::ReachRouteInvalid),
                "group receipts, Typing, calls and SelfSync are uniformly unavailable"
            );
        }
        for operation in [1, 3, 11, 15] {
            assert!(
                check(&identity, 8, Some(operation), true).is_err(),
                "a group label cannot authorize another Control, including a grouped own-copy wrapper"
            );
        }
        assert!(
            check(&identity, 1, None, false).is_err(),
            "an unsigned legacy group cannot hold a transport grant"
        );
        let mut invalid = identity.clone();
        invalid.conversation_id = "dm:forged".into();
        assert!(
            check(&invalid, 1, None, true).is_err(),
            "groups cannot occupy the reserved DM namespace"
        );
        invalid = identity;
        invalid.group_epoch = None;
        assert!(
            check(&invalid, 1, None, true).is_err(),
            "all group kinds require their authenticated epoch"
        );
    }
}
