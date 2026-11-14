// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Projection-only tests; signature and complete-page verification is a separate boundary.
use super::*;
use ramflux_protocol::{
    contact_reach::{Admission, Decision},
    custody::{DeviceRef, Envelope},
};
use std::collections::BTreeMap;
const NOW: u64 = 1000;
fn state() -> SavedReachState {
    SavedReachState {
        root: "owner".into(),
        revision: 1,
        admission_revision: 1,
        home_head_hash: "home".into(),
        authority_head_hash: "authority".into(),
        state_hash: "content".into(),
        records: vec![],
        restrictions: BTreeMap::new(),
        conflict: false,
    }
}
fn subject() -> Subject {
    Subject::Conversation { root: "peer".into(), conversation_id: "dm".into() }
}
fn grant(subject: Subject, until: u64, permissions: Permissions) -> StateRecord {
    let update = Envelope {
        body: Admission {
            version: 2,
            operation_id: "op".into(),
            recipient_root: "owner".into(),
            home_head_hash: "home".into(),
            expected_revision: 0,
            subject: subject.clone(),
            decision: Decision::Allow,
            permissions: Some(permissions),
            grant_until: Some(until),
            authority_head_hash: "authority".into(),
            master_certificate_hash: "cert".into(),
            actor: DeviceRef {
                account_anchor: "owner".into(),
                device_id: "phone".into(),
                device_epoch: 0,
            },
            notice_hash: Some("notice".into()),
            evidence_hash: Some("evidence".into()),
            issued_at: NOW,
            expires_at: NOW + 300,
        },
        signature: "verified-before-projection".into(),
    };
    StateRecord::Grant { subject, permissions, grant_until: until, update }
}
fn placement(placement: Placement, relationship: Relationship) -> StateRecord {
    StateRecord::Placement {
        conversation_id: "dm".into(),
        revision: 1,
        placement,
        relationship,
        tombstone: false,
        basis: vec![],
    }
}
#[test]
fn cr_reply_permission_expires_without_accepting_or_erasing_thread() -> Result<(), SdkError> {
    let mut state = state();
    state.records = vec![
        placement(Placement::Strangers, Relationship::Unaccepted),
        grant(subject(), NOW + 10, Permissions::UNACCEPTED),
    ];
    let active = state.conversation("peer", "node", "dm", NOW)?;
    assert_eq!(
        active.conversation_permission,
        ConversationPermission::Active,
        "a current conversation grant must support replies"
    );
    assert_eq!(
        active.relationship,
        Relationship::Unaccepted,
        "reply cannot manufacture friendship"
    );
    assert_eq!(
        active.permissions,
        Permissions::UNACCEPTED,
        "reply cannot silently enable optional signals"
    );
    let expired = state.conversation("peer", "node", "dm", NOW + 10)?;
    assert_eq!(
        expired.conversation_permission,
        ConversationPermission::Expired,
        "grant deadline is exclusive"
    );
    assert_eq!(
        expired.placement,
        Placement::Strangers,
        "expiry must retain thread placement/history"
    );
    Ok(())
}
#[test]
fn cr_open_placement_and_missing_friendship_never_grant_optional_signals() -> Result<(), SdkError> {
    let mut state = state();
    state.records.push(placement(Placement::Direct, Relationship::Accepted));
    let view = state.conversation("peer", "node", "dm", NOW)?;
    assert_eq!(view.placement, Placement::Direct, "retain direct thread history");
    assert_eq!(
        view.relationship,
        Relationship::Unaccepted,
        "an absent positive grant cannot be inferred from placement"
    );
    assert_eq!(
        view.permissions,
        Permissions::UNACCEPTED,
        "direct placement does not authorize receipts or typing"
    );
    Ok(())
}
#[test]
fn cr_retained_denial_dominates_current_positive_grants() -> Result<(), SdkError> {
    let mut state = state();
    state.records.push(grant(
        Subject::Friendship { root: "peer".into() },
        0,
        Permissions::ACCEPTED,
    ));
    assert_eq!(
        state.conversation("peer", "node", "dm", NOW)?.relationship,
        Relationship::Accepted,
        "explicit friendship is the positive control"
    );
    state.restrictions.insert(
        "deny".into(),
        StateRecord::Floor {
            subject: Subject::Node { node_id: "node".into() },
            revision: 2,
            denied: true,
            erase_generation: 2,
            erased: true,
        },
    );
    assert!(
        state.conversation("peer", "node", "dm", NOW).is_err(),
        "a retained node block must dominate accepted friendship"
    );
    state.restrictions.clear();
    state.records.push(StateRecord::Floor {
        subject: subject(),
        revision: 3,
        denied: true,
        erase_generation: 3,
        erased: true,
    });
    assert!(
        state.conversation("peer", "node", "dm", NOW).is_err(),
        "a current conversation denial must dominate friendship too"
    );
    Ok(())
}

#[test]
fn cr_remote_cas_failure_preserves_revision_for_explicit_refresh() {
    let result = ramflux_protocol::contact_reach::OperationResult::Error {
        reason: Reason::ReachRevisionConflict,
        retry_after_ms: None,
        current_revision: Some(9),
    };
    assert!(
        matches!(
            crate::contact_reach::remote_result(result),
            Err(SdkError::ReachRemote {
                reason: Reason::ReachRevisionConflict,
                current_revision: Some(9),
                retry_after_ms: None
            })
        ),
        "SDK must preserve authoritative CAS metadata rather than returning an opaque refusal"
    );
}
