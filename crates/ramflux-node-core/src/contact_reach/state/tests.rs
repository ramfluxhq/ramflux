// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reducer semantics only; the real home-writer tests exercise signature and CAS authorization.
use super::*;
use ramflux_protocol::{contact_reach::Permissions, custody::DeviceRef};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
pub(super) const NOW: u64 = 1_760_000_000;
pub(super) fn digest(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
pub(super) fn command(subject: Subject, decision: Decision, revision: u64) -> Signed<Admission> {
    let allow = decision == Decision::Allow;
    let conversation = matches!(subject, Subject::Conversation { .. });
    Signed {
        body: Admission {
            version: 2,
            operation_id: digest(10),
            recipient_root: digest(1),
            home_head_hash: digest(11),
            expected_revision: revision,
            subject,
            decision,
            permissions: allow.then_some(Permissions::UNACCEPTED),
            grant_until: allow.then_some(if conversation { NOW + 2_592_000 } else { 0 }),
            authority_head_hash: digest(12),
            master_certificate_hash: digest(13),
            actor: DeviceRef {
                account_anchor: digest(1),
                device_id: "phone".into(),
                device_epoch: 1,
            },
            notice_hash: allow.then(|| digest(14)),
            evidence_hash: allow.then(|| digest(15)),
            issued_at: NOW,
            expires_at: NOW + 300,
        },
        signature: ramflux_protocol::encode_base64url([16; 64]),
    }
}
fn subjects() -> std::result::Result<(Subject, Subject, String), Box<dyn std::error::Error>> {
    let id = ramflux_protocol::message::dm_scope::derive(&digest(1), &digest(2))?;
    Ok((
        Subject::Friendship { root: digest(2) },
        Subject::Conversation { root: digest(2), conversation_id: id.clone() },
        id,
    ))
}
#[test]
fn cr_reply_renews_without_friendship_and_expiry_preserves_strangers() -> TestResult {
    let (_, conversation, id) = subjects()?;
    let mut state = closed_state()?;
    state.admission(command(conversation.clone(), Decision::Allow, 0), Some(&id), NOW)?;
    let mut renewal = command(conversation.clone(), Decision::Allow, 1);
    renewal.body.operation_id = digest(20);
    renewal.body.issued_at += 200;
    renewal.body.expires_at += 200;
    renewal.body.grant_until = Some(NOW + 200 + 2_592_000);
    state.admission(renewal, Some(&id), NOW + 200)?;
    assert_eq!(state.grants.len(), 1, "renewal must replace only the same conversation grant");
    assert!(
        matches!(state.grants.get(&conversation.key()?),
        Some(StateRecord::Grant { grant_until, permissions, .. })
        if *grant_until == NOW + 200 + 2_592_000 && *permissions == Permissions::UNACCEPTED),
        "renewal preserves the explicit default prohibition on optional signals"
    );
    assert!(
        matches!(
            state.placements.get(&id),
            Some(StateRecord::Placement {
                placement: Placement::Strangers,
                relationship: Relationship::Unaccepted,
                ..
            })
        ),
        "replies cannot synthesize acceptance or move the stranger thread"
    );
    let route = Route {
        version: 1,
        source: DeviceRef { account_anchor: digest(2), device_id: "peer".into(), device_epoch: 1 },
        recipient_root: digest(1),
        conversation_id: id.clone(),
        traffic: Traffic::Dm,
        group: None,
        envelope_hash: digest(21),
        authority_head_hash: digest(22),
        issued_at: NOW,
        expires_at: NOW + 3_000_000,
    };
    assert_eq!(
        state.classify(&route, "peer.example", NOW + 2_592_100)?.0,
        ReachClass::Replied,
        "the renewed grant must remain active beyond the first grant's deadline"
    );
    assert_eq!(
        state.classify(&route, "peer.example", NOW + 2_592_200)?.0,
        ReachClass::Unsolicited,
        "expiry must stop permission at the renewed deadline"
    );
    assert!(
        matches!(
            state.placements.get(&id),
            Some(StateRecord::Placement {
                placement: Placement::Strangers,
                relationship: Relationship::Unaccepted,
                ..
            })
        ),
        "time-based expiry cannot erase or accept the existing stranger thread"
    );
    Ok(())
}
#[test]
fn cr_root_block_removes_all_peer_grants_but_conversation_block_is_scoped() -> TestResult {
    let (friendship, conversation, id) = subjects()?;
    let mut state = AccountReach::default();
    state.admission(command(friendship.clone(), Decision::Allow, 0), Some(&id), NOW)?;
    state.admission(command(conversation.clone(), Decision::Allow, 1), Some(&id), NOW)?;
    state.admission(command(conversation.clone(), Decision::Block, 2), Some(&id), NOW)?;
    assert!(
        state.grants.contains_key(&friendship.key()?),
        "a conversation-specific decision cannot silently remove unrelated friendship authority"
    );
    assert!(
        !state.grants.contains_key(&conversation.key()?),
        "the blocked conversation grant must retire"
    );
    state.admission(command(friendship.clone(), Decision::Block, 3), Some(&id), NOW)?;
    assert!(state.grants.is_empty(), "a root block must remove every grant for that peer");
    assert!(
        state.admission(command(conversation, Decision::Allow, 4), Some(&id), NOW).is_err(),
        "an allow cannot install latent authority beneath a retained root block"
    );
    state.admission(command(friendship, Decision::Unblock, 4), Some(&id), NOW)?;
    assert!(state.grants.is_empty(), "unblock must restore no positive authority");
    Ok(())
}

pub(super) fn closed_state() -> std::result::Result<AccountReach, Box<dyn std::error::Error>> {
    let mut state = AccountReach::default();
    state.policy(Signed {
        body: ReachPolicy {
            version: 1,
            operation_id: digest(30),
            account_anchor: digest(1),
            home_head_hash: digest(11),
            expected_revision: 0,
            revision: 1,
            mode: ReachMode::ContactsOnly,
            authority_head_hash: digest(12),
            master_certificate_hash: digest(13),
            actor: DeviceRef {
                account_anchor: digest(1),
                device_id: "phone".into(),
                device_epoch: 1,
            },
            issued_at: NOW,
            expires_at: NOW + 300,
        },
        signature: ramflux_protocol::encode_base64url([16; 64]),
    })?;
    Ok(state)
}

#[test]
fn cr_group_route_requires_its_own_grant_even_with_friendship() -> TestResult {
    let mut state = closed_state()?;
    let (friendship, _, id) = subjects()?;
    state.admission(command(friendship, Decision::Allow, 0), Some(&id), NOW)?;
    let route = Route {
        version: 1,
        source: DeviceRef { account_anchor: digest(2), device_id: "peer".into(), device_epoch: 1 },
        recipient_root: digest(1),
        conversation_id: "signed-thread".into(),
        traffic: Traffic::Group,
        group: Some(ramflux_protocol::contact_reach::GroupRoute {
            group_id: "group".into(),
            group_epoch: 1,
            membership_hash: digest(15),
        }),
        envelope_hash: digest(21),
        authority_head_hash: digest(22),
        issued_at: NOW,
        expires_at: NOW + 3600,
    };
    assert!(
        matches!(
            state.classify(&route, "peer.example", NOW),
            Err(ReachError::Refused(Reason::ForeignReadRefused))
        ),
        "friendship cannot substitute for a group grant and its current roster"
    );
    Ok(())
}
