// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reducer controls; these do not claim SDK, service transport or historical signer acceptance.
use super::super::tests::{NOW, closed_state, command, digest};
use super::*;
use ramflux_protocol::contact_reach::{
    GROUP_ROSTER_MEMBERS_DOMAIN, GroupRosterHeader, GroupRosterMember, GroupRoute, Traffic,
};
use ramflux_protocol::custody::DeviceRef;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn cr_group_reservation_includes_existing_bytes_and_has_a_hard_ceiling() -> TestResult {
    let mut state = closed_state()?;
    for index in 0..1024_u64 {
        let mut genesis = [0_u8; 32];
        genesis.get_mut(..8).ok_or("genesis prefix")?.copy_from_slice(&index.to_be_bytes());
        let subject = Subject::Group {
            group_id: format!("group-{index}"),
            conversation_id: format!("thread-{index}"),
            genesis_hash: ramflux_protocol::encode_base64url(genesis),
            group_epoch: 1,
            membership_hash: digest(15),
        };
        let update = command(subject.clone(), Decision::Allow, index);
        state.grants.insert(
            subject.key()?,
            StateRecord::Grant {
                subject,
                permissions: Permissions::UNACCEPTED,
                grant_until: 0,
                update,
            },
        );
    }
    state.check_group_reservations(true)?;
    assert_eq!(
        state.grants.len(),
        1024,
        "the count cap remains reachable with realistic serialized grants"
    );
    // This reducer-only corruption probe exercises the byte ceiling independently of signature checks.
    let Some(StateRecord::Grant { update, .. }) = state.grants.values_mut().next() else {
        return Err("first group grant".into());
    };
    update.signature = "x".repeat(GROUP_DENIAL_RESERVATION);
    assert!(
        matches!(
            state.check_group_reservations(true),
            Err(ReachError::Refused(Reason::ForeignCapacity))
        ),
        "positive capacity cannot grow a group beyond its fixed 15-KiB reservation"
    );
    assert!(
        state.check_group_reservations(false).is_err(),
        "reopen validation also refuses an oversized group record instead of silently enlarging its reservation"
    );
    Ok(())
}
fn subject(epoch: u64) -> Subject {
    Subject::Group {
        group_id: "group".into(),
        conversation_id: "signed-thread".into(),
        genesis_hash: digest(30),
        group_epoch: epoch,
        membership_hash: digest(15),
    }
}
fn roster(
    grant: &Signed<Admission>,
    epoch: u64,
    members: Vec<GroupRosterMember>,
) -> Result<GroupRoster> {
    Ok(GroupRoster {
        header: Signed {
            body: GroupRosterHeader {
                authority_head_hash: grant.body.authority_head_hash.clone(),
                master_certificate_hash: grant.body.master_certificate_hash.clone(),
                version: 1,
                recipient_root: digest(1),
                group_id: "group".into(),
                conversation_id: "signed-thread".into(),
                grant_hash: framed_hash(OPERATION_HASH_DOMAIN, grant)?,
                group_epoch: epoch,
                membership_hash: digest(15),
                members_hash: framed_hash(GROUP_ROSTER_MEMBERS_DOMAIN, &members)?,
                member_count: u64::try_from(members.len()).map_err(storage)?,
                issued_at: NOW,
            },
            signature: ramflux_protocol::encode_base64url([40; 64]),
        },
        members,
    })
}
#[test]
fn cr_group_floor_proof_and_retained_unblock_model() -> TestResult {
    let mut state = closed_state()?;
    let grant = command(subject(100), Decision::Allow, 0);
    state.admission(grant.clone(), None, NOW)?;
    state.group_roster(roster(
        &grant,
        100,
        vec![GroupRosterMember { root: digest(2), since_epoch: 100 }],
    )?)?;
    state.admission(command(subject(101), Decision::Revoke, 1), None, NOW)?;
    let key = subject(1).key()?;
    let floor = state.group_floor(&key)?.ok_or("retirement floor")?;
    assert_eq!(
        floor.floor_epoch, 101,
        "a kick head above the grant and roster is part of the one floor formula"
    );
    assert!(
        state.rosters.is_empty() && state.grants.is_empty(),
        "retirement removes the grant and roster in the same candidate state"
    );
    state.admission(command(subject(1), Decision::Block, 2), None, NOW)?;
    state.admission(command(subject(1), Decision::Unblock, 3), None, NOW)?;
    let floor = state.group_floor(&key)?.ok_or("unblocked floor")?;
    assert!(!floor.blocked(), "the later signed unblock clears only the active block");
    assert_eq!(floor.floor_epoch, 101, "unblock never changes the admission floor");
    let before = ramflux_protocol::canonical_json_bytes(&state)?;
    assert!(
        matches!(
            state.admission(command(subject(101), Decision::Allow, 4), None, NOW),
            Err(ReachError::Refused(Reason::GroupEpochStale))
        ),
        "rejoin must strictly exceed the retained floor"
    );
    assert_eq!(
        ramflux_protocol::canonical_json_bytes(&state)?,
        before,
        "a refused rejoin writes no partial positive state"
    );
    state.admission(command(subject(102), Decision::Allow, 4), None, NOW)?;
    state.admission(command(subject(1), Decision::Revoke, 5), None, NOW)?;
    let StateRecord::Retirement { update, group_floor: Some(floor), .. } =
        state.retirements.get(&key).ok_or("second retirement")?
    else {
        return Err("canonical group retirement missing".into());
    };
    floor.validate(update)?;
    assert_eq!(floor.floor_epoch, 102, "the newly retired grant dominates the previous floor");
    assert_eq!(
        floor.block_control.as_ref().map(|control| control.body.decision),
        Some(Decision::Unblock),
        "the signed clearance survives rejoin and a later leave"
    );
    let record = state.retirements.get(&key).ok_or("retained proof")?;
    assert!(
        ramflux_protocol::canonical_json_bytes(record)?.len() <= GROUP_DENIAL_RESERVATION,
        "the complete signed proof remains inside its JOIN-time reservation"
    );
    Ok(())
}
#[test]
fn cr_group_route_binding_and_roster_admission_floor_model() -> TestResult {
    let mut state = closed_state()?;
    let grant = command(subject(10), Decision::Allow, 0);
    state.admission(grant.clone(), None, NOW)?;
    let mut route = Route {
        version: 1,
        source: DeviceRef { account_anchor: digest(2), device_id: "peer".into(), device_epoch: 1 },
        recipient_root: digest(1),
        conversation_id: "signed-thread".into(),
        traffic: Traffic::Group,
        group: Some(GroupRoute {
            group_id: "group".into(),
            group_epoch: 10,
            membership_hash: digest(15),
        }),
        envelope_hash: digest(21),
        authority_head_hash: digest(22),
        issued_at: NOW,
        expires_at: NOW + 3600,
    };
    assert!(
        state.classify(&route, "peer.example", NOW).is_err(),
        "a live group grant without its matching roster authorizes no sender"
    );
    state.group_roster(roster(
        &grant,
        10,
        vec![GroupRosterMember { root: digest(2), since_epoch: 10 }],
    )?)?;
    assert_eq!(
        state.classify(&route, "peer.example", NOW)?,
        (ReachClass::Accepted, Placement::Direct),
        "initial JOIN roster permits a member at the grant's epoch"
    );
    route.group.as_mut().ok_or("group route")?.group_epoch = 9;
    assert!(
        matches!(
            state.classify(&route, "peer.example", NOW),
            Err(ReachError::Refused(Reason::GroupEpochStale))
        ),
        "membership predating JOIN cannot lower its admission floor"
    );
    route.group.as_mut().ok_or("group route")?.group_epoch = 11;
    assert!(
        state.classify(&route, "peer.example", NOW).is_ok(),
        "a higher W epoch is bounded transport only and never installs a head"
    );
    assert_eq!(
        state.rosters.get(&subject(1).key()?).map(|roster| roster.header.body.group_epoch),
        Some(10),
        "unverified W metadata cannot advance the primary-signed roster"
    );
    state.group_roster(roster(&grant, 11, Vec::new())?)?;
    assert!(
        state.classify(&route, "peer.example", NOW).is_err(),
        "removal takes effect from the committed roster even if the grant remains live"
    );
    Ok(())
}
