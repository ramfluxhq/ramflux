// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual certified-primary signatures and redb commits/reopens, separate from SDK/rf acceptance.
use super::*;
use ramflux_protocol::contact_reach::{
    GROUP_JOIN_NOTICE_DOMAIN, GROUP_ROSTER_MEMBERS_DOMAIN, GroupJoinNotice, GroupRoster,
    GroupRosterHeader, GroupRosterMember, GroupRoute, Route, StateRecord, Traffic,
};
fn subject(epoch: u64) -> Subject {
    Subject::Group {
        group_id: "group".into(),
        conversation_id: "signed-thread".into(),
        genesis_hash: digest(30),
        group_epoch: epoch,
        membership_hash: digest(31),
    }
}
fn decision(
    f: &Fixture,
    id: u8,
    subject: Subject,
    revision: u64,
    decision: Decision,
    now: u64,
) -> TestResult<Operation> {
    let allow = decision == Decision::Allow;
    let notice = GroupJoinNotice {
        version: 1,
        recipient_root: f.root.clone(),
        group_id: "group".into(),
        conversation_id: "signed-thread".into(),
        genesis_hash: digest(30),
        epoch: 100,
        membership_hash: digest(31),
        inviter_root: digest(41),
        member_root_count: 2,
    };
    let update = f.key.sign_reach_admission(
        Admission {
            version: 2,
            operation_id: digest(id),
            recipient_root: f.root.clone(),
            home_head_hash: f.home.clone(),
            expected_revision: revision,
            subject,
            decision,
            permissions: allow.then_some(ramflux_protocol::contact_reach::Permissions::UNACCEPTED),
            grant_until: allow.then_some(0),
            authority_head_hash: custody::object_hash(f.authority.envelope())?,
            master_certificate_hash: custody::object_hash(
                &f.authority.envelope().body.master_certificate,
            )?,
            actor: f.actor.clone(),
            notice_hash: allow
                .then(|| custody::framed_hash(GROUP_JOIN_NOTICE_DOMAIN, &notice))
                .transpose()?,
            evidence_hash: allow.then(|| digest(31)),
            issued_at: now,
            expires_at: now + 300,
        },
        &f.authority,
        now,
    )?;
    Ok(Operation::Admission { update, peer_evidence: None, notice: None })
}
fn install_live_group(store: &RouterRedbStore, f: &Fixture) -> TestResult<Operation> {
    store.reach_owner_commit(owner(f), &policy(f, 10, 0, ReachMode::ContactsOnly)?, NOW)?;
    let grant = decision(f, 50, subject(100), 0, Decision::Allow, NOW)?;
    store.reach_owner_commit(owner(f), &grant, NOW)?;
    let Operation::Admission { update, .. } = &grant else {
        return Err("group grant operation".into());
    };
    let members = vec![GroupRosterMember { root: digest(41), since_epoch: 100 }];
    let body = GroupRosterHeader {
        version: 1,
        recipient_root: f.root.clone(),
        group_id: "group".into(),
        conversation_id: "signed-thread".into(),
        grant_hash: custody::framed_hash(OPERATION_HASH_DOMAIN, update)?,
        group_epoch: 100,
        membership_hash: digest(31),
        members_hash: custody::framed_hash(GROUP_ROSTER_MEMBERS_DOMAIN, &members)?,
        member_count: 1,
        issued_at: NOW,
    };
    let roster =
        GroupRoster { header: f.key.sign_group_roster_header(body, &f.authority, NOW)?, members };
    store.reach_group_roster(owner(f), &digest(51), &roster, NOW)?;
    Ok(grant)
}
fn route(f: &Fixture) -> Route {
    Route {
        version: 1,
        source: DeviceRef { account_anchor: digest(41), device_id: "peer".into(), device_epoch: 1 },
        recipient_root: f.root.clone(),
        conversation_id: "signed-thread".into(),
        traffic: Traffic::Group,
        group: Some(GroupRoute {
            group_id: "group".into(),
            group_epoch: 100,
            membership_hash: digest(31),
        }),
        envelope_hash: digest(42),
        authority_head_hash: digest(43),
        issued_at: NOW,
        expires_at: NOW + 3600,
    }
}
#[test]
fn cr_group_home_roster_and_retirement_survive_reopen() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("home.redb");
    let (store, f) = initialize(&path)?;
    install_live_group(&store, &f)?;
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    {
        let tx = store.begin_write()?;
        let state = load(&tx, &f.root)?;
        assert_eq!(
            state.classify(&route(&f), "peer.example", NOW)?,
            (
                crate::contact_reach::ReachClass::Accepted,
                ramflux_protocol::contact_reach::Placement::Direct
            ),
            "the persisted primary-signed roster admits its exact granted member after reopen"
        );
    }
    store.reach_owner_commit(
        owner(&f),
        &decision(&f, 52, subject(101), 1, Decision::Revoke, NOW)?,
        NOW,
    )?;
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let tx = store.begin_write()?;
    let state = load(&tx, &f.root)?;
    assert!(
        state.grants.is_empty() && state.rosters.is_empty(),
        "leave removes the live grant and roster atomically and durably"
    );
    let StateRecord::Retirement { update, group_floor: Some(floor), .. } =
        state.retirements.get(&subject(1).key()?).ok_or("group retirement")?
    else {
        return Err("canonical group floor".into());
    };
    assert_eq!(
        floor.floor_epoch, 101,
        "the signed retirement epoch dominates both epoch-100 witnesses"
    );
    ramflux_crypto::contact_reach::verify_group_retirement(update, floor, &f.authority, NOW + 301)?;
    assert!(
        state.classify(&route(&f), "peer.example", NOW).is_err(),
        "the retained witness cannot act as a live grant after reopen"
    );
    Ok(())
}
#[test]
fn cr_group_home_retained_unblock_outlives_dedup_and_last_update() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("home.redb");
    let (store, f) = initialize(&path)?;
    install_live_group(&store, &f)?;
    for (id, epoch, revision, action) in
        [(52, 101, 1, Decision::Revoke), (53, 1, 2, Decision::Block), (54, 1, 3, Decision::Unblock)]
    {
        store.reach_owner_commit(
            owner(&f),
            &decision(&f, id, subject(epoch), revision, action, NOW)?,
            NOW,
        )?;
    }
    let unrelated = decision(
        &f,
        55,
        Subject::Node { node_id: "unrelated.example".into() },
        4,
        Decision::Block,
        NOW + 400,
    )?;
    store.reach_owner_commit(owner(&f), &unrelated, NOW + 400)?;
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let tx = store.begin_write()?;
    let state = load(&tx, &f.root)?;
    assert!(
        matches!(
            state.last_update.as_ref().map(|update| &update.body.subject),
            Some(Subject::Node { .. })
        ),
        "an unrelated admission overwrites the account-wide last update"
    );
    assert!(
        tx.open_table(OPERATIONS)?.get(key(&f.root, &digest(54))?.as_str())?.is_none(),
        "the old unblock command cache has expired and been collected"
    );
    let StateRecord::Retirement { update, group_floor: Some(floor), .. } =
        state.retirements.get(&subject(1).key()?).ok_or("retained group floor")?
    else {
        return Err("canonical group retirement".into());
    };
    assert_eq!(
        floor.floor_epoch, 101,
        "neither unrelated commands nor reopen lower the group floor"
    );
    let control = floor.block_control.as_ref().ok_or("retained signed unblock")?;
    assert_eq!(
        control.body.decision,
        Decision::Unblock,
        "clearance remains in the canonical group record independently of last_update and command dedup"
    );
    ramflux_crypto::contact_reach::verify_group_retirement(update, floor, &f.authority, NOW + 400)?;
    assert!(
        !floor.blocked() && state.grants.is_empty() && state.rosters.is_empty(),
        "unblock clears only the block and creates no grant or roster"
    );
    Ok(())
}
