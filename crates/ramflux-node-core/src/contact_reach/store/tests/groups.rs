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
        authority_head_hash: custody::object_hash(f.authority.envelope())?,
        master_certificate_hash: custody::object_hash(
            &f.authority.envelope().body.master_certificate,
        )?,
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
fn cr_group_receiving_barrier_rechecks_original_recipient_signatures() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("recipient-signatures.redb");
    let (store, f) = initialize(&path)?;
    install_live_group(&store, &f)?;
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let tx = store.begin_write()?;
    let state = load(&tx, &f.root)?;
    drop(tx);
    let route = route(&f);
    assert_eq!(
        state.classify_current(&route, "peer.example", &f.authority, NOW)?.0,
        crate::contact_reach::ReachClass::Accepted,
        "the receiving barrier must accept the original persisted phone signatures"
    );
    for alteration in 0..4 {
        let mut changed = state.clone();
        let invalid_signature = ramflux_protocol::encode_base64url([99; 64]);
        match alteration {
            0 => changed.policy.as_mut().ok_or("policy")?.signature = invalid_signature,
            1 => {
                let StateRecord::Grant { update, .. } =
                    changed.grants.get_mut(&subject(100).key()?).ok_or("group grant")?
                else {
                    return Err("group grant record".into());
                };
                update.signature = invalid_signature;
            }
            2 => {
                changed.rosters.get_mut(&subject(100).key()?).ok_or("roster")?.header.signature =
                    invalid_signature;
            }
            _ => {
                changed.policy.as_mut().ok_or("policy")?.body.master_certificate_hash = digest(98);
            }
        }
        assert!(
            changed.classify_current(&route, "peer.example", &f.authority, NOW).is_err(),
            "a saved policy, grant, roster or certificate substitution cannot authorize ingress: {alteration}"
        );
    }
    Ok(())
}

#[test]
fn cr_dm_receiving_barrier_requires_the_original_grant_signature() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let (store, f) = initialize(&dir.path().join("dm-recipient-signature.redb"))?;
    store.reach_owner_commit(owner(&f), &policy(&f, 10, 0, ReachMode::ContactsOnly)?, NOW)?;
    let tx = store.begin_write()?;
    let mut state = load(&tx, &f.root)?;
    drop(tx);
    let subject = Subject::Friendship { root: digest(41) };
    let Operation::Admission { update, .. } =
        decision(&f, 51, subject.clone(), 0, Decision::Allow, NOW)?
    else {
        return Err("friendship admission".into());
    };
    // The reducer boundary receives an original primary signature; peer/Notice admission
    // is tested by the home-writer controls, independently of this use-time signature gate.
    state.admission(update, None, NOW)?;
    let mut route = route(&f);
    route.traffic = Traffic::Dm;
    route.group = None;
    route.conversation_id = ramflux_protocol::message::dm_scope::derive(
        &route.source.account_anchor,
        &route.recipient_root,
    )?;
    state.classify_current(&route, "peer.example", &f.authority, NOW)?;
    let StateRecord::Grant { update, .. } =
        state.grants.get_mut(&subject.key()?).ok_or("friendship grant")?
    else {
        return Err("grant row".into());
    };
    update.signature = ramflux_protocol::encode_base64url([99; 64]);
    assert!(
        state.classify(&route, "peer.example", NOW).is_ok(),
        "saved reducer presence alone cannot authenticate the original phone grant"
    );
    assert!(
        state.classify_current(&route, "peer.example", &f.authority, NOW).is_err(),
        "the actual receiving signature gate must refuse a home-substituted grant"
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

#[test]
fn cr_source_submit_requires_original_return_grant_before_first_dm() -> TestResult {
    use crate::contact_reach::submit::require_return_grant;
    let dir = tempfile::TempDir::new()?;
    let (store, f) = initialize(&dir.path().join("source-return-grant.redb"))?;
    store.reach_owner_commit(owner(&f), &policy(&f, 70, 0, ReachMode::ContactsOnly)?, NOW)?;
    store.reach_owner_commit(owner(&f), &policy(&f, 71, 1, ReachMode::Open)?, NOW)?;
    let tx = store.begin_write()?;
    let mut state = load(&tx, &f.root)?;
    drop(tx);
    let peer = digest(41);
    let conversation = ramflux_protocol::message::dm_scope::derive(&f.root, &peer)?;
    let mut outgoing = Route {
        version: 1,
        source: f.actor.clone(),
        recipient_root: peer.clone(),
        conversation_id: conversation.clone(),
        traffic: Traffic::Dm,
        group: None,
        envelope_hash: digest(72),
        authority_head_hash: custody::object_hash(f.authority.envelope())?,
        issued_at: NOW,
        expires_at: NOW + 3600,
    };
    assert!(
        require_return_grant(&state, &outgoing, &f.authority, "peer.example", NOW).is_err(),
        "open source policy cannot replace the explicit return grant required before first send"
    );
    let Operation::Admission { update, .. } =
        decision(&f, 73, Subject::Friendship { root: peer.clone() }, 0, Decision::Allow, NOW)?
    else {
        return Err("friendship operation".into());
    };
    let mut body = update.body;
    body.subject =
        Subject::Conversation { root: peer.clone(), conversation_id: conversation.clone() };
    body.grant_until = Some(NOW + ramflux_protocol::contact_reach::CONVERSATION_LIFETIME);
    let grant = f.key.sign_reach_admission(body, &f.authority, NOW)?;
    // This exercises source use-time authorization from an original primary signature.
    // The composite writer's Notice/evidence/outbox atomicity has separate controls.
    state.admission(grant, Some(&conversation), NOW)?;
    require_return_grant(&state, &outgoing, &f.authority, "peer.example", NOW)?;
    for traffic in [Traffic::ReceiptDelivered, Traffic::ReceiptRead, Traffic::Typing] {
        outgoing.traffic = traffic;
        assert!(
            require_return_grant(&state, &outgoing, &f.authority, "peer.example", NOW).is_err(),
            "default conversation grants cannot authorize optional outbound receipt or typing signals"
        );
    }
    outgoing.traffic = Traffic::Dm;
    let expires = NOW + ramflux_protocol::contact_reach::CONVERSATION_LIFETIME;
    let renewed = renewed_primary(&f, expires)?;
    require_return_grant(&state, &outgoing, &renewed, "peer.example", expires - 1)?;
    assert!(
        require_return_grant(&state, &outgoing, &renewed, "peer.example", expires).is_err(),
        "the exact grant deadline must stop sending while the same primary remains authorized"
    );
    let subject = Subject::Conversation { root: peer, conversation_id: conversation };
    let StateRecord::Grant { update, .. } =
        state.grants.get_mut(&subject.key()?).ok_or("return grant")?
    else {
        return Err("grant row".into());
    };
    update.signature = ramflux_protocol::encode_base64url([99; 64]);
    assert!(
        require_return_grant(&state, &outgoing, &f.authority, "peer.example", NOW).is_err(),
        "a saved grant row without the original phone signature cannot authorize source egress"
    );
    Ok(())
}

pub(super) fn renewed_primary(f: &Fixture, expires: u64) -> TestResult<VerifiedRecord> {
    let mut body = f.authority.envelope().body.clone();
    body.device_set_epoch = body.device_set_epoch.checked_add(1).ok_or("epoch overflow")?;
    body.previous_record_hash = Some(custody::object_hash(f.authority.envelope())?);
    body.issued_at = expires - 3600;
    let primary = body
        .devices
        .iter_mut()
        .find(|device| device.device_id == f.actor.device_id)
        .ok_or("primary device")?;
    let mut branch = primary.branch_certificate.as_ref().ok_or("primary certificate")?.body.clone();
    branch.cert_id = digest(75);
    branch.not_before = expires - 3600;
    branch.expires_at = expires + 3600;
    primary.branch_certificate = Some(f.key.certify_branch(branch)?);
    let record = f.key.sign_record(body)?;
    Ok(ramflux_crypto::custody::verify_record(&record, expires, None, None)?)
}

#[test]
fn cr_current_recipient_primary_revocation_fences_persisted_group_authority() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("revoked-recipient-primary.redb");
    let (store, f) = initialize(&path)?;
    install_live_group(&store, &f)?;
    let tx = store.begin_write()?;
    let state = load(&tx, &f.root)?;
    drop(tx);
    let mut sibling = f
        .authority
        .envelope()
        .body
        .devices
        .first()
        .and_then(|device| device.branch_certificate.as_ref())
        .ok_or("primary certificate")?
        .body
        .clone();
    sibling.device_id = "sibling".into();
    sibling.cert_id = digest(80);
    sibling.branch_signing_public_key = ramflux_crypto::public_key_base64url_from_seed([81; 32]);
    let enrolled = f.key.enroll_device(&f.authority, f.key.certify_branch(sibling)?, NOW + 1)?;
    let enrolled = ramflux_crypto::custody::verify_record(&enrolled, NOW + 1, None, None)?;
    state.classify_current(&route(&f), "peer.example", &enrolled, NOW + 1)?;
    let revoked = f.key.revoke_device(&enrolled, &f.actor.device_id, NOW + 2)?;
    let current = ramflux_crypto::custody::verify_record(&revoked, NOW + 2, None, None)?;
    let sibling =
        DeviceRef { account_anchor: f.root.clone(), device_id: "sibling".into(), device_epoch: 1 };
    current.authorize(&sibling, "message", NOW + 2)?;
    let tx = store.begin_write()?;
    let mut saved = account(&tx, &f.root)?;
    saved.pins.observe(&enrolled)?;
    saved.pins.observe(&current)?;
    saved.publication.record = revoked;
    tx.open_table(CUSTODY)?.insert(f.root.as_str(), encoded(&saved)?.as_slice())?;
    tx.commit()?;
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let tx = store.begin_write()?;
    let saved = load(&tx, &f.root)?;
    let authority = authority(&tx, &f.root, NOW + 2)?;
    authority.authorize(&sibling, "message", NOW + 2)?;
    assert_eq!(
        saved.classify(&route(&f), "peer.example", NOW + 2)?.0,
        crate::contact_reach::ReachClass::Accepted,
        "the old signed grant and roster remain present; the control must reach current authority checks"
    );
    assert!(
        saved.classify_current(&route(&f), "peer.example", &authority, NOW + 2).is_err(),
        "a live sibling cannot reactivate policy/grants approved by the now-revoked original primary"
    );
    assert_eq!(
        saved.records()?,
        state.records()?,
        "authority revocation must fence use without rewriting or forging original recipient decisions"
    );
    Ok(())
}

#[test]
fn cr_volatile_source_home_binding_requires_prior_recipient_adoption() -> TestResult {
    use crate::contact_reach::store::require_adopted_source_home;
    let dir = tempfile::TempDir::new()?;
    let (store, f) = initialize(&dir.path().join("volatile-home-binding.redb"))?;
    let recipient = digest(83);
    let home = {
        let tx = store.begin_write()?;
        home(&tx, &f.root)?
    };
    let peer_node = home.record.home().0.to_owned();
    let read = store.migration_db().begin_read()?;
    assert!(
        require_adopted_source_home(&read, &recipient, &f.authority, &peer_node).is_err(),
        "an unrelated known custody key cannot bootstrap volatile peer trust"
    );
    drop(read);
    let mut pins = ramflux_crypto::custody::AuthorityPins::default();
    pins.observe(&f.authority)?;
    let adopted = AdoptedPeer {
        home,
        authority_pins: pins,
        custodian_pins: ramflux_crypto::custody::AuthorityPins::default(),
    };
    let bytes = encoded(&adopted)?;
    let trust_key = key(&recipient, &f.root)?;
    let tx = store.begin_write()?;
    tx.open_table(TRUST)?.insert(trust_key.as_str(), bytes.as_slice())?;
    tx.commit()?;
    let read = store.migration_db().begin_read()?;
    require_adopted_source_home(&read, &recipient, &f.authority, &peer_node)?;
    assert!(
        require_adopted_source_home(&read, &recipient, &f.authority, "other.example").is_err(),
        "a valid W cannot be relayed through another authenticated node to bypass a node denial"
    );
    assert!(
        require_adopted_source_home(&read, &digest(84), &f.authority, &peer_node).is_err(),
        "another recipient's adoption cannot grant this recipient volatile authority"
    );
    assert_eq!(
        read.open_table(TRUST)?.get(trust_key.as_str())?.ok_or("adopted row")?.value(),
        bytes.as_slice(),
        "volatile success and refusal must preserve the exact adopted row"
    );
    Ok(())
}

#[test]
fn cr_volatile_recipient_home_check_refuses_a_moved_home() -> TestResult {
    use crate::contact_reach::store::require_ephemeral_local_home;
    let dir = tempfile::TempDir::new()?;
    let (store, f) = initialize(&dir.path().join("volatile-local-home.redb"))?;
    let home = {
        let tx = store.begin_write()?;
        home(&tx, &f.root)?
    };
    let own_node = home.record.home().0.to_owned();
    let node = crate::MigrationNode::new(
        home.node_record,
        [8; 32],
        crate::MigrationEndpoints {
            gateway_tcp_addr: format!("{own_node}:443"),
            federation_endpoint: format!("https://{own_node}"),
            discovery_hash: digest(85),
            server_record_hash: digest(86),
        },
        NOW,
    )?;
    let read = store.migration_db().begin_read()?;
    require_ephemeral_local_home(&read, &node, &f.root)?;
    assert!(
        require_ephemeral_local_home(&read, &node, &digest(87)).is_err(),
        "a cached target device alone cannot establish that its receiving home is local"
    );
    drop(read);
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?;
    let moved: ramflux_protocol::home_migration::RecordEvidence = serde_json::from_value(
        vector.get("committed_home").ok_or("committed move vector")?.clone(),
    )?;
    let tx = store.begin_write()?;
    tx.open_table(HEADS)?.insert(f.root.as_str(), encoded(&moved)?.as_slice())?;
    tx.commit()?;
    let read = store.migration_db().begin_read()?;
    assert!(
        require_ephemeral_local_home(&read, &node, &f.root).is_err(),
        "the old home must stop volatile publication even while its custody rows and session still exist"
    );
    Ok(())
}

#[test]
fn cr_group_roster_op_and_expired_retry_use_exact_command_identity() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let (store, f) = initialize(&dir.path().join("roster-command.redb"))?;
    install_live_group(&store, &f)?;
    let tx = store.begin_write()?;
    let original =
        load(&tx, &f.root)?.rosters.get(&subject(100).key()?).ok_or("retained roster")?.clone();
    drop(tx);
    let applied = OperationResult::GroupRoster { group_epoch: 100, outcome: Applied::Applied };
    assert_eq!(
        store.reach_group_roster(owner(&f), &digest(51), &original, NOW + 301)?,
        applied,
        "a lost committed response remains recoverable after the submission window"
    );
    let mut fresh = original.clone();
    fresh.header.body.issued_at = NOW + 301;
    fresh.header = f.key.sign_group_roster_header(fresh.header.body, &f.authority, NOW + 301)?;
    assert!(
        matches!(
            store.reach_group_roster(owner(&f), &digest(51), &fresh, NOW + 301),
            Err(crate::contact_reach::ReachError::Refused(Reason::IdempotencyConflict))
        ),
        "changing any complete operation bytes while the dedup row lives must conflict"
    );
    assert!(
        matches!(
            store.reach_group_roster(owner(&f), &digest(51), &original, NOW + 361),
            Err(crate::contact_reach::ReachError::Refused(Reason::ReachCommandExpired))
        ),
        "an expired command cannot be reapplied after dedup retention"
    );
    assert_eq!(
        store.reach_group_roster(owner(&f), &digest(52), &fresh, NOW + 361)?,
        OperationResult::GroupRoster { group_epoch: 100, outcome: Applied::Duplicate },
        "a fresh command with equal grant and membership hashes keeps the old roster"
    );
    let tx = store.begin_write()?;
    let state = load(&tx, &f.root)?;
    assert_eq!(
        state.rosters.get(&subject(100).key()?),
        Some(&original),
        "fresh duplicate bookkeeping cannot replace the original signed roster"
    );
    assert_eq!(state.admission_revision, 1, "roster commands never sign or advance consent");
    drop(tx);
    store.reach_owner_commit(
        owner(&f),
        &decision(&f, 53, subject(101), 1, Decision::Revoke, NOW + 361)?,
        NOW + 361,
    )?;
    assert!(
        matches!(
            store.reach_group_roster(owner(&f), &digest(54), &fresh, NOW + 361),
            Err(crate::contact_reach::ReachError::Refused(Reason::ForeignReadRefused))
        ),
        "bookkeeping cannot recreate a retired group grant"
    );
    Ok(())
}

#[test]
fn cr_reach_error_lifting_preserves_uncertainty_at_roster_commit() -> TestResult {
    use crate::contact_reach::store::rosters::fault;
    use crate::contact_reach::{ReachService, ReachSession};
    for point in [fault::Point::BeforeCommit, fault::Point::AfterCommit] {
        let dir = tempfile::TempDir::new()?;
        let (store, f) = initialize(&dir.path().join("roster-fault.redb"))?;
        install_live_group(&store, &f)?;
        let tx = store.begin_write()?;
        let home = home(&tx, &f.root)?;
        let mut state = load(&tx, &f.root)?;
        let roster = state.rosters.get(&subject(100).key()?).ok_or("roster")?.clone();
        state.rosters.clear();
        save(&tx, &f.root, &state)?;
        tx.commit()?;
        let node_id = home.record.home().0.to_owned();
        let node = crate::MigrationNode::new(
            home.node_record,
            [8; 32],
            crate::MigrationEndpoints {
                gateway_tcp_addr: format!("{node_id}:443"),
                federation_endpoint: format!("https://{node_id}"),
                discovery_hash: digest(85),
                server_record_hash: digest(86),
            },
            NOW,
        )?;
        let service = ReachService::new(node)?;
        let request = ramflux_protocol::contact_reach::Request {
            request_id: digest(90),
            session_id: "phone-session".into(),
            session_generation: 1,
            remaining_ms: 1000,
            operation: Operation::GroupRoster {
                operation_id: digest(91),
                roster: Box::new(roster),
            },
        };
        let session = ReachSession { actor: &f.actor, id: "phone-session", generation: 1 };
        {
            let _fault = fault::arm(point);
            let response = service.owner(&store, session, &request, NOW);
            assert_eq!(
                response.result,
                OperationResult::Error {
                    reason: Reason::ForeignStorageUnavailable,
                    retry_after_ms: None,
                    current_revision: None,
                },
                "both sides of commit must produce the same uncertain storage answer"
            );
            request.validate_response(&response)?;
        }
        let tx = store.begin_write()?;
        assert_eq!(
            load(&tx, &f.root)?.rosters.len(),
            usize::from(point == fault::Point::AfterCommit),
            "the injected failure must straddle the actual durable commit point"
        );
        drop(tx);
        let retry = service.owner(&store, session, &request, NOW);
        assert_eq!(
            retry.result,
            OperationResult::GroupRoster { group_epoch: 100, outcome: Applied::Applied },
            "a pre-commit fault retries the write; an after-commit fault returns its original result"
        );
        let tx = store.begin_write()?;
        assert_eq!(
            load(&tx, &f.root)?.rosters.len(),
            1,
            "the retry must leave exactly one derived roster"
        );
        drop(tx);
        let Operation::GroupRoster { roster, .. } = &request.operation else {
            return Err("roster request".into());
        };
        assert_eq!(
            store.reach_group_roster(owner(&f), &digest(92), roster, NOW)?,
            OperationResult::GroupRoster { group_epoch: 100, outcome: Applied::Duplicate },
            "a second operation proves the roster was really persisted"
        );
        let mut unauthenticated = f.actor.clone();
        unauthenticated.device_id = "unregistered-web".into();
        let refused = service.owner(
            &store,
            ReachSession { actor: &unauthenticated, id: "phone-session", generation: 1 },
            &request,
            NOW,
        );
        assert_eq!(
            refused.result,
            OperationResult::Error {
                reason: Reason::CustodyRefused,
                retry_after_ms: None,
                current_revision: None,
            },
            "management authority failure is a definite custody refusal, even for a known operation"
        );
    }
    Ok(())
}

#[test]
fn cr_nonempty_reach_state_refuses_home_activation() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let (store, f) = initialize(&dir.path().join("migration-reach.redb"))?;
    {
        let tx = store.begin_write()?;
        crate::contact_reach::require_empty_reach_activation(&tx, &f.root)?;
    }
    install_live_group(&store, &f)?;
    let tx = store.begin_write()?;
    assert!(
        matches!(
            crate::contact_reach::require_empty_reach_activation(&tx, &f.root),
            Err(crate::NodeCoreError::ContactReachRefused(Reason::HomeEvidenceRequired))
        ),
        "a destination cannot activate an existing reach account without its state-transfer module"
    );
    assert_eq!(
        load(&tx, &f.root)?.grants.len(),
        1,
        "the refusal leaves existing signed permission state unchanged"
    );
    Ok(())
}

#[test]
fn cr_group_duplicate_preserves_original_header_signer_reference_after_native_advance() -> TestResult
{
    let dir = tempfile::TempDir::new()?;
    let (store, mut f) = initialize(&dir.path().join("duplicate-original-header.redb"))?;
    let node = super::costs::issuer(&store, &f)?;
    f.home = {
        let tx = store.begin_write()?;
        ramflux_protocol::home_migration::record_hash(&home(&tx, &f.root)?.record)?
    };
    install_live_group(&store, &f)?;
    let original = {
        let tx = store.begin_write()?;
        load(&tx, &f.root)?.rosters.get(&subject(100).key()?).ok_or("original roster")?.clone()
    };
    let next = renewed_primary(&f, NOW + 3601)?;
    let tx = store.begin_write()?;
    let mut native = account(&tx, &f.root)?;
    native.pins.observe(&next)?;
    native.publication.record = next.envelope().clone();
    tx.open_table(CUSTODY)?.insert(f.root.as_str(), encoded(&native)?.as_slice())?;
    tx.commit()?;
    f.authority = next;
    let mut header = original.header.body.clone();
    header.authority_head_hash = custody::object_hash(f.authority.envelope())?;
    header.issued_at = NOW + 1;
    let attempted = GroupRoster {
        header: f.key.sign_group_roster_header(header, &f.authority, NOW + 1)?,
        members: original.members.clone(),
    };
    let result = store.reach_group_roster(owner(&f), &digest(95), &attempted, NOW + 1)?;
    assert!(
        matches!(result, OperationResult::GroupRoster { outcome: Applied::Duplicate, .. }),
        "same roster tuple stays duplicate even when the new valid command uses another native head"
    );
    let retained = {
        let tx = store.begin_write()?;
        load(&tx, &f.root)?.rosters.get(&subject(100).key()?).ok_or("retained roster")?.clone()
    };
    assert_eq!(
        retained, original,
        "duplicate processing must retain the exact original header and signature"
    );
    store.reach_owner_commit(
        owner(&f),
        &decision(&f, 96, subject(101), 1, Decision::Revoke, NOW + 2)?,
        NOW + 2,
    )?;
    let service = crate::contact_reach::ReachService::new(node)?;
    let state = super::provenance::call(
        &service,
        &store,
        &f,
        Operation::ReachState { known_revision: 0, snapshot_id: None, page: 0 },
        NOW + 2,
    );
    let OperationResult::ReachState { manifest, page } = state else {
        return Err(format!("owner state: {state:?}").into());
    };
    let object_hash = custody::framed_hash(OPERATION_HASH_DOMAIN, &original.header)?;
    let reference = page
        .signers
        .iter()
        .find(|reference| {
            reference.object_kind == ramflux_protocol::contact_reach::ObjectKind::GroupRoster
                && reference.object_hash == object_hash
        })
        .ok_or("original header reference")?;
    let proof = super::provenance::call(
        &service,
        &store,
        &f,
        Operation::ReachProvenance {
            snapshot_id: manifest.body.snapshot_id,
            proof_hash: reference.proof_hash.clone(),
        },
        NOW + 2,
    );
    let OperationResult::ReachProvenance { authority, .. } = proof else {
        return Err(format!("owner proof: {proof:?}").into());
    };
    assert_eq!(
        custody::object_hash(&authority.publication.record)?,
        original.header.body.authority_head_hash,
        "retirement proof selects the stored header's original native context, never the duplicate attempt's signer"
    );
    assert_ne!(
        original.header.body.authority_head_hash, attempted.header.body.authority_head_hash,
        "the control must use two distinct genuinely signed native heads"
    );
    Ok(())
}
