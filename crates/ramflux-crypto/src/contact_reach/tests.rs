// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current human and managed-agent authority, separate from transport branch possession.
use super::*;
use crate::custody::{GenesisInput, MasterKey, RecoveryPhrase, create_genesis, verify_record};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_000;
fn d(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
struct Account {
    key: SelfSigningKey,
    record: VerifiedRecord,
    branch: DeviceBranch,
}
fn account(seed: u8, human: Option<&Account>) -> TestResult<Account> {
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[seed; 32])?)?;
    let key = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([seed + 1; 32]));
    let branch = crate::create_device_branch("vector.example", "primary", 1, [seed + 2; 32]);
    let reference =
        human.map(|a| a.record.envelope().body.master_certificate.body.primary_device_ref.clone());
    let record = create_genesis(
        &master,
        &key,
        &branch,
        &crate::X25519KeyPair::from_seed([seed + 3; 32]),
        GenesisInput {
            principal_kind: if human.is_some() {
                ramflux_protocol::PrincipalKind::HeadlessAi
            } else {
                ramflux_protocol::PrincipalKind::Human
            },
            display_name: "Reach test".into(),
            issued_at: NOW,
            master_cert_id: d(seed + 4),
            branch_cert_id: d(seed + 5),
            external_human_primary: reference,
        },
    )?;
    let record = verify_record(&record, NOW, None, human.map(|a| &a.record))?;
    Ok(Account { key, record, branch })
}
fn policy(a: &Account) -> TestResult<wire::ReachPolicy> {
    let record = a.record.envelope();
    Ok(wire::ReachPolicy {
        version: 1,
        operation_id: d(71),
        account_anchor: record.body.account_anchor.clone(),
        home_head_hash: d(72),
        expected_revision: 0,
        revision: 1,
        mode: wire::ReachMode::ContactsOnly,
        authority_head_hash: custody::object_hash(record)?,
        master_certificate_hash: custody::object_hash(&record.body.master_certificate)?,
        actor: record.body.master_certificate.body.primary_device_ref.clone(),
        issued_at: NOW,
        expires_at: NOW + 300,
    })
}
#[test]
fn cr_policy_requires_certified_primary_and_retained_policy_outlives_submission_window()
-> TestResult {
    let human = account(10, None)?;
    let signed = human.key.sign_reach_policy(policy(&human)?, &human.record, NOW)?;
    verify_policy(&signed, &human.record, &d(72), &signed.body.actor, NOW)?;
    assert!(
        verify_policy(&signed, &human.record, &d(72), &signed.body.actor, NOW + 300).is_err(),
        "an expired command cannot be submitted again as a new mutation"
    );
    verify_retained_policy(&signed, &human.record, NOW + 301)?;
    let mut forged = signed.clone();
    forged.signature = crate::sign_canonical_bytes_with_seed(
        &custody::signing_bytes(wire::POLICY_DOMAIN, &forged.body)?,
        [12; 32],
    );
    assert!(
        verify_policy(&forged, &human.record, &d(72), &forged.body.actor, NOW).is_err(),
        "valid transport branch possession cannot sign receiving policy"
    );
    let mut actor = signed.body.actor.clone();
    actor.device_id = "linked browser".into();
    assert!(
        verify_policy(&signed, &human.record, &d(72), &actor, NOW).is_err(),
        "a linked session cannot courier primary management intent as its own action"
    );
    let mut changed = signed.clone();
    changed.body.mode = wire::ReachMode::Open;
    assert!(
        verify_policy(&changed, &human.record, &d(72), &changed.body.actor, NOW).is_err(),
        "policy mode substitution must invalidate the primary signature"
    );
    Ok(())
}
#[test]
fn cr_agent_management_requires_its_current_independently_verified_human_primary() -> TestResult {
    let human = account(20, None)?;
    let agent = account(30, Some(&human))?;
    let signed = agent.key.sign_reach_policy(policy(&agent)?, &agent.record, NOW)?;
    assert_ne!(
        signed.body.actor.account_anchor, signed.body.account_anchor,
        "an agent's approving human and managed account are different roots"
    );
    verify_policy(&signed, &agent.record, &d(72), &signed.body.actor, NOW)?;
    let mut body = signed.body.clone();
    body.actor = DeviceRef {
        account_anchor: body.account_anchor.clone(),
        device_id: agent.branch.device_id.clone(),
        device_epoch: agent.branch.device_epoch,
    };
    assert!(
        agent.key.sign_reach_policy(body, &agent.record, NOW).is_err(),
        "an agent's own branch cannot claim the approving human's management scope"
    );
    let revoked = human.key.revoke_device(&human.record, "primary", NOW + 1)?;
    let revoked = verify_record(&revoked, NOW + 1, None, None)?;
    assert!(
        verify_record(agent.record.envelope(), NOW + 1, None, Some(&revoked)).is_err(),
        "a revoked human custodian must fence new agent management"
    );
    let stranger = account(40, None)?;
    assert!(
        verify_record(agent.record.envelope(), NOW, None, Some(&stranger.record)).is_err(),
        "a body-supplied unrelated human publication cannot establish custody"
    );
    Ok(())
}

fn group_grant(account: &Account) -> TestResult<Signed<wire::Admission>> {
    let record = account.record.envelope();
    let body = wire::Admission {
        version: 2,
        operation_id: d(71),
        recipient_root: record.body.account_anchor.clone(),
        home_head_hash: d(72),
        expected_revision: 0,
        subject: wire::Subject::Group {
            group_id: "group".into(),
            conversation_id: "signed-thread".into(),
            genesis_hash: d(73),
            group_epoch: 10,
            membership_hash: d(74),
        },
        decision: wire::Decision::Allow,
        permissions: Some(wire::Permissions::UNACCEPTED),
        grant_until: Some(0),
        authority_head_hash: custody::object_hash(record)?,
        master_certificate_hash: custody::object_hash(&record.body.master_certificate)?,
        actor: record.body.master_certificate.body.primary_device_ref.clone(),
        notice_hash: Some(d(75)),
        evidence_hash: Some(d(74)),
        issued_at: NOW,
        expires_at: NOW + 300,
    };
    Ok(account.key.sign_reach_admission(body, &account.record, NOW)?)
}
#[test]
fn cr_group_roster_binds_primary_grant_and_nul_framed_members() -> TestResult {
    let owner = account(10, None)?;
    let grant = group_grant(&owner)?;
    let members = vec![wire::GroupRosterMember { root: d(40), since_epoch: 10 }];
    let header = wire::GroupRosterHeader {
        version: 1,
        recipient_root: grant.body.recipient_root.clone(),
        group_id: "group".into(),
        conversation_id: "signed-thread".into(),
        grant_hash: custody::framed_hash(wire::OPERATION_HASH_DOMAIN, &grant)?,
        group_epoch: 10,
        membership_hash: d(74),
        members_hash: custody::framed_hash(wire::GROUP_ROSTER_MEMBERS_DOMAIN, &members)?,
        member_count: 1,
        issued_at: NOW,
    };
    let roster = wire::GroupRoster {
        header: owner.key.sign_group_roster_header(header, &owner.record, NOW)?,
        members,
    };
    verify_group_roster(&roster, &grant, &owner.record, NOW)?;
    let mut forged = roster.clone();
    forged.header.signature = crate::sign_canonical_bytes_with_seed(
        &custody::signing_bytes(wire::GROUP_ROSTER_DOMAIN, &forged.header.body)?,
        [12; 32],
    );
    assert!(
        verify_group_roster(&forged, &grant, &owner.record, NOW).is_err(),
        "a valid device branch cannot sign the primary roster header"
    );
    let mut altered = roster.clone();
    altered.members.first_mut().ok_or("first roster member")?.since_epoch = 9;
    assert!(
        verify_group_roster(&altered, &grant, &owner.record, NOW).is_err(),
        "a changed admission floor cannot borrow a signed members commitment"
    );
    let mut wrong_domain = roster.clone();
    wrong_domain.header.body.members_hash = ramflux_protocol::hash_base64url(
        wire::GROUP_ROSTER_MEMBERS_DOMAIN,
        &ramflux_protocol::canonical_json_bytes(&wrong_domain.members)?,
    )?;
    wrong_domain.header =
        owner.key.sign_group_roster_header(wrong_domain.header.body, &owner.record, NOW)?;
    assert!(
        verify_group_roster(&wrong_domain, &grant, &owner.record, NOW).is_err(),
        "even a primary signature cannot replace the required NUL-framed member hash"
    );
    let mut replacement = grant.body.clone();
    replacement.operation_id = d(76);
    let replacement = owner.key.sign_reach_admission(replacement, &owner.record, NOW)?;
    assert!(
        verify_group_roster(&roster, &replacement, &owner.record, NOW).is_err(),
        "the complete signed allow, including its operation identity, is the live-grant binding"
    );
    Ok(())
}
#[test]
fn cr_group_retirement_verifies_every_original_witness() -> TestResult {
    let owner = account(10, None)?;
    let grant = group_grant(&owner)?;
    let mut negative = grant.body.clone();
    negative.operation_id = d(77);
    negative.expected_revision = 1;
    negative.decision = wire::Decision::Revoke;
    negative.permissions = None;
    negative.grant_until = None;
    negative.notice_hash = None;
    negative.evidence_hash = None;
    if let wire::Subject::Group { group_epoch, .. } = &mut negative.subject {
        *group_epoch = 101;
    }
    let update = owner.key.sign_reach_admission(negative, &owner.record, NOW)?;
    let mut floor = wire::GroupFloor {
        floor_epoch: 101,
        grant: Some(Box::new(grant)),
        roster_header: None,
        block_control: None,
    };
    verify_group_retirement(&update, &floor, &owner.record, NOW + 301)?;
    floor.floor_epoch = 100;
    assert!(
        verify_group_retirement(&update, &floor, &owner.record, NOW + 301).is_err(),
        "the signed kick epoch participates in the one reproducible floor formula"
    );
    floor.floor_epoch = 101;
    floor.grant.as_mut().ok_or("grant witness")?.signature =
        ramflux_protocol::encode_base64url([1; 64]);
    assert!(
        verify_group_retirement(&update, &floor, &owner.record, NOW + 301).is_err(),
        "a historical-looking witness is not trusted without its original certified signature"
    );
    Ok(())
}
