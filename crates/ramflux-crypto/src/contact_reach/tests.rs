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
