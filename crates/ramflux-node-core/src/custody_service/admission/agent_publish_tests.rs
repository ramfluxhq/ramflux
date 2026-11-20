// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `AgentPublish` through the real admission path. Every agent object is built with the real
//! crypto genesis, profile and decision signers; no check is mocked.

use crate::custody_authority::CustodyAccountState;
use crate::tests::custody_sessions::Driver;
use crate::{CustodyPublication, CustodyService, RouterCore, RouterRedbStore};
use ramflux_crypto::custody::{
    GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey, create_genesis,
    sign_register_decision, verify_record,
};
use ramflux_protocol::agent_profile::{AgentProfileEnvelope, AgentProfileV1};
use ramflux_protocol::custody::{
    AgentDecisionRequest, AgentPublishReceipt, AgentRegisterProfile, CustodyProofAction,
    CustodyRefusal, CustodyServerFrame, DeviceRef, DeviceSet, Envelope,
    GENESIS_BRANCH_CAPABILITIES, RegisterDecision, RegisterOutcome, RegisterPlan, RegisterPurpose,
    encode_register_plan, object_hash, register_decision_body, register_plan_hash,
};
use ramflux_protocol::{PrincipalKind, domain, encode_base64url};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const NOW: u64 = 1_760_000_000;
const HUMAN_PRINCIPAL: &str = "agent-human";
const HUMAN_SEED: u8 = 10;
const AGENT_PRINCIPAL: &str = "agent-principal";
const AGENT_SEED: u8 = 40;
const REQUEST_ID: &str = "agent-request-1";

fn human_branch() -> ramflux_crypto::DeviceBranch {
    ramflux_crypto::create_device_branch(HUMAN_PRINCIPAL, "primary", 1, [HUMAN_SEED + 2; 32])
}

fn agent_branch() -> ramflux_crypto::DeviceBranch {
    ramflux_crypto::create_device_branch(AGENT_PRINCIPAL, "primary", 1, [AGENT_SEED + 2; 32])
}

fn agent_record(human_primary: DeviceRef) -> Result<Envelope<DeviceSet>> {
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[AGENT_SEED; 32])?)?;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([AGENT_SEED + 1; 32]));
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([AGENT_SEED + 3; 32]);
    Ok(create_genesis(
        &master,
        &primary,
        &agent_branch(),
        &agreement,
        GenesisInput {
            principal_kind: PrincipalKind::HeadlessAi,
            display_name: "Helper".into(),
            issued_at: NOW,
            master_cert_id: encode_base64url([AGENT_SEED + 4; 32]),
            branch_cert_id: encode_base64url([AGENT_SEED + 5; 32]),
            external_human_primary: Some(human_primary),
        },
    )?)
}

/// Everything one test needs: a real store, router and service with a human custodian
/// published through the real path, and an agent driver whose record is not yet published.
struct Fixture {
    store: RouterRedbStore,
    router: RouterCore,
    service: CustodyService,
    agent: Driver,
    profile: AgentProfileEnvelope,
    plan: RegisterPlan,
}

fn fixture(name: &str) -> Result<Fixture> {
    let path =
        ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(
            format!("agent-publish-{name}-{}.redb", encode_base64url(ramflux_crypto::random_32()?)),
        );
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.bootstrap_router(&router)?;
    let human = Driver::new(HUMAN_PRINCIPAL, HUMAN_SEED)?;
    let service = CustodyService::new(human.node.clone(), false, &store, NOW)?;
    assert!(matches!(
        human.run(&service, &router, &store, human.publish())?,
        CustodyServerFrame::Published { .. }
    ));
    let human_primary = human.reference.clone();
    let record = agent_record(human_primary.clone())?;
    let agent_anchor = record.body.account_anchor.clone();
    let agent_reference = DeviceRef {
        account_anchor: agent_anchor.clone(),
        device_id: "primary".into(),
        device_epoch: 1,
    };
    let agent = Driver::from_parts(
        CustodyPublication { record: record.clone(), compacted_ids: None },
        agent_branch(),
        agent_reference.clone(),
        AGENT_SEED,
    )?;
    let human_verified = verify_record(&human.publication.record, NOW, None, None)?;
    let agent_verified = verify_record(&record, NOW, None, Some(&human_verified))?;
    let device = &record.body.devices[0];
    let branch = &device.branch_certificate.as_ref().ok_or("agent branch")?.body;
    let master = &record.body.master_certificate.body;
    let body = AgentProfileV1 {
        schema: domain::AGENT_PROFILE.into(),
        version: 1,
        agent_anchor: agent_anchor.clone(),
        agent_custody_hash: object_hash(&record)?,
        custodian_anchor: human_primary.account_anchor.clone(),
        custodian_primary: human_primary.clone(),
        kind: "headless_ai".into(),
        profile_epoch: 1,
        responsibility: "Research".into(),
        provider: "local".into(),
        model: "model".into(),
        persona_version: 1,
        persona_hash: encode_base64url([7; 32]),
    };
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([AGENT_SEED + 1; 32]));
    let profile = primary.sign_agent_profile(body, &agent_verified, &human_verified, NOW)?;
    let plan = RegisterPlan {
        schema: ramflux_protocol::custody::REGISTER_PLAN_SCHEMA.into(),
        version: 1,
        request_id: REQUEST_ID.into(),
        purpose: RegisterPurpose::Create,
        owner_anchor: human_primary.account_anchor.clone(),
        human_head_hash: object_hash(&human.publication.record)?,
        human_primary: human_primary.clone(),
        desktop: DeviceRef {
            account_anchor: human_primary.account_anchor.clone(),
            device_id: "desktop".into(),
            device_epoch: 1,
        },
        agent_anchor,
        principal_id: AGENT_PRINCIPAL.into(),
        agent_device: agent_reference,
        master_public_key: master.master_public_key.clone(),
        self_signing_public_key: master.self_signing_public_key.clone(),
        branch_signing_public_key: branch.branch_signing_public_key.clone(),
        agreement_public_key: branch.agreement_identity_public_key.clone(),
        capabilities: GENESIS_BRANCH_CAPABILITIES.iter().map(|c| (*c).to_owned()).collect(),
        display_name: "Helper".into(),
        certificate_issued_at: master.issued_at,
        branch_not_before: branch.not_before,
        branch_expires_at: branch.expires_at,
        master_cert_id: master.cert_id.clone(),
        branch_cert_id: branch.cert_id.clone(),
        profile: AgentRegisterProfile {
            responsibility: "Research".into(),
            provider: "local".into(),
            model: "model".into(),
            persona_version: 1,
            persona_hash: encode_base64url([7; 32]),
            profile_epoch: 1,
        },
        issued_at: NOW,
        expires_at: NOW + 300,
        previous_agent_head_hash: None,
        previous_master_certificate_hash: None,
        next_range: 1,
    };
    Ok(Fixture { store, router, service, agent, profile, plan })
}

/// Decision signed by the human primary branch over the exact bytes of `plan`.
fn decide(
    plan: &RegisterPlan,
    outcome: RegisterOutcome,
    issued: u64,
    expires: u64,
) -> Result<RegisterDecision> {
    Ok(ramflux_crypto::custody::sign_register_decision_request(
        &human_branch(),
        &AgentDecisionRequest {
            plan_bytes: encode_register_plan(plan)?,
            plan_hash: register_plan_hash(plan)?,
            decision: outcome,
            signer: plan.human_primary.clone(),
            issued_at: issued,
            expires_at: expires,
        },
    )?)
}

fn publish_action(
    record: &Envelope<DeviceSet>,
    profile: &AgentProfileEnvelope,
    plan: &RegisterPlan,
    decision: RegisterDecision,
) -> CustodyProofAction {
    CustodyProofAction::AgentPublish {
        publication: Box::new(ramflux_protocol::custody::Publication {
            record: record.clone(),
            compacted_ids: None,
        }),
        agent_profile: Box::new(profile.clone()),
        plan: Box::new(plan.clone()),
        authorization: Box::new(decision),
    }
}

fn refused(frame: &CustodyServerFrame, code: CustodyRefusal) -> bool {
    *frame == CustodyServerFrame::Refused { code, capacity: None, retry: None }
}

fn assert_nothing_written(fx: &Fixture) -> Result {
    assert!(fx.router.custody_record(&fx.agent.reference.account_anchor, NOW)?.is_none());
    assert!(fx.store.agent_publish_by_request(REQUEST_ID)?.is_none());
    Ok(())
}

/// Decision-level refusals: a bad plan hash, a non-primary signer, deny, and bad windows.
fn decision_refusal_cases(
    fx: &Fixture,
    record: &Envelope<DeviceSet>,
    good: &RegisterDecision,
) -> Result<Vec<(&'static str, CustodyProofAction, CustodyRefusal)>> {
    // Bad plan hash: the decision names a different plan.
    let mut bad_hash = good.clone();
    bad_hash.body.request_hash = encode_base64url([0x21; 32]);
    let cases: Vec<(&str, CustodyProofAction, CustodyRefusal)> = vec![
        (
            "bad plan hash",
            publish_action(record, &fx.profile, &fx.plan, bad_hash),
            CustodyRefusal::InvalidInput,
        ),
        (
            "decision signed by a non-primary",
            {
                let request = AgentDecisionRequest {
                    plan_bytes: encode_register_plan(&fx.plan)?,
                    plan_hash: register_plan_hash(&fx.plan)?,
                    decision: RegisterOutcome::Approve,
                    signer: fx.plan.human_primary.clone(),
                    issued_at: NOW,
                    expires_at: NOW + 300,
                };
                let body = register_decision_body(&request)?;
                let signed = sign_register_decision(&agent_branch(), body)?;
                publish_action(record, &fx.profile, &fx.plan, signed)
            },
            CustodyRefusal::BindingRefused,
        ),
        (
            "deny decision",
            publish_action(
                record,
                &fx.profile,
                &fx.plan,
                decide(&fx.plan, RegisterOutcome::Deny, NOW, NOW + 300)?,
            ),
            CustodyRefusal::InvalidInput,
        ),
        (
            "expired decision",
            publish_action(
                record,
                &fx.profile,
                &fx.plan,
                decide(&fx.plan, RegisterOutcome::Approve, NOW - 400, NOW - 100)?,
            ),
            CustodyRefusal::InvalidInput,
        ),
        (
            "decision not yet valid",
            publish_action(
                record,
                &fx.profile,
                &fx.plan,
                decide(&fx.plan, RegisterOutcome::Approve, NOW + 10, NOW + 200)?,
            ),
            CustodyRefusal::InvalidInput,
        ),
    ];
    Ok(cases)
}

/// Plan-level refusals: each changed field is re-signed, so only its own check refuses.
fn plan_refusal_cases(
    fx: &Fixture,
    record: &Envelope<DeviceSet>,
) -> Result<Vec<(&'static str, CustodyProofAction, CustodyRefusal)>> {
    let other_anchor = encode_base64url([0x77; 32]);
    let other_key = encode_base64url([0x99; 32]);
    let other_head = encode_base64url([0x55; 32]);
    let mut wrong_anchor = fx.plan.clone();
    wrong_anchor.agent_anchor = other_anchor.clone();
    wrong_anchor.agent_device.account_anchor = other_anchor;
    let mut wrong_key = fx.plan.clone();
    wrong_key.master_public_key = other_key;
    let mut stale_head = fx.plan.clone();
    stale_head.human_head_hash = other_head;
    let mut wrong_signer = fx.plan.clone();
    wrong_signer.human_primary.device_id = "secondary".into();
    let mut rebind_on_new = fx.plan.clone();
    rebind_on_new.purpose = RegisterPurpose::Rebind;
    rebind_on_new.previous_agent_head_hash = Some(encode_base64url([0x11; 32]));
    rebind_on_new.previous_master_certificate_hash = Some(encode_base64url([0x12; 32]));
    rebind_on_new.next_range = 2;

    let cases: Vec<(&str, CustodyProofAction, CustodyRefusal)> = vec![
        (
            "anchor differs from the record",
            publish_action(
                record,
                &fx.profile,
                &wrong_anchor,
                decide(&wrong_anchor, RegisterOutcome::Approve, NOW, NOW + 300)?,
            ),
            CustodyRefusal::InvalidInput,
        ),
        (
            "master key differs from the record",
            publish_action(
                record,
                &fx.profile,
                &wrong_key,
                decide(&wrong_key, RegisterOutcome::Approve, NOW, NOW + 300)?,
            ),
            CustodyRefusal::InvalidInput,
        ),
        (
            "stale human head",
            publish_action(
                record,
                &fx.profile,
                &stale_head,
                decide(&stale_head, RegisterOutcome::Approve, NOW, NOW + 300)?,
            ),
            CustodyRefusal::InvalidInput,
        ),
        (
            "custodian device differs",
            publish_action(
                record,
                &fx.profile,
                &wrong_signer,
                decide(&wrong_signer, RegisterOutcome::Approve, NOW, NOW + 300)?,
            ),
            CustodyRefusal::BindingRefused,
        ),
        (
            "rebind on a new anchor",
            publish_action(
                record,
                &fx.profile,
                &rebind_on_new,
                decide(&rebind_on_new, RegisterOutcome::Approve, NOW, NOW + 300)?,
            ),
            CustodyRefusal::InvalidInput,
        ),
    ];
    Ok(cases)
}

#[test]
fn agent_publish_accepts_a_create_and_refuses_each_decision_check_on_its_own() -> Result {
    let fx = fixture("refusals")?;
    let record = fx.agent.publication.record.clone();
    let good = decide(&fx.plan, RegisterOutcome::Approve, NOW, NOW + 300)?;
    let mut cases = decision_refusal_cases(&fx, &record, &good)?;
    cases.extend(plan_refusal_cases(&fx, &record)?);
    for (name, action, code) in cases {
        let frame = fx.agent.run(&fx.service, &fx.router, &fx.store, action)?;
        assert!(refused(&frame, code.clone()), "{name}: expected {code:?}, got {frame:?}");
        assert_nothing_written(&fx)?;
    }

    // Accepted create, with the genuine plan, decision and profile.
    let action = publish_action(&record, &fx.profile, &fx.plan, good.clone());
    let frame = fx.agent.run(&fx.service, &fx.router, &fx.store, action.clone())?;
    let CustodyServerFrame::AgentPublished { receipt } = frame else {
        return Err(format!("create refused: {frame:?}").into());
    };
    assert_eq!(receipt.request_hash, register_plan_hash(&fx.plan)?);
    assert_eq!(receipt.record_hash, object_hash(&record)?);
    assert_eq!(receipt.custodian_primary, fx.plan.human_primary);
    assert!(fx.router.custody_record(&fx.agent.reference.account_anchor, NOW)?.is_some());

    // Exact replay returns the stored receipt with no second write.
    let replay = fx.agent.run(&fx.service, &fx.router, &fx.store, action)?;
    assert_eq!(replay, CustodyServerFrame::AgentPublished { receipt: receipt.clone() });

    // Same request identifier with another record refuses; the stored receipt is untouched.
    let mut other_record_body = record.body.clone();
    other_record_body.issued_at = NOW - 1;
    let other_record = SelfSigningKey::from_vault_seed(&Zeroizing::new([AGENT_SEED + 1; 32]))
        .sign_record(other_record_body)?;
    // The branch proof binds the record hash, so the other record needs its own driver.
    let other_driver = Driver::from_parts(
        CustodyPublication { record: other_record.clone(), compacted_ids: None },
        agent_branch(),
        fx.agent.reference.clone(),
        AGENT_SEED + 1,
    )?;
    let conflict = other_driver.run(
        &fx.service,
        &fx.router,
        &fx.store,
        publish_action(&other_record, &fx.profile, &fx.plan, good),
    )?;
    assert!(refused(&conflict, CustodyRefusal::IdempotencyConflict), "{conflict:?}");
    assert_eq!(
        fx.store.agent_publish_by_request(REQUEST_ID)?.map(|row| row.receipt),
        Some(*receipt)
    );
    Ok(())
}

#[test]
fn plain_publish_refuses_a_new_headless_record_and_accepts_the_unchanged_one() -> Result {
    let fx = fixture("plain-publish")?;
    let record = fx.agent.publication.record.clone();
    let plain = CustodyProofAction::Publish {
        publication: Box::new(ramflux_protocol::custody::Publication {
            record: record.clone(),
            compacted_ids: None,
        }),
    };
    let frame = fx.agent.run(&fx.service, &fx.router, &fx.store, plain.clone())?;
    assert!(refused(&frame, CustodyRefusal::AgentAuthorizationRequired), "{frame:?}");
    assert_nothing_written(&fx)?;

    let good = decide(&fx.plan, RegisterOutcome::Approve, NOW, NOW + 300)?;
    assert!(matches!(
        fx.agent.run(
            &fx.service,
            &fx.router,
            &fx.store,
            publish_action(&record, &fx.profile, &fx.plan, good)
        )?,
        CustodyServerFrame::AgentPublished { .. }
    ));
    // The same custodian primary: an ordinary publication of the unchanged record still succeeds.
    assert!(matches!(
        fx.agent.run(&fx.service, &fx.router, &fx.store, plain)?,
        CustodyServerFrame::Published { .. }
    ));
    Ok(())
}

#[test]
fn consumed_authorization_and_directory_record_commit_together_or_not_at_all() -> Result {
    let fx = fixture("atomic")?;
    let record = fx.agent.publication.record.clone();
    let anchor = fx.agent.reference.account_anchor.clone();
    let state = CustodyAccountState {
        publication: CustodyPublication { record: record.clone(), compacted_ids: None },
        pins: ramflux_crypto::custody::AuthorityPins::default(),
    };
    let receipt = AgentPublishReceipt {
        request_id: "atomic-row".into(),
        request_hash: encode_base64url([1; 32]),
        record_hash: object_hash(&record)?,
        profile_hash: object_hash(&fx.profile)?,
        custodian_head_hash: encode_base64url([2; 32]),
        custodian_primary: fx.plan.human_primary.clone(),
        accepted_at: NOW,
    };
    let row = crate::router_store::StoredAgentPublish {
        request_hash: receipt.request_hash.clone(),
        record_hash: receipt.record_hash.clone(),
        decision_hash: encode_base64url([3; 32]),
        receipt: receipt.clone(),
    };
    // A directory write that refuses inside the transaction leaves no authorization row.
    let tx = fx.store.begin_write()?;
    RouterRedbStore::record_agent_publish_in_tx(&tx, "atomic-row", &row)?;
    let refused_write = fx.store.record_custody_account_in_tx(
        &tx,
        crate::router_store::CustodyAccountWrite {
            anchor: &anchor,
            state: &state,
            expected: Some(&state),
            is_new: false,
            source: "192.0.2.1".parse()?,
            now: NOW,
        },
    );
    assert!(refused_write.is_err(), "a mismatched expected state must refuse");
    drop(tx);
    assert!(fx.store.agent_publish_by_request("atomic-row")?.is_none());
    assert!(fx.router.custody_record(&anchor, NOW)?.is_none());

    // An authorization row that already consumed the decision refuses the whole write.
    let tx = fx.store.begin_write()?;
    RouterRedbStore::record_agent_publish_in_tx(&tx, "first", &row)?;
    let reused = RouterRedbStore::record_agent_publish_in_tx(&tx, "second", &row);
    assert!(reused.is_err(), "a second request may not consume the same decision");
    drop(tx);
    assert!(fx.store.agent_publish_by_request("first")?.is_none());
    assert!(fx.store.agent_publish_by_request("second")?.is_none());
    Ok(())
}

#[test]
fn saved_receipt_is_read_back_after_restart() -> Result {
    let fx = fixture("restart")?;
    let record = fx.agent.publication.record.clone();
    let good = decide(&fx.plan, RegisterOutcome::Approve, NOW, NOW + 300)?;
    let frame = fx.agent.run(
        &fx.service,
        &fx.router,
        &fx.store,
        publish_action(&record, &fx.profile, &fx.plan, good),
    )?;
    let CustodyServerFrame::AgentPublished { receipt } = frame else {
        return Err("create refused".into());
    };
    let row = fx.store.agent_publish_by_request(REQUEST_ID)?.ok_or("row missing")?;
    assert_eq!(row.receipt, *receipt);
    let reloaded = fx.store.load_router()?.ok_or("router")?;
    assert!(reloaded.custody_record(&fx.agent.reference.account_anchor, NOW)?.is_some());
    Ok(())
}

#[test]
fn agent_publish_capability_name_is_the_advertised_one() {
    assert_eq!(
        ramflux_protocol::AGENT_CUSTODY_AUTHORIZATION_CAPABILITY,
        "agent_custody_authorization_v1"
    );
}
