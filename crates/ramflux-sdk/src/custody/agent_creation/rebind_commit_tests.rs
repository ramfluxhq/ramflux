// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stage D4 tests of the rebind commit (contract 7.5): the next master range, the recertified
//! branch, the new `DeviceSet` and profile, the refusals, and the replay after a crash.
//!
//! REAL: the agent master (`MemoryPrimaryVault` certify with the previous certificate and the range
//! rules), the agent's self-signing key, the branch recertification, `verify_record` on the new
//! `DeviceSet` against the transferred human record, `verify_agent_profile`, the authority file and
//! its pins (`custody::store::replace_rebound_authority`), and the creation and inventory files.
//! FIXTURE: as in `rebind_plan_tests` (the transferred human record is passed in memory; no node).
//! The "crash before the commit point" is simulated by moving the record back to `authorized` after a
//! completed commit: the authority and the range are already in place, which is the state a crash
//! leaves between the authority write and the commit point.
use super::rebind::RebindBinding;
use super::rebind_plan_tests::{
    REQUEST_REBIND, Rebind, begin, new_primary_decision, now_of, setup,
};
use super::tests::{HUMAN, capable};
use super::{
    AgentCreationRecord, AgentCreationState, AgentFailure, apply_decision, commit_approved,
    commit_rebind,
};
use crate::SdkError;
use crate::custody::store::custody_vault_reference;
use crate::custody::vault::AGENT_MASTER_PREFIX;
use crate::custody::{CustodyVaultReason, PrimaryVault};
use ramflux_crypto::agent_profile::verify_agent_profile;
use ramflux_crypto::custody::{AgentMasterPurpose, AgentMasterRequest, verify_record};
use ramflux_protocol::agent_profile::decode_agent_profile;
use ramflux_protocol::custody::{
    DeviceSet, Envelope, RegisterOutcome, RegisterPlan, decode_epoch, decode_register_plan,
    encode_register_plan, object_hash, register_plan_hash,
};
use ramflux_protocol::{PrincipalKind, decode_base64url, encode_base64url};
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The desktop has the new primary's approval applied: the request is `authorized`.
fn authorize(setup: &Rebind) -> TestResult {
    let outcome = begin(setup, REQUEST_REBIND, &setup.desktop)?;
    let decision = new_primary_decision(setup, &outcome.plan_bytes, RegisterOutcome::Approve)?;
    apply_decision(
        &setup.store,
        &setup.desk,
        REQUEST_REBIND,
        &decision,
        &setup.new_primary.branch_public,
        now_of(setup),
    )?;
    Ok(())
}

fn commit(setup: &Rebind) -> Result<AgentCreationRecord, SdkError> {
    commit_rebind(
        &setup.store,
        &setup.desk,
        &setup.transferred,
        REQUEST_REBIND,
        &capable(),
        now_of(setup),
    )
}

/// The agent's authority as it is on the desktop root now.
fn agent_authority(setup: &Rebind) -> Result<Envelope<DeviceSet>, Box<dyn std::error::Error>> {
    Ok(crate::custody::store::stored_record_unverified(
        &setup.fixture.root.0.to_path_buf(),
        &setup.agent_id,
    )?)
}

fn authority_path(setup: &Rebind) -> PathBuf {
    setup
        .fixture
        .root
        .0
        .to_path_buf()
        .join("custody_accounts")
        .join(&setup.agent_id)
        .join("authority.json")
}

fn master_reference(setup: &Rebind) -> Result<String, Box<dyn std::error::Error>> {
    let reference = custody_vault_reference(
        setup.store.root(),
        &setup.agent_id,
        &setup.agent_plan.agent_anchor,
    )?;
    Ok(format!("{AGENT_MASTER_PREFIX}{reference}"))
}

fn stored_plan(setup: &Rebind) -> Result<RegisterPlan, Box<dyn std::error::Error>> {
    let record = setup.store.load(REQUEST_REBIND)?.ok_or("the rebind request")?;
    Ok(decode_register_plan(&record.plan_bytes()?)?)
}

#[test]
fn committed_rebind_certifies_the_next_range_and_rebinds_the_profile() -> TestResult {
    let setup = setup()?;
    authorize(&setup)?;
    let old = agent_authority(&setup)?;
    let plan = stored_plan(&setup)?;
    let record = commit(&setup)?;
    assert_eq!(record.state, AgentCreationState::PublicationPending, "the commit point is reached");

    let rebound = agent_authority(&setup)?;
    let now = now_of(&setup);
    let certificate = &rebound.body.master_certificate.body;
    let previous = &old.body.master_certificate.body;
    assert_eq!(certificate.range_index, plan.next_range, "the next range is certified");
    assert_eq!(certificate.primary_device_ref, plan.human_primary, "the new primary certifies");
    assert_eq!(
        certificate.previous_certificate_hash.as_deref(),
        Some(object_hash(&old.body.master_certificate)?.as_str()),
        "the range chains to the previous certificate"
    );
    assert_eq!(certificate.self_signing_public_key, previous.self_signing_public_key);
    assert_eq!(certificate.master_public_key, previous.master_public_key, "same master key");
    assert_eq!(rebound.body.profile.custodian.as_ref(), Some(&plan.human_primary));
    assert_eq!(decode_epoch(rebound.body.device_set_epoch)?.0, plan.next_range);

    let old_branch = &old.body.devices[0].branch_certificate.as_ref().ok_or("branch")?.body;
    let branch = &rebound.body.devices[0].branch_certificate.as_ref().ok_or("branch")?.body;
    assert_eq!(branch.master_certificate_hash, object_hash(&rebound.body.master_certificate)?);
    assert_eq!(branch.cert_id, plan.branch_cert_id, "the branch names the approved certificate id");
    assert_eq!(branch.capabilities, old_branch.capabilities, "capabilities do not widen");
    assert_eq!(branch.not_before, old_branch.not_before, "the lease does not move");
    assert_eq!(branch.expires_at, old_branch.expires_at, "the lease does not widen");
    assert_eq!(branch.branch_signing_public_key, old_branch.branch_signing_public_key);

    let human = verify_record(&setup.transferred, now, None, None)?;
    let agent = verify_record(&rebound, now, None, Some(&human))?;
    let profile_bytes = decode_base64url(record.profile_b64.as_deref().ok_or("the profile")?)?;
    verify_agent_profile(&profile_bytes, &agent, &human, now)?;
    let profile = decode_agent_profile(&profile_bytes)?;
    assert_eq!(profile.body.custodian_primary, plan.human_primary, "the profile names the primary");
    assert_eq!(profile.body.profile_epoch, plan.profile.profile_epoch, "the epoch is the plan's");
    assert_eq!(profile.body.agent_custody_hash, object_hash(&rebound)?, "bound to the new record");

    let entry = setup.store.load_rebind(&setup.agent_id)?.ok_or("the inventory entry")?;
    assert_eq!(entry.binding, RebindBinding::Committed, "the inventory says committed");
    assert_eq!(entry.master_range, plan.next_range);
    Ok(())
}

#[test]
fn a_missing_master_item_refuses_with_custody_key_unavailable_and_forges_nothing() -> TestResult {
    let setup = setup()?;
    authorize(&setup)?;
    let before = object_hash(&agent_authority(&setup)?)?;
    setup.desk.delete_agent_master(&master_reference(&setup)?, 1)?;
    let refused = commit(&setup);
    assert!(
        matches!(refused, Err(SdkError::CustodyVault(CustodyVaultReason::KeyUnavailable))),
        "a missing master refuses with custody_key_unavailable: {refused:?}"
    );
    assert_eq!(object_hash(&agent_authority(&setup)?)?, before, "the agent authority is unchanged");
    let kept = setup.store.load(REQUEST_REBIND)?.ok_or("the request")?;
    assert_eq!(kept.state, AgentCreationState::Authorized, "the request stays authorized");
    let entry = setup.store.load_rebind(&setup.agent_id)?.ok_or("the inventory entry")?;
    assert_eq!(entry.binding, RebindBinding::RebindPending, "the agent stays paused");
    assert_eq!(entry.failure, Some(AgentFailure::CustodyKeyUnavailable));
    Ok(())
}

#[test]
fn the_vault_refuses_a_same_range_and_a_skipped_range() -> TestResult {
    let setup = setup()?;
    let previous = agent_authority(&setup)?.body.master_certificate;
    let reference = master_reference(&setup)?;
    let request = |range: u64| AgentMasterRequest {
        purpose: AgentMasterPurpose::Rebind,
        anchor: setup.agent_plan.agent_anchor.clone(),
        principal_id: setup.agent_plan.principal_id.clone(),
        principal_kind: PrincipalKind::HeadlessAi,
        cert_id: encode_base64url([37_u8; 32]),
        self_signing_public_key: setup.agent_plan.self_signing_public_key.clone(),
        external_ref: setup.new_primary.device.clone(),
        range,
        previous: Some(previous.clone()),
        issued_at: now_of(&setup),
    };
    assert!(
        setup.desk.certify_agent_master(&reference, request(1)).is_err(),
        "the current range is not a new range"
    );
    assert!(
        setup.desk.certify_agent_master(&reference, request(3)).is_err(),
        "a skipped range is refused"
    );
    Ok(())
}

#[test]
fn an_altered_lease_refuses_before_any_write() -> TestResult {
    let setup = setup()?;
    let outcome = begin(&setup, REQUEST_REBIND, &setup.desktop)?;
    let mut altered = decode_register_plan(&outcome.plan_bytes)?;
    altered.branch_expires_at -= 1;
    let altered_bytes = encode_register_plan(&altered)?;
    let mut record = setup.store.load(REQUEST_REBIND)?.ok_or("the request")?;
    record.plan_b64 = encode_base64url(&altered_bytes);
    record.request_hash = register_plan_hash(&altered)?;
    setup.store.save(&record)?;
    let decision = new_primary_decision(&setup, &altered_bytes, RegisterOutcome::Approve)?;
    apply_decision(
        &setup.store,
        &setup.desk,
        REQUEST_REBIND,
        &decision,
        &setup.new_primary.branch_public,
        now_of(&setup),
    )?;
    let before = object_hash(&agent_authority(&setup)?)?;
    assert!(commit(&setup).is_err(), "a lease that differs from the stored agent refuses");
    assert_eq!(object_hash(&agent_authority(&setup)?)?, before, "nothing is written");
    let kept = setup.store.load(REQUEST_REBIND)?.ok_or("the request")?;
    assert_eq!(kept.state, AgentCreationState::Authorized, "the request stays authorized");
    Ok(())
}

#[test]
fn a_stale_head_refuses_the_commit_and_closes_the_request() -> TestResult {
    let setup = setup()?;
    authorize(&setup)?;
    let stale = commit_rebind(
        &setup.store,
        &setup.desk,
        &setup.before,
        REQUEST_REBIND,
        &capable(),
        now_of(&setup),
    );
    assert!(
        matches!(stale, Err(SdkError::AgentCreationRefused("creation_primary_changed"))),
        "a head the plan does not name refuses: {stale:?}"
    );
    let closed = setup.store.load(REQUEST_REBIND)?.ok_or("the request")?;
    assert_eq!(closed.state, AgentCreationState::Refused);
    assert_eq!(closed.failure, Some(AgentFailure::CreationPrimaryChanged));
    assert!(setup.store.load_rebind(&setup.agent_id)?.is_none(), "the inventory is not touched");
    Ok(())
}

#[test]
fn a_replay_after_a_crash_before_the_commit_point_keeps_one_range() -> TestResult {
    let setup = setup()?;
    authorize(&setup)?;
    commit(&setup)?;
    let first_authority = std::fs::read(authority_path(&setup))?;
    let first_master = object_hash(&agent_authority(&setup)?.body.master_certificate)?;

    // The crash: the authority and the range are written, the record still says authorized.
    let mut record = setup.store.load(REQUEST_REBIND)?.ok_or("the request")?;
    record.state = AgentCreationState::Authorized;
    setup.store.save(&record)?;
    let replayed = commit(&setup)?;

    assert_eq!(
        replayed.state,
        AgentCreationState::PublicationPending,
        "the commit point is reached"
    );
    assert_eq!(std::fs::read(authority_path(&setup))?, first_authority, "the same authority bytes");
    assert_eq!(
        object_hash(&agent_authority(&setup)?.body.master_certificate)?,
        first_master,
        "the same certificate: no second range"
    );
    Ok(())
}

#[test]
fn the_creation_commit_never_commits_a_rebind() -> TestResult {
    let setup = setup()?;
    authorize(&setup)?;
    let refused = commit_approved(
        &setup.store,
        &setup.desk,
        HUMAN,
        REQUEST_REBIND,
        &capable(),
        now_of(&setup),
    );
    assert!(refused.is_err(), "a rebind is never committed as a creation");
    let kept = setup.store.load(REQUEST_REBIND)?.ok_or("the request")?;
    assert_eq!(kept.state, AgentCreationState::Authorized);
    Ok(())
}

/// Stage D R2b: the stored agent of a rebind is read only after a verified decision, and a stored
/// agent that does not match the approved plan or was altered on disk is refused without writes.
#[test]
fn a_tampered_stored_agent_is_refused_and_nothing_is_written() -> TestResult {
    let setup = setup()?;
    authorize(&setup)?;
    let path = authority_path(&setup);
    let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let issued = value["record"]["body"]["issued_at"].as_u64().ok_or("test: issued_at")?;
    value["record"]["body"]["issued_at"] = serde_json::json!(issued + 1);
    std::fs::write(&path, serde_json::to_vec(&value)?)?;
    let before = std::fs::read(&path)?;
    assert!(commit(&setup).is_err(), "a tampered stored agent is refused");
    assert_eq!(std::fs::read(&path)?, before, "the authority is not rewritten");
    let record = setup.store.load(REQUEST_REBIND)?.ok_or("test: the rebind record")?;
    assert_eq!(record.state, AgentCreationState::Authorized, "the request stays authorized");
    Ok(())
}

/// A stored agent whose hash differs from the plan's predecessor head is refused by the check that
/// every read goes through (`check_predecessors`).
#[test]
fn a_stored_agent_that_differs_from_the_approved_plan_is_refused() -> TestResult {
    let setup = setup()?;
    let outcome = begin(&setup, REQUEST_REBIND, &setup.desktop)?;
    let plan = decode_register_plan(&outcome.plan_bytes)?;
    let mut other = agent_authority(&setup)?;
    other.body.issued_at += 1;
    assert!(super::rebind_commit::check_predecessors(&plan, &agent_authority(&setup)?).is_ok());
    assert!(super::rebind_commit::check_predecessors(&plan, &other).is_err());
    Ok(())
}

/// The stored agent is read only after `verify_rebind_decision` accepted the new primary's
/// decision: a genuine approval passes, and an approval whose signed body was changed does not.
#[test]
fn the_stored_agent_is_read_only_after_a_verified_rebind_decision() -> TestResult {
    let setup = setup()?;
    authorize(&setup)?;
    let record = setup.store.load(REQUEST_REBIND)?.ok_or("test: the rebind record")?;
    let now = now_of(&setup);
    assert!(super::rebind_commit::verify_rebind_decision(&setup.transferred, &record, now).is_ok());

    let genuine = record.decision_bytes()?.ok_or("test: the decision is stored")?;
    let mut decision = ramflux_protocol::custody::decode_register_decision(&genuine)?;
    decision.body.expires_at += 1;
    let mut forged = record.clone();
    forged.decision_b64 =
        Some(encode_base64url(ramflux_protocol::custody::encode_register_decision(&decision)?));
    assert!(
        super::rebind_commit::verify_rebind_decision(&setup.transferred, &forged, now).is_err(),
        "a changed signed body is not a verified decision"
    );
    Ok(())
}
