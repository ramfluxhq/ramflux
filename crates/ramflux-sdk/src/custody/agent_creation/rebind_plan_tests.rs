// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stage D3 tests of the rebind request (contract 7.5): the plan the desktop freezes for the new
//! primary, the new primary's approval, and each refusal the card names.
//!
//! REAL: the creation store and its files, the desktop's approval of the agent (`approve_for_human`,
//! `commit_approved`), the primary transfer (`cooperative_transfer_preserving_devices`, the master
//! and the new primary key are the fixture seeds), the memory vault's signing and presence, and the
//! receiving and decision checks.
//! FIXTURE: the human authority is `tests::human_fixture_with_sibling` (persisted on the desktop root,
//! not published to any node). The transferred authority is handed to the desktop and to the new
//! primary in memory: it is NOT written to any root (stage D5 persists it). The new primary's vault
//! holds the transferred primary key and the sibling's branch seeds. The desktop's "complete" state
//! of the agent is set by hand, as in `rebind_tests::complete_agent`.
use super::rebind_plan::is_rebind;
use super::tests::{
    HUMAN, HUMAN_PRINCIPAL, HumanFixture, Phone, SIBLING_AGREEMENT_SEED, SIBLING_DEVICE,
    SIBLING_SIGNING_SEED, account_id_of, approve_for_human, begin_for_human, capable,
    fixture_phone, human_fixture_with_sibling, owner_anchor, phone,
};
use super::{
    AgentCreationRecord, AgentCreationState, AgentCreationStore, AgentSteps, PrimarySigning,
    RebindInput, advance_one, apply_decision, begin_rebind, check_decision_context,
    commit_approved, primary_sign_decision, receive_plan, stored_profile,
};
use crate::SdkError;
use crate::custody::memory_vault::MemoryPrimaryVault;
use crate::custody::{AgentDecisionSigning, PrimaryVault};
use ramflux_crypto::create_device_branch_from_seed;
use ramflux_crypto::custody::{
    CooperativeTransferInput, MasterKey, SelfSigningKey, cooperative_transfer_preserving_devices,
    verify_record,
};
use ramflux_protocol::agent_profile::AgentProfileEnvelope;
use ramflux_protocol::custody::{
    AgentDecisionRequest, DeviceRef, DeviceSet, Envelope, RegisterOutcome, RegisterPlan,
    RegisterPurpose, decode_register_plan, encode_register_decision, encode_register_plan,
    object_hash, register_plan_hash,
};
use ramflux_protocol::encode_base64url;
use std::future::Future;
use tempfile::TempDir;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DESKTOP_DEVICE: &str = "desktop-device";
const REQUEST_AGENT: &str = "req-agent";
pub(super) const REQUEST_REBIND: &str = "req-rebind";

/// The new primary (the sibling after the transfer): its vault and its store.
pub(super) struct NewPrimary {
    pub(super) vault: MemoryPrimaryVault,
    pub(super) primary_ref: String,
    pub(super) branch_ref: String,
    pub(super) primary_public: String,
    pub(super) branch_public: String,
    pub(super) device: DeviceRef,
    pub(super) store: AgentCreationStore,
    pub(super) _dir: TempDir,
}

/// Everything the rebind tests share.
pub(super) struct Rebind {
    pub(super) fixture: HumanFixture,
    pub(super) store: AgentCreationStore,
    pub(super) desk: MemoryPrimaryVault,
    pub(super) agent_id: String,
    pub(super) agent_plan: RegisterPlan,
    pub(super) agent_record: AgentCreationRecord,
    /// The human authority before the transfer (the stale snapshot).
    pub(super) before: Envelope<DeviceSet>,
    /// The human authority after the transfer: the new primary is the sibling.
    pub(super) transferred: Envelope<DeviceSet>,
    pub(super) new_primary: NewPrimary,
    /// The old primary's phone (fixture primary keys).
    pub(super) old_primary: Phone,
    pub(super) desktop: DeviceRef,
}

fn desktop_ref(fixture: &HumanFixture, device: &str) -> DeviceRef {
    DeviceRef { account_anchor: fixture.anchor.clone(), device_id: device.into(), device_epoch: 1 }
}

/// A committed agent under the old primary, then the real primary transfer to the sibling.
pub(super) fn setup() -> Result<Rebind, Box<dyn std::error::Error>> {
    let fixture = human_fixture_with_sibling()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN)?;
    let desk = MemoryPrimaryVault::default();
    let creator = phone(&owner_anchor())?;
    let outcome = begin_for_human(&fixture, &store, &desk, REQUEST_AGENT, None)?;
    let authorized = approve_for_human(&fixture, &creator, &store, &desk, &outcome)?;
    let agent_id = account_id_of(&authorized)?;
    commit_approved(&store, &desk, HUMAN, REQUEST_AGENT, &capable(), fixture.now + 2)?;
    let mut agent_record = store.load(REQUEST_AGENT)?.ok_or("test: the committed record")?;
    agent_record.state = AgentCreationState::Complete;
    agent_record.master_range = 1;
    store.save(&agent_record)?;
    let agent_plan = decode_register_plan(&agent_record.plan_bytes()?)?;

    let now = fixture.now;
    let account = before_account(&fixture)?;
    let before = account.record().clone();
    let current = verify_record(account.record(), now, None, None)?;
    let master = MasterKey::from_vault_seed(&Zeroizing::new([21_u8; 32]));
    let successor = SelfSigningKey::from_vault_seed(&Zeroizing::new([31_u8; 32]));
    let transferred = cooperative_transfer_preserving_devices(
        &master,
        &successor,
        &current,
        CooperativeTransferInput {
            destination: desktop_ref(&fixture, SIBLING_DEVICE),
            fresh_destination: None,
            highest_observed_range: 0,
            issued_at: now + 1,
            master_cert_id: encode_base64url([36_u8; 32]),
        },
    )?;
    let new_primary = new_primary(&fixture, &successor)?;
    Ok(Rebind {
        desktop: desktop_ref(&fixture, DESKTOP_DEVICE),
        fixture,
        store,
        desk,
        agent_id,
        agent_plan,
        agent_record,
        before,
        transferred,
        new_primary,
        old_primary: fixture_phone()?,
    })
}

fn before_account(
    fixture: &HumanFixture,
) -> Result<crate::custody::BornAccount, Box<dyn std::error::Error>> {
    Ok(crate::custody::store::load_account(&fixture.root.0, HUMAN, fixture.now)?)
}

/// The sibling's vault after the transfer: the transferred primary key and its branch seeds.
fn new_primary(
    fixture: &HumanFixture,
    successor: &SelfSigningKey,
) -> Result<NewPrimary, Box<dyn std::error::Error>> {
    let vault = MemoryPrimaryVault::default();
    let primary_ref = encode_base64url([41_u8; 32]);
    let branch_ref = format!("branch:{}", encode_base64url([42_u8; 32]));
    vault.store_new(&primary_ref, successor)?;
    let mut seeds = Zeroizing::new([0_u8; 64]);
    seeds[..32].copy_from_slice(&SIBLING_SIGNING_SEED);
    seeds[32..].copy_from_slice(&SIBLING_AGREEMENT_SEED);
    vault.store_branch(&branch_ref, &seeds)?;
    let branch = create_device_branch_from_seed(
        HUMAN_PRINCIPAL,
        SIBLING_DEVICE,
        1,
        &Zeroizing::new(SIBLING_SIGNING_SEED),
    );
    let dir = TempDir::new()?;
    let store = AgentCreationStore::open(dir.path(), HUMAN)?;
    Ok(NewPrimary {
        vault,
        primary_ref,
        branch_ref,
        primary_public: successor.public_key(),
        branch_public: encode_base64url(branch.signing_key.verifying_key().to_bytes()),
        device: desktop_ref(fixture, SIBLING_DEVICE),
        store,
        _dir: dir,
    })
}

/// The desktop begins the rebind of the agent for `desktop`, with the transferred authority.
pub(super) fn begin(
    setup: &Rebind,
    request_id: &str,
    desktop: &DeviceRef,
) -> Result<super::BeginOutcome, SdkError> {
    let stored_agent =
        crate::custody::store::stored_record_unverified(&setup.fixture.root.0, &setup.agent_id)?;
    let profile: AgentProfileEnvelope = stored_profile(&setup.agent_record)?;
    let input = RebindInput {
        request_id: request_id.into(),
        agent_account_id: setup.agent_id.clone(),
        agent: &stored_agent,
        profile: &profile,
        human: &setup.transferred,
        desktop,
        now: setup.fixture.now + 4,
    };
    begin_rebind(&setup.store, &input)
}

/// The new primary approves the exact plan: presence is armed for its hash, then one signature.
pub(super) fn new_primary_decision(
    setup: &Rebind,
    plan_bytes: &[u8],
    outcome: RegisterOutcome,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let plan = decode_register_plan(plan_bytes)?;
    let np = &setup.new_primary;
    np.vault.approve_agent_decision_once_for_test(&register_plan_hash(&plan)?)?;
    let signing = PrimarySigning {
        primary_device: &np.device,
        primary_reference: &np.primary_ref,
        expected_primary_public_key: &np.primary_public,
        branch_reference: &np.branch_ref,
        principal_id: HUMAN_PRINCIPAL,
    };
    Ok(primary_sign_decision(&np.vault, &signing, plan_bytes, outcome, setup.fixture.now + 5)?)
}

pub(super) fn now_of(setup: &Rebind) -> u64 {
    setup.fixture.now + 5
}

/// Steps that count their calls and refuse every one: an advance of a rebind request may reach only
/// `commit_rebind`, never the creation commit or the activation of a creation.
#[derive(Default)]
struct CountingSteps {
    creation_calls: u32,
    rebind_calls: u32,
}

impl AgentSteps for CountingSteps {
    fn commit(
        &mut self,
        _request_id: &str,
        _now: u64,
    ) -> impl Future<Output = Result<AgentCreationRecord, SdkError>> {
        self.creation_calls += 1;
        std::future::ready(Err(SdkError::CustodySetupInvalid))
    }

    fn commit_rebind(
        &mut self,
        _request_id: &str,
        _now: u64,
    ) -> impl Future<Output = Result<AgentCreationRecord, SdkError>> {
        self.rebind_calls += 1;
        std::future::ready(Err(SdkError::CustodySetupInvalid))
    }

    fn is_live(&self, _account_id: &str) -> bool {
        false
    }

    fn activate(
        &mut self,
        _record: &AgentCreationRecord,
    ) -> impl Future<Output = Result<(), SdkError>> {
        self.creation_calls += 1;
        std::future::ready(Err(SdkError::CustodySetupInvalid))
    }

    fn complete(
        &mut self,
        _request_id: &str,
    ) -> impl Future<Output = Result<AgentCreationRecord, SdkError>> {
        self.creation_calls += 1;
        std::future::ready(Err(SdkError::CustodySetupInvalid))
    }
}

#[test]
fn rebind_plan_names_the_new_primary_and_the_next_range_with_nothing_widened() -> TestResult {
    let setup = setup()?;
    let outcome = begin(&setup, REQUEST_REBIND, &setup.desktop)?;
    let plan = decode_register_plan(&outcome.plan_bytes)?;
    let stored =
        &crate::custody::store::stored_record_unverified(&setup.fixture.root.0, &setup.agent_id)?;
    let branch = &stored.body.devices[0].branch_certificate.as_ref().ok_or("branch")?.body;
    assert_eq!(plan.purpose, RegisterPurpose::Rebind);
    assert_eq!(plan.human_primary, setup.new_primary.device, "the new primary is the sibling");
    assert_eq!(plan.human_head_hash, object_hash(&setup.transferred)?, "the new head");
    assert_eq!(plan.agent_anchor, setup.agent_plan.agent_anchor, "same anchor");
    assert_eq!(plan.principal_id, setup.agent_plan.principal_id, "same principal");
    assert_eq!(plan.master_public_key, setup.agent_plan.master_public_key, "same master key");
    assert_eq!(plan.self_signing_public_key, setup.agent_plan.self_signing_public_key);
    assert_eq!(plan.branch_signing_public_key, branch.branch_signing_public_key, "same branch");
    assert_eq!(plan.capabilities, branch.capabilities, "capabilities do not widen");
    assert_eq!(plan.branch_expires_at, branch.expires_at, "the branch lease does not widen");
    assert_eq!(plan.previous_agent_head_hash, Some(object_hash(stored)?), "the agent head");
    assert_eq!(
        plan.previous_master_certificate_hash,
        Some(object_hash(&stored.body.master_certificate)?),
        "the agent master certificate"
    );
    assert_eq!(plan.next_range, 2, "the next range after the stored certificate");
    assert_eq!(
        plan.profile.profile_epoch,
        setup.agent_plan.profile.profile_epoch + 1,
        "the profile epoch is raised"
    );
    let record = setup.store.load(REQUEST_REBIND)?.ok_or("test: the rebind request is saved")?;
    assert_eq!(record.account_id.as_deref(), Some(setup.agent_id.as_str()));
    assert!(record.vault_refs.is_empty(), "no pending vault item is written for a rebind");
    Ok(())
}

#[test]
fn rebind_for_an_unpaired_desktop_refuses_and_writes_nothing() -> TestResult {
    let setup = setup()?;
    let stranger = desktop_ref(&setup.fixture, "desktop-gone");
    let refused = begin(&setup, "req-stranger", &stranger);
    assert!(
        matches!(refused, Err(SdkError::AgentCreationRefused("creation_pairing_required"))),
        "a desktop that is not an enrolled sibling is refused: {refused:?}"
    );
    assert!(setup.store.load("req-stranger")?.is_none(), "no request is saved");
    Ok(())
}

#[test]
fn the_new_primary_approves_the_exact_rebind_plan_and_the_desktop_authorizes_it() -> TestResult {
    let setup = setup()?;
    let outcome = begin(&setup, REQUEST_REBIND, &setup.desktop)?;
    let decision = new_primary_decision(&setup, &outcome.plan_bytes, RegisterOutcome::Approve)?;
    let np = &setup.new_primary;
    let received = receive_plan(&np.store, &outcome.plan_bytes, now_of(&setup))?;
    assert_eq!(received.state, AgentCreationState::AuthorizationPending, "the sibling holds it");
    assert!(is_rebind(&received), "the received request is a rebind");
    let plan = decode_register_plan(&outcome.plan_bytes)?;
    check_decision_context(&plan, &setup.transferred, &np.device)
        .map_err(|token| format!("the new primary is the current primary: {token}"))?;
    let authorized = apply_decision(
        &setup.store,
        &setup.desk,
        REQUEST_REBIND,
        &decision,
        &np.branch_public,
        now_of(&setup),
    )?;
    assert_eq!(authorized.state, AgentCreationState::Authorized, "the desktop authorizes it");
    Ok(())
}

#[test]
fn the_old_primary_cannot_approve_a_rebind_plan() -> TestResult {
    let setup = setup()?;
    let outcome = begin(&setup, REQUEST_REBIND, &setup.desktop)?;
    let plan_bytes = &outcome.plan_bytes;
    let old = &setup.old_primary;
    let refused = primary_sign_decision(
        &old.vault,
        &PrimarySigning {
            primary_device: &old.primary_device,
            primary_reference: &old.primary_ref,
            expected_primary_public_key: &old.primary_public,
            branch_reference: &old.branch_ref,
            principal_id: HUMAN_PRINCIPAL,
        },
        plan_bytes,
        RegisterOutcome::Approve,
        now_of(&setup),
    );
    assert!(refused.is_err(), "the old primary signs no plan that names the new primary");

    // A decision the old primary signs as the new primary's plan: its signature is the old branch,
    // so the desktop refuses it against the new primary's branch key.
    let plan = decode_register_plan(plan_bytes)?;
    let hash = register_plan_hash(&plan)?;
    old.vault.approve_agent_decision_once_for_test(&hash)?;
    let forged = old.vault.sign_agent_register_decision(AgentDecisionSigning {
        primary_reference: &old.primary_ref,
        expected_primary_public_key: &old.primary_public,
        branch_reference: &old.branch_ref,
        principal_id: HUMAN_PRINCIPAL,
        request: &AgentDecisionRequest {
            plan_bytes: plan_bytes.clone(),
            plan_hash: hash,
            decision: RegisterOutcome::Approve,
            signer: plan.human_primary.clone(),
            issued_at: now_of(&setup),
            expires_at: plan.expires_at,
        },
    })?;
    let bytes = encode_register_decision(&forged)?;
    let applied = apply_decision(
        &setup.store,
        &setup.desk,
        REQUEST_REBIND,
        &bytes,
        &setup.new_primary.branch_public,
        now_of(&setup),
    );
    assert!(applied.is_err(), "a decision signed by the old primary is refused");
    let kept = setup.store.load(REQUEST_REBIND)?.ok_or("test: the request is kept")?;
    assert_eq!(kept.state, AgentCreationState::AuthorizationPending, "the request stays pending");
    Ok(())
}

#[test]
fn a_changed_rebind_plan_under_the_same_request_refuses_on_the_new_primary() -> TestResult {
    let setup = setup()?;
    let outcome = begin(&setup, REQUEST_REBIND, &setup.desktop)?;
    let original = decode_register_plan(&outcome.plan_bytes)?;
    receive_plan(&setup.new_primary.store, &outcome.plan_bytes, now_of(&setup))?;
    let mut altered = original.clone();
    altered.profile.profile_epoch += 1;
    let changed = encode_register_plan(&altered)?;
    assert!(
        receive_plan(&setup.new_primary.store, &changed, now_of(&setup)).is_err(),
        "a plan changed after it was stored refuses"
    );
    let kept = setup.new_primary.store.load(REQUEST_REBIND)?.ok_or("test: the plan is kept")?;
    assert_eq!(kept.plan_bytes()?, outcome.plan_bytes, "the stored plan is unchanged");
    Ok(())
}

#[test]
fn a_stale_head_or_a_non_primary_device_refuses_the_decision_context() -> TestResult {
    let setup = setup()?;
    let outcome = begin(&setup, REQUEST_REBIND, &setup.desktop)?;
    let plan = decode_register_plan(&outcome.plan_bytes)?;
    let np = &setup.new_primary.device;
    assert!(
        check_decision_context(&plan, &setup.transferred, np).is_ok(),
        "the current head and the current primary pass"
    );
    assert_eq!(
        check_decision_context(&plan, &setup.before, np),
        Err("creation_plan_changed"),
        "a stale human head refuses"
    );
    assert_eq!(
        check_decision_context(&plan, &setup.transferred, &setup.desktop),
        Err("creation_not_primary"),
        "a device that is not the current primary refuses"
    );
    Ok(())
}

#[test]
fn a_rebind_request_is_never_advanced_as_a_creation_nor_found_as_the_agent_record() -> TestResult {
    let setup = setup()?;
    let outcome = begin(&setup, REQUEST_REBIND, &setup.desktop)?;
    let decision = new_primary_decision(&setup, &outcome.plan_bytes, RegisterOutcome::Approve)?;
    apply_decision(
        &setup.store,
        &setup.desk,
        REQUEST_REBIND,
        &decision,
        &setup.new_primary.branch_public,
        now_of(&setup),
    )?;
    let found = setup.store.find_by_account(&setup.agent_id)?.ok_or("the agent record")?;
    assert_eq!(found.request_id, REQUEST_AGENT, "the rebind is never the creation record");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let mut steps = CountingSteps::default();
    let advanced =
        runtime.block_on(advance_one(&mut steps, &setup.store, REQUEST_REBIND, now_of(&setup)));
    assert!(advanced.is_err(), "the refusing rebind step reports its failure");
    assert_eq!(steps.rebind_calls, 1, "a rebind is committed by its own step");
    assert_eq!(steps.creation_calls, 0, "no creation step runs for a rebind");
    let kept = setup.store.load(REQUEST_REBIND)?.ok_or("the request")?;
    assert_eq!(kept.state, AgentCreationState::Authorized, "the failed commit keeps it authorized");
    Ok(())
}
