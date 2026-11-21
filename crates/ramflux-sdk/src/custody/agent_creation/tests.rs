// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stage B exit tests: the vault operations and the creation state machine, driven by the real
//! `MemoryPrimaryVault`, real key generation and a `TempDir` store. Time is always an argument.
use super::commit::desktop_is_enrolled;
use super::{
    AgentCreationRecord, AgentCreationState, AgentCreationStore, AgentFailure, BeginInput,
    BeginOutcome, PrimarySigning, apply_decision, begin, cancel, check_received_request,
    check_sender, commit_approved, expected_scope, primary_sign_decision, receive_plan,
    resume_request,
};
use crate::SdkError;
use crate::custody::vault::agent_master_item::AgentMasterCells;
use crate::custody::store::GenesisMaterial;
use crate::custody::{CreateInput, PrimaryVault, memory_vault::MemoryPrimaryVault};
use ramflux_crypto::create_device_branch_from_seed;
use ramflux_crypto::custody::{
    AgentMasterPurpose, AgentMasterRequest, GenesisInput, MasterKey, SelfSigningKey,
    create_genesis, master_anchor, verify_register_decision,
};
use ramflux_crypto::X25519KeyPair;
use ramflux_protocol::custody::{
    AgentRegisterProfile, BranchCertificate, Device, DeviceRef, DeviceSet, Envelope,
    MAX_BRANCH_LEASE_SECONDS, MigrationState, RegisterCancel, RegisterOutcome,
    decode_register_decision, decode_register_plan, encode_register_cancel, encode_register_plan,
    object_hash,
};
use ramflux_protocol::{DeviceSetStatus, PrincipalKind, domain};
use ramflux_protocol::encode_base64url;
use tempfile::TempDir;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const NOW: u64 = 1_000;
const PRIMARY_DEVICE: &str = "primary-device";
const PRINCIPAL: &str = "agent-principal-1";
const DESKTOP_DEVICE: &str = "desktop-device";
/// The human account whose data directory holds the creation records in these tests.
const HUMAN: &str = "human";

/// The human primary phone: vault holds its self-signing key and branch seeds, plus one armed
/// presence approval per plan hash.
struct Phone {
    vault: MemoryPrimaryVault,
    primary_ref: String,
    branch_ref: String,
    primary_public: String,
    branch_public: String,
    primary_device: DeviceRef,
}

fn owner_anchor() -> String {
    encode_base64url([9_u8; 32])
}

fn phone(owner: &str) -> Result<Phone, Box<dyn std::error::Error>> {
    let vault = MemoryPrimaryVault::default();
    let primary = SelfSigningKey::generate()?;
    let primary_ref = encode_base64url([1_u8; 32]);
    let branch_ref = format!("branch:{}", encode_base64url([2_u8; 32]));
    vault.store_new(&primary_ref, &primary)?;
    let signing_seed = Zeroizing::new([5_u8; 32]);
    let agreement_seed = Zeroizing::new([6_u8; 32]);
    let mut seeds = Zeroizing::new([0_u8; 64]);
    seeds
        .iter_mut()
        .zip(signing_seed.iter().chain(agreement_seed.iter()))
        .for_each(|(slot, byte)| *slot = *byte);
    vault.store_branch(&branch_ref, &seeds)?;
    let primary_device = DeviceRef {
        account_anchor: owner.into(),
        device_id: PRIMARY_DEVICE.into(),
        device_epoch: 1,
    };
    let branch = create_device_branch_from_seed(PRINCIPAL, PRIMARY_DEVICE, 1, &signing_seed);
    Ok(Phone {
        vault,
        primary_ref,
        branch_ref,
        primary_public: primary.public_key(),
        branch_public: encode_base64url(branch.signing_key.verifying_key().to_bytes()),
        primary_device,
    })
}

fn begin_input(request_id: &str, owner: &str, primary: &DeviceRef, expires: u64) -> BeginInput {
    BeginInput {
        request_id: request_id.into(),
        owner_anchor: owner.into(),
        human_head_hash: encode_base64url([3_u8; 32]),
        human_primary: primary.clone(),
        desktop: DeviceRef {
            account_anchor: owner.into(),
            device_id: DESKTOP_DEVICE.into(),
            device_epoch: 1,
        },
        principal_id: PRINCIPAL.into(),
        display_name: "Support agent".into(),
        profile: AgentRegisterProfile {
            responsibility: "Answer support questions".into(),
            provider: "provider-a".into(),
            model: "model-a".into(),
            persona_version: 1,
            persona_hash: encode_base64url([4_u8; 32]),
            profile_epoch: 1,
        },
        primary_branch_expires_at: expires,
    }
}

fn signing<'a>(phone: &'a Phone, device: &'a DeviceRef) -> PrimarySigning<'a> {
    PrimarySigning {
        primary_device: device,
        primary_reference: &phone.primary_ref,
        expected_primary_public_key: &phone.primary_public,
        branch_reference: &phone.branch_ref,
        principal_id: PRINCIPAL,
    }
}

/// Desktop side of a request: a fresh store directory and an in-memory desktop vault.
fn desktop(dir: &TempDir) -> Result<(AgentCreationStore, MemoryPrimaryVault), SdkError> {
    Ok((AgentCreationStore::open(dir.path(), HUMAN)?, MemoryPrimaryVault::default()))
}

/// Pending item references of a request, read back from its saved record.
fn saved_refs(
    store: &AgentCreationStore,
    id: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let record = store.load(id)?.ok_or("record must exist")?;
    Ok(record.vault_refs)
}

/// Every pending item of a closed request must be absent from the desktop vault.
fn assert_items_gone(vault: &MemoryPrimaryVault, refs: &[String]) -> TestResult {
    assert!(!refs.is_empty(), "the request must have had pending items");
    let device = DeviceRef {
        account_anchor: owner_anchor(),
        device_id: DESKTOP_DEVICE.into(),
        device_epoch: 1,
    };
    for reference in refs {
        let absent = if reference.starts_with("agent-master:") {
            // Storing succeeds only when the item is absent; the probe is removed by the vault.
            vault.store_agent_master(reference, &MasterKey::generate()?).is_ok()
        } else if reference.starts_with("branch:") {
            vault.load_branch(reference, PRINCIPAL, &device).is_err()
        } else if reference.starts_with("agent-provisioning:") {
            vault.load_provisioning_secret(reference).is_err()
        } else {
            vault.load_primary(reference).is_err()
        };
        assert!(absent, "pending vault item {reference} must be deleted");
    }
    Ok(())
}

fn create_request(
    master: &MasterKey,
    issued_at: u64,
    external: &DeviceRef,
    range: u64,
    previous: Option<
        ramflux_protocol::custody::Envelope<ramflux_protocol::custody::MasterCertificate>,
    >,
) -> Result<AgentMasterRequest, Box<dyn std::error::Error>> {
    let key = SelfSigningKey::generate()?;
    Ok(AgentMasterRequest {
        purpose: if previous.is_some() {
            AgentMasterPurpose::Rebind
        } else {
            AgentMasterPurpose::Create
        },
        anchor: master_anchor(master)?,
        principal_id: PRINCIPAL.into(),
        principal_kind: ramflux_protocol::PrincipalKind::HeadlessAi,
        cert_id: encode_base64url([7_u8; 32]),
        self_signing_public_key: key.public_key(),
        external_ref: external.clone(),
        range,
        previous,
        issued_at,
    })
}

#[test]
fn create_certify_succeeds_once_and_second_create_refuses() -> TestResult {
    let dir = TempDir::new()?;
    let (_store, vault) = desktop(&dir)?;
    let phone = phone(&owner_anchor())?;
    let master = MasterKey::generate()?;
    let reference = format!("agent-master:{}", encode_base64url([8_u8; 32]));
    vault.store_agent_master(&reference, &master)?;
    let first = vault.certify_agent_master(
        &reference,
        create_request(&master, NOW, &phone.primary_device, 1, None)?,
    )?;
    assert_eq!(first.body.range_index, 1, "genesis certificate uses the genesis range");
    assert!(first.body.previous_certificate_hash.is_none(), "genesis has no previous hash");
    let second = vault.certify_agent_master(
        &reference,
        create_request(&master, NOW, &phone.primary_device, 1, None)?,
    );
    assert!(second.is_err(), "a second genesis certificate for the same reference must refuse");
    let duplicate = vault.store_agent_master(&reference, &master);
    assert!(duplicate.is_err(), "an existing agent master item must not be replaced");
    Ok(())
}

#[test]
fn rebind_accepts_the_right_previous_and_refuses_wrong_hash_anchor_or_range() -> TestResult {
    let dir = TempDir::new()?;
    let (_store, vault) = desktop(&dir)?;
    let phone = phone(&owner_anchor())?;
    let master = MasterKey::generate()?;
    let reference = format!("agent-master:{}", encode_base64url([8_u8; 32]));
    vault.store_agent_master(&reference, &master)?;
    let genesis = vault.certify_agent_master(
        &reference,
        create_request(&master, NOW, &phone.primary_device, 1, None)?,
    )?;
    let mut wrong_anchor =
        create_request(&master, NOW, &phone.primary_device, 2, Some(genesis.clone()))?;
    wrong_anchor.anchor = encode_base64url([0xee_u8; 32]);
    assert!(vault.certify_agent_master(&reference, wrong_anchor).is_err(), "wrong anchor refuses");
    let wrong_range =
        create_request(&master, NOW, &phone.primary_device, 3, Some(genesis.clone()))?;
    assert!(vault.certify_agent_master(&reference, wrong_range).is_err(), "non-next range refuses");
    let right = create_request(&master, NOW, &phone.primary_device, 2, Some(genesis.clone()))?;
    let rebound = vault.certify_agent_master(&reference, right)?;
    assert_eq!(rebound.body.range_index, 2, "rebind uses the next range");
    assert_eq!(
        rebound.body.previous_certificate_hash.as_deref(),
        Some(object_hash(&genesis)?.as_str()),
        "rebind records the hash of the previous certificate"
    );
    let stale = create_request(&master, NOW, &phone.primary_device, 2, Some(genesis))?;
    assert!(
        vault.certify_agent_master(&reference, stale).is_err(),
        "a stale previous certificate (wrong hash) refuses after the rebind"
    );
    Ok(())
}

#[test]
fn decision_is_signed_only_after_approval_only_for_the_primary_and_verifies() -> TestResult {
    let dir = TempDir::new()?;
    let (store, desk) = desktop(&dir)?;
    let phone = phone(&owner_anchor())?;
    let outcome = begin(
        &store,
        &desk,
        &begin_input("req-sign", &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW,
    )?;
    let plan_hash = outcome.request_hash.clone();

    let unarmed = primary_sign_decision(
        &phone.vault,
        &signing(&phone, &phone.primary_device),
        &outcome.plan_bytes,
        RegisterOutcome::Approve,
        NOW + 1,
    );
    assert!(unarmed.is_err(), "no signature without the one-shot presence approval");

    let other = DeviceRef {
        account_anchor: owner_anchor(),
        device_id: "secondary-device".into(),
        device_epoch: 1,
    };
    let wrong_device = signing(&phone, &other);
    phone.vault.approve_agent_decision_once_for_test(&plan_hash)?;
    assert!(
        primary_sign_decision(
            &phone.vault,
            &wrong_device,
            &outcome.plan_bytes,
            RegisterOutcome::Approve,
            NOW + 1
        )
        .is_err(),
        "a device that is not the plan's human primary must not sign"
    );
    let signed = primary_sign_decision(
        &phone.vault,
        &signing(&phone, &phone.primary_device),
        &outcome.plan_bytes,
        RegisterOutcome::Approve,
        NOW + 1,
    )?;
    let envelope = decode_register_decision(&signed)?;
    verify_register_decision(&phone.branch_public, &envelope)?;
    assert_eq!(envelope.body.request_hash, plan_hash, "the decision names the exact plan");

    let replay = primary_sign_decision(
        &phone.vault,
        &signing(&phone, &phone.primary_device),
        &outcome.plan_bytes,
        RegisterOutcome::Approve,
        NOW + 1,
    );
    assert!(replay.is_err(), "the approval is one-shot");
    Ok(())
}

#[test]
fn approve_then_authorized_and_deny_cleans_up_and_tombstones() -> TestResult {
    let dir = TempDir::new()?;
    let (store, desk) = desktop(&dir)?;
    let phone = phone(&owner_anchor())?;
    let outcome = begin(
        &store,
        &desk,
        &begin_input("req-deny", &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW,
    )?;
    let refs = saved_refs(&store, "req-deny")?;
    phone.vault.approve_agent_decision_once_for_test(&outcome.request_hash)?;
    let deny = primary_sign_decision(
        &phone.vault,
        &signing(&phone, &phone.primary_device),
        &outcome.plan_bytes,
        RegisterOutcome::Deny,
        NOW + 2,
    )?;
    let record = apply_decision(&store, &desk, "req-deny", &deny, &phone.branch_public, NOW + 2)?;
    assert_eq!(record.state, AgentCreationState::Refused, "a signed deny refuses the request");
    assert_eq!(record.failure, Some(AgentFailure::AuthorizationRefused));
    assert_items_gone(&desk, &refs)?;
    assert!(store.load("req-deny")?.is_some(), "the refused request is kept as a tombstone");
    Ok(())
}

#[test]
fn approval_moves_to_authorized_and_a_forged_decision_is_refused() -> TestResult {
    let dir = TempDir::new()?;
    let (store, desk) = desktop(&dir)?;
    let phone = phone(&owner_anchor())?;
    let outcome = begin(
        &store,
        &desk,
        &begin_input("req-ok", &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW,
    )?;
    phone.vault.approve_agent_decision_once_for_test(&outcome.request_hash)?;
    let approve = primary_sign_decision(
        &phone.vault,
        &signing(&phone, &phone.primary_device),
        &outcome.plan_bytes,
        RegisterOutcome::Approve,
        NOW + 2,
    )?;
    let forged_key = encode_base64url([0x42_u8; 32]);
    assert!(
        apply_decision(&store, &desk, "req-ok", &approve, &forged_key, NOW + 2).is_err(),
        "a decision must verify against the independently refreshed primary branch key"
    );
    let record = apply_decision(&store, &desk, "req-ok", &approve, &phone.branch_public, NOW + 2)?;
    assert_eq!(record.state, AgentCreationState::Authorized);
    let replay = apply_decision(&store, &desk, "req-ok", &approve, &phone.branch_public, NOW + 3)?;
    assert_eq!(
        replay.state,
        AgentCreationState::Authorized,
        "an exact replay returns the saved state"
    );
    Ok(())
}

#[test]
fn expiry_driven_by_now_cleans_up_pending_items() -> TestResult {
    let dir = TempDir::new()?;
    let (store, desk) = desktop(&dir)?;
    let phone = phone(&owner_anchor())?;
    let outcome = begin(
        &store,
        &desk,
        &begin_input("req-exp", &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW,
    )?;
    let refs = saved_refs(&store, "req-exp")?;
    assert_eq!(outcome.state, AgentCreationState::AuthorizationPending);
    let record = resume_request(&store, &desk, "req-exp", outcome_expiry(&outcome)?)?;
    assert_eq!(record.state, AgentCreationState::Expired, "the deadline passed by `now`");
    assert_items_gone(&desk, &refs)?;
    Ok(())
}

#[test]
fn cancel_cleans_up_pending_items_and_tombstones() -> TestResult {
    let dir = TempDir::new()?;
    let (store, desk) = desktop(&dir)?;
    let phone = phone(&owner_anchor())?;
    let outcome = begin(
        &store,
        &desk,
        &begin_input("req-cancel", &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW,
    )?;
    let refs = saved_refs(&store, "req-cancel")?;
    let cancel_bytes = encode_register_cancel(&RegisterCancel {
        request_id: "req-cancel".into(),
        request_hash: outcome.request_hash.clone(),
    })?;
    let record = cancel(&store, &desk, &cancel_bytes, NOW + 5)?;
    assert_eq!(record.state, AgentCreationState::Cancelled);
    assert_items_gone(&desk, &refs)?;
    let wrong = encode_register_cancel(&RegisterCancel {
        request_id: "req-cancel".into(),
        request_hash: encode_base64url([0x33_u8; 32]),
    })?;
    assert!(cancel(&store, &desk, &wrong, NOW + 6).is_err(), "a cancel for another plan refuses");
    Ok(())
}

#[cfg(unix)]
#[test]
fn failing_vault_delete_gives_cleanup_pending_then_retries_to_terminal() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new()?;
    let store = AgentCreationStore::open(dir.path(), HUMAN)?;
    let vault_dir = dir.path().join("vault");
    std::fs::create_dir_all(&vault_dir)?;
    let desk = MemoryPrimaryVault::persist_at(vault_dir.join("items.json"))?;
    let phone = phone(&owner_anchor())?;
    let outcome = begin(
        &store,
        &desk,
        &begin_input("req-del", &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW,
    )?;
    let refs = saved_refs(&store, "req-del")?;
    std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o500))?;
    let record = resume_request(&store, &desk, "req-del", NOW + 400);
    std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o700))?;
    let record = record?;
    assert_eq!(
        record.state,
        AgentCreationState::CleanupPending,
        "a failed delete is never success"
    );
    assert_eq!(record.intended, Some(AgentCreationState::Expired));
    assert!(
        !refs.is_empty() && record.vault_refs.len() == refs.len(),
        "every undeleted reference is kept"
    );
    let retried = resume_request(&store, &desk, "req-del", NOW + 401)?;
    assert_eq!(retried.state, AgentCreationState::Expired, "a later run finishes the cleanup");
    assert_eq!(retried.vault_refs, Vec::<String>::new(), "no pending item is left");
    assert_ne!(outcome.plan_bytes, Vec::<u8>::new(), "a plan was produced");
    Ok(())
}

#[test]
fn reopening_after_restart_keeps_the_original_deadline() -> TestResult {
    let dir = TempDir::new()?;
    let phone = phone(&owner_anchor())?;
    let (store, desk) = desktop(&dir)?;
    let outcome = begin(
        &store,
        &desk,
        &begin_input("req-restart", &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW,
    )?;
    let original_expiry = outcome_expiry(&outcome)?;
    drop(store);
    let reopened = AgentCreationStore::open(dir.path(), HUMAN)?;
    let again = begin(
        &reopened,
        &desk,
        &begin_input("req-restart", &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW + 100,
    )?;
    assert_eq!(again.plan_bytes, outcome.plan_bytes, "a restart re-reads the stored plan");
    let record = reopened.load("req-restart")?.ok_or("record must exist after restart")?;
    assert_eq!(record.expires_at, original_expiry, "the 300 second deadline is not restarted");
    assert_eq!(record.state, AgentCreationState::AuthorizationPending);
    Ok(())
}

#[test]
fn stored_issue_time_in_the_future_expires_the_request() -> TestResult {
    let dir = TempDir::new()?;
    let phone = phone(&owner_anchor())?;
    let (store, desk) = desktop(&dir)?;
    let outcome = begin(
        &store,
        &desk,
        &begin_input("req-clock", &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW,
    )?;
    let refs = saved_refs(&store, "req-clock")?;
    let record = resume_request(&store, &desk, "req-clock", NOW - 1)?;
    assert_eq!(
        record.state,
        AgentCreationState::Expired,
        "a clock behind the stored issue time expires it"
    );
    assert_items_gone(&desk, &refs)?;
    assert_ne!(outcome.plan_bytes, Vec::<u8>::new(), "a plan was produced");
    Ok(())
}

#[test]
fn begin_refuses_a_primary_branch_that_is_already_invalid() -> TestResult {
    let dir = TempDir::new()?;
    let phone = phone(&owner_anchor())?;
    let (store, desk) = desktop(&dir)?;
    let refused = begin(
        &store,
        &desk,
        &begin_input("req-old", &owner_anchor(), &phone.primary_device, NOW),
        NOW,
    );
    assert!(
        matches!(refused, Err(SdkError::CustodyExpired)),
        "an expired primary branch starts nothing"
    );
    assert!(store.load("req-old")?.is_none(), "no record is written for a refused start");
    Ok(())
}

/// The deadline of a begun request, read back from its plan.
fn outcome_expiry(outcome: &super::BeginOutcome) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(ramflux_protocol::custody::decode_register_plan(&outcome.plan_bytes)?.expires_at)
}

/// A master request with a fixed self-signing key, so a retry builds byte-identical input.
fn fixed_request(
    master: &MasterKey,
    self_key: &str,
    external: &DeviceRef,
    range: u64,
    previous: Option<
        ramflux_protocol::custody::Envelope<ramflux_protocol::custody::MasterCertificate>,
    >,
    issued_at: u64,
) -> Result<AgentMasterRequest, Box<dyn std::error::Error>> {
    Ok(AgentMasterRequest {
        purpose: if previous.is_some() {
            AgentMasterPurpose::Rebind
        } else {
            AgentMasterPurpose::Create
        },
        anchor: master_anchor(master)?,
        principal_id: PRINCIPAL.into(),
        principal_kind: ramflux_protocol::PrincipalKind::HeadlessAi,
        cert_id: encode_base64url([7_u8; 32]),
        self_signing_public_key: self_key.into(),
        external_ref: external.clone(),
        range,
        previous,
        issued_at,
    })
}

#[test]
fn certificate_retry_returns_the_recorded_certificate_and_a_changed_request_refuses() -> TestResult
{
    let dir = TempDir::new()?;
    let (_store, vault) = desktop(&dir)?;
    let phone = phone(&owner_anchor())?;
    let master = MasterKey::generate()?;
    let self_key = SelfSigningKey::generate()?.public_key();
    let reference = format!("agent-master:{}", encode_base64url([9_u8; 32]));
    vault.store_agent_master(&reference, &master)?;
    let genesis = vault.certify_agent_master(
        &reference,
        fixed_request(&master, &self_key, &phone.primary_device, 1, None, NOW)?,
    )?;
    // A retry after a crash between the insert and the reply returns the recorded certificate.
    let retry = vault.certify_agent_master(
        &reference,
        fixed_request(&master, &self_key, &phone.primary_device, 1, None, NOW)?,
    )?;
    assert_eq!(object_hash(&genesis)?, object_hash(&retry)?, "the genesis retry is identical");
    let other_time = fixed_request(&master, &self_key, &phone.primary_device, 1, None, NOW + 1)?;
    assert!(
        vault.certify_agent_master(&reference, other_time).is_err(),
        "a different genesis for a recorded range refuses"
    );
    let rebound = vault.certify_agent_master(
        &reference,
        fixed_request(&master, &self_key, &phone.primary_device, 2, Some(genesis.clone()), NOW)?,
    )?;
    let rebind_retry = vault.certify_agent_master(
        &reference,
        fixed_request(&master, &self_key, &phone.primary_device, 2, Some(genesis.clone()), NOW)?,
    )?;
    assert_eq!(
        object_hash(&rebound)?,
        object_hash(&rebind_retry)?,
        "the rebind retry is identical"
    );
    let rebind_other =
        fixed_request(&master, &self_key, &phone.primary_device, 2, Some(genesis), NOW + 1)?;
    assert!(
        vault.certify_agent_master(&reference, rebind_other).is_err(),
        "a different rebind for a recorded range refuses"
    );
    Ok(())
}

#[test]
fn delete_agent_master_removes_the_seed_and_every_certificate_item() -> TestResult {
    let dir = TempDir::new()?;
    let (_store, vault) = desktop(&dir)?;
    let phone = phone(&owner_anchor())?;
    let master = MasterKey::generate()?;
    let self_key = SelfSigningKey::generate()?.public_key();
    let id = encode_base64url([9_u8; 32]);
    let reference = format!("agent-master:{id}");
    vault.store_agent_master(&reference, &master)?;
    let genesis = vault.certify_agent_master(
        &reference,
        fixed_request(&master, &self_key, &phone.primary_device, 1, None, NOW)?,
    )?;
    vault.certify_agent_master(
        &reference,
        fixed_request(&master, &self_key, &phone.primary_device, 2, Some(genesis), NOW)?,
    )?;
    let cert_1 = format!("agent-master-cert:{id}:1");
    let cert_2 = format!("agent-master-cert:{id}:2");
    for item in [&reference, &cert_1, &cert_2] {
        assert!(AgentMasterCells::read_item(&vault, item)?.is_some(), "{item} is recorded");
    }
    vault.delete_agent_master(&reference, 2)?;
    for item in [&reference, &cert_1, &cert_2] {
        assert!(AgentMasterCells::read_item(&vault, item)?.is_none(), "{item} is removed");
    }
    let after = fixed_request(&master, &self_key, &phone.primary_device, 1, None, NOW)?;
    assert!(vault.certify_agent_master(&reference, after).is_err(), "a deleted master refuses");
    Ok(())
}

/// Desktop-side request for the custody receive tests.
fn custody_request(
    dir: &TempDir,
    id: &str,
    phone: &Phone,
) -> Result<(AgentCreationStore, MemoryPrimaryVault, super::BeginOutcome), SdkError> {
    let (store, desk) = desktop(dir)?;
    let outcome = begin(
        &store,
        &desk,
        &begin_input(id, &owner_anchor(), &phone.primary_device, NOW + 9_000),
        NOW,
    )?;
    Ok((store, desk, outcome))
}

#[test]
fn custody_scope_is_the_derived_owner_agent_scope_only() -> TestResult {
    let dir = TempDir::new()?;
    let phone = phone(&owner_anchor())?;
    let (_store, _desk, outcome) = custody_request(&dir, "req-scope", &phone)?;
    let owner = owner_anchor();
    let plan = decode_register_plan(&outcome.plan_bytes)?;
    let right = expected_scope(&owner, &plan.agent_anchor)?;
    let accepted = check_received_request(
        &outcome.plan_bytes,
        &right,
        &owner,
        &owner,
        DESKTOP_DEVICE,
        PRIMARY_DEVICE,
    )?;
    assert_eq!(accepted.request_id, "req-scope", "the matching scope admits the plan");
    let other_agent = encode_base64url([8_u8; 32]);
    let wrong = expected_scope(&owner, &other_agent)?;
    assert!(
        check_received_request(
            &outcome.plan_bytes,
            &wrong,
            &owner,
            &owner,
            DESKTOP_DEVICE,
            PRIMARY_DEVICE
        )
        .is_err(),
        "a scope derived for another agent must refuse"
    );
    assert!(
        check_received_request(
            &outcome.plan_bytes,
            &owner,
            &owner,
            &owner,
            DESKTOP_DEVICE,
            PRIMARY_DEVICE
        )
        .is_err(),
        "the bare owner anchor is not a conversation scope"
    );
    assert!(expected_scope(&owner, &owner).is_err(), "equal roots never derive a self scope");
    Ok(())
}

#[test]
fn custody_packet_refuses_non_sibling_sources_and_a_secondary_as_primary() -> TestResult {
    let dir = TempDir::new()?;
    let phone = phone(&owner_anchor())?;
    let (_store, _desk, outcome) = custody_request(&dir, "req-sibling", &phone)?;
    let owner = owner_anchor();
    let agent = decode_register_plan(&outcome.plan_bytes)?.agent_anchor;
    let scope = expected_scope(&owner, &agent)?;
    let foreign_root = encode_base64url([8_u8; 32]);
    let refuse = |source_root: &str, source: &str, local: &str| {
        check_received_request(&outcome.plan_bytes, &scope, &owner, source_root, source, local)
            .is_err()
    };
    assert!(refuse(&foreign_root, DESKTOP_DEVICE, PRIMARY_DEVICE), "another root is not a sibling");
    assert!(refuse(&owner, PRIMARY_DEVICE, PRIMARY_DEVICE), "a device cannot send to itself");
    assert!(refuse(&owner, "other-desktop", PRIMARY_DEVICE), "the plan names one desktop only");
    assert!(refuse(&owner, DESKTOP_DEVICE, "secondary-laptop"), "a secondary is not the primary");
    assert!(check_sender(&owner, &owner, DESKTOP_DEVICE, PRIMARY_DEVICE).is_ok());
    assert!(check_sender(&owner, &foreign_root, DESKTOP_DEVICE, PRIMARY_DEVICE).is_err());
    Ok(())
}

#[test]
fn custody_plan_and_decision_apply_once_and_replays_return_the_saved_record() -> TestResult {
    let dir = TempDir::new()?;
    let phone = phone(&owner_anchor())?;
    let (store, desk, outcome) = custody_request(&dir, "req-replay", &phone)?;
    let phone_dir = TempDir::new()?;
    let phone_store = AgentCreationStore::open(phone_dir.path(), HUMAN)?;
    let first = receive_plan(&phone_store, &outcome.plan_bytes, NOW + 1)?;
    assert_eq!(first.state, AgentCreationState::AuthorizationPending);
    let replay = receive_plan(&phone_store, &outcome.plan_bytes, NOW + 2)?;
    assert_eq!(replay.request_hash, first.request_hash, "an exact replay returns the saved plan");
    let mut altered = decode_register_plan(&outcome.plan_bytes)?;
    altered.display_name = "Support agent two".into();
    let altered_bytes = encode_register_plan(&altered)?;
    assert!(
        receive_plan(&phone_store, &altered_bytes, NOW + 2).is_err(),
        "the same request id with another plan must refuse"
    );
    let plan = decode_register_plan(&outcome.plan_bytes)?;
    let late_dir = TempDir::new()?;
    let late = AgentCreationStore::open(late_dir.path(), HUMAN)?;
    assert!(
        matches!(
            receive_plan(&late, &outcome.plan_bytes, plan.expires_at),
            Err(SdkError::CustodyExpired)
        ),
        "a plan received at its expiry is expired"
    );

    phone.vault.approve_agent_decision_once_for_test(&outcome.request_hash)?;
    let approve = primary_sign_decision(
        &phone.vault,
        &signing(&phone, &phone.primary_device),
        &outcome.plan_bytes,
        RegisterOutcome::Approve,
        NOW + 3,
    )?;
    let authorized =
        apply_decision(&store, &desk, "req-replay", &approve, &phone.branch_public, NOW + 3)?;
    assert_eq!(authorized.state, AgentCreationState::Authorized);
    let again =
        apply_decision(&store, &desk, "req-replay", &approve, &phone.branch_public, NOW + 4)?;
    assert_eq!(again.state, AgentCreationState::Authorized, "an exact replay changes nothing");

    // The vault consumes the approval for this plan hash once: a second decision for the same
    // plan cannot be signed at all, so no differing decision can reach the desktop.
    let second = primary_sign_decision(
        &phone.vault,
        &signing(&phone, &phone.primary_device),
        &outcome.plan_bytes,
        RegisterOutcome::Deny,
        NOW + 4,
    );
    assert!(second.is_err(), "a consumed plan approval must not sign a second decision");
    Ok(())
}

/// Principal and device names of the human fixture: the primary phone and a paired desktop.
const HUMAN_PRINCIPAL: &str = "principal-human";
const HUMAN_PRIMARY_DEVICE: &str = "primary";

/// A live human account on a fresh data root with two active devices in its authority: the primary
/// (genesis, signed by the human primary key) and the desktop, a successor record signed by the
/// same key with a `sync` branch. The phone-side keys of these tests are separate, as in production.
struct HumanFixture {
    root: crate::custody::tests::Root,
    now: u64,
    anchor: String,
    primary: DeviceRef,
    head: String,
}

/// The desktop device of the human fixture, with a branch signed by the human primary key.
fn with_desktop_device(
    primary: &SelfSigningKey,
    base: &Envelope<DeviceSet>,
    now: u64,
) -> Result<Envelope<DeviceSet>, Box<dyn std::error::Error>> {
    let branch = create_device_branch_from_seed(
        HUMAN_PRINCIPAL,
        DESKTOP_DEVICE,
        1,
        &Zeroizing::new([27_u8; 32]),
    );
    let signing = encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let agreement = encode_base64url(X25519KeyPair::from_seed([28_u8; 32]).public);
    let (signing_commitment, agreement_commitment) =
        ramflux_crypto::device_key_commitments(&signing, &agreement)?;
    let branch_cert = primary.certify_branch(BranchCertificate {
        schema: domain::CUSTODY_BRANCH_CERTIFICATE.into(),
        version: 1,
        account_anchor: base.body.account_anchor.clone(),
        master_certificate_hash: object_hash(&base.body.master_certificate)?,
        device_id: DESKTOP_DEVICE.into(),
        device_epoch: 1,
        principal_kind: PrincipalKind::Human,
        branch_signing_public_key: signing,
        agreement_identity_public_key: agreement,
        capabilities: ["call", "group", "message", "register", "sync"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        not_before: now,
        expires_at: now + MAX_BRANCH_LEASE_SECONDS,
        cert_id: encode_base64url([29_u8; 32]),
    })?;
    let mut body = base.body.clone();
    body.devices.push(Device {
        device_id: DESKTOP_DEVICE.into(),
        device_epoch: 1,
        signing_key_commitment: signing_commitment,
        agreement_key_commitment: agreement_commitment,
        status: DeviceSetStatus::Active,
        revoked_at: None,
        branch_certificate: Some(branch_cert),
        message_layer: None,
        migration_state: MigrationState::Native,
    });
    // The roster is sorted by device id and must stay unique (`desktop-device` before `primary`).
    body.devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    Ok(primary.sign_record(body)?)
}

fn human_fixture() -> Result<HumanFixture, Box<dyn std::error::Error>> {
    let root = crate::custody::tests::Root::new()?;
    let vault = crate::custody::tests::TestVault::default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .saturating_sub(60);
    let master = MasterKey::from_vault_seed(&Zeroizing::new([21_u8; 32]));
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([22_u8; 32]));
    let signing_seed = Zeroizing::new([23_u8; 32]);
    let branch =
        create_device_branch_from_seed(HUMAN_PRINCIPAL, HUMAN_PRIMARY_DEVICE, 1, &signing_seed);
    let agreement = X25519KeyPair::from_seed([24_u8; 32]);
    let base = create_genesis(
        &master,
        &primary,
        &branch,
        &agreement,
        GenesisInput {
            principal_kind: PrincipalKind::Human,
            display_name: "Example Human".into(),
            issued_at: now,
            master_cert_id: encode_base64url([25_u8; 32]),
            branch_cert_id: encode_base64url([26_u8; 32]),
            external_human_primary: None,
        },
    )?;
    let record = with_desktop_device(&primary, &base, now)?;
    let mut seeds = Zeroizing::new([0_u8; 64]);
    seeds[..32].copy_from_slice(&signing_seed[..]);
    seeds[32..].copy_from_slice(&[24_u8; 32]);
    let input = CreateInput {
        local_account_id: HUMAN.into(),
        principal_id: HUMAN_PRINCIPAL.into(),
        device_id: HUMAN_PRIMARY_DEVICE.into(),
        display_name: "Example Human".into(),
        principal_kind: PrincipalKind::Human,
        custodian_account_id: None,
    };
    crate::custody::store::persist(
        &root.0,
        &input,
        GenesisMaterial {
            record,
            primary: &primary,
            branch: Some(&seeds),
            now,
            data_secret: None,
            commit_gate: None,
            pre_staged: false,
        },
        &vault,
    )?;
    crate::custody::tests::mark_live(&root.0, HUMAN, now)?;
    let account = crate::custody::store::load_account(&root.0, HUMAN, now)?;
    let record = account.record();
    Ok(HumanFixture {
        anchor: record.body.account_anchor.clone(),
        primary: record.body.master_certificate.body.primary_device_ref.clone(),
        head: object_hash(record)?,
        root,
        now,
    })
}

/// Begin a request against the human fixture; `head` overrides the human head hash when given.
/// The desktop named here is the fixture's desktop device, whose branch is in the authority.
fn begin_for_human(
    fixture: &HumanFixture,
    store: &AgentCreationStore,
    desk: &MemoryPrimaryVault,
    request_id: &str,
    head: Option<&str>,
) -> Result<BeginOutcome, Box<dyn std::error::Error>> {
    let desktop = DeviceRef {
        account_anchor: fixture.anchor.clone(),
        device_id: DESKTOP_DEVICE.into(),
        device_epoch: 1,
    };
    begin_for_human_as(fixture, store, desk, request_id, head, &desktop)
}

/// Like [`begin_for_human`], with the desktop device named by `desktop`.
fn begin_for_human_as(
    fixture: &HumanFixture,
    store: &AgentCreationStore,
    desk: &MemoryPrimaryVault,
    request_id: &str,
    head: Option<&str>,
    desktop: &DeviceRef,
) -> Result<BeginOutcome, Box<dyn std::error::Error>> {
    let mut input =
        begin_input(request_id, &fixture.anchor, &fixture.primary, fixture.now + 10_000);
    input.human_head_hash = head.unwrap_or(&fixture.head).to_owned();
    input.desktop = desktop.clone();
    Ok(begin(store, desk, &input, fixture.now)?)
}

/// One approval from the human primary (presence armed for this plan), applied to the request.
fn approve_for_human(
    fixture: &HumanFixture,
    phone: &Phone,
    store: &AgentCreationStore,
    desk: &MemoryPrimaryVault,
    outcome: &BeginOutcome,
) -> Result<AgentCreationRecord, Box<dyn std::error::Error>> {
    phone.vault.approve_agent_decision_once_for_test(&outcome.request_hash)?;
    let approve = primary_sign_decision(
        &phone.vault,
        &signing(phone, &fixture.primary),
        &outcome.plan_bytes,
        RegisterOutcome::Approve,
        fixture.now + 1,
    )?;
    Ok(apply_decision(
        store,
        desk,
        &outcome.request_id,
        &approve,
        &phone.branch_public,
        fixture.now + 1,
    )?)
}

fn agent_account_dir(root: &std::path::Path, account_id: &str) -> std::path::PathBuf {
    root.join("custody_accounts").join(account_id)
}

fn account_id_of(record: &AgentCreationRecord) -> Result<String, Box<dyn std::error::Error>> {
    Ok(record.account_id.clone().ok_or("the desktop record names its account")?)
}

#[test]
fn commit_refuses_before_approval_and_writes_no_account() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN)?;
    let desk = MemoryPrimaryVault::default();
    let outcome = begin_for_human(&fixture, &store, &desk, "req-unapproved", None)?;
    let account_id = account_id_of(&store.load("req-unapproved")?.ok_or("record")?)?;
    assert!(commit_approved(&store, &desk, HUMAN, "req-unapproved", fixture.now + 2).is_err());
    assert!(
        !agent_account_dir(&fixture.root.0, &account_id).exists(),
        "no account directory before a verified approval"
    );
    assert_eq!(outcome.state, AgentCreationState::AuthorizationPending);
    Ok(())
}

#[test]
fn commit_writes_the_bundle_once_after_a_verified_approval() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN)?;
    let desk = MemoryPrimaryVault::default();
    let phone = phone(&owner_anchor())?;
    let outcome = begin_for_human(&fixture, &store, &desk, "req-commit", None)?;
    let authorized = approve_for_human(&fixture, &phone, &store, &desk, &outcome)?;
    assert_eq!(authorized.state, AgentCreationState::Authorized);
    let account_id = account_id_of(&authorized)?;
    assert!(!store.committed(&authorized)?, "approval alone is not a commit");

    let committed = commit_approved(&store, &desk, HUMAN, "req-commit", fixture.now + 2)?;
    assert_eq!(committed.state, AgentCreationState::PublicationPending);
    assert!(store.account_committed(&account_id)?, "the commit writes the authority");
    let again = commit_approved(&store, &desk, HUMAN, "req-commit", fixture.now + 3)?;
    assert_eq!(again, committed, "a second commit returns the saved record and writes nothing");
    let account =
        crate::custody::store::load_account(&fixture.root.0, &account_id, fixture.now + 3)?;
    assert_eq!(account.local_account_id(), account_id);
    assert_eq!(account.record().body.principal_kind, ramflux_protocol::PrincipalKind::HeadlessAi);
    let plan = decode_register_plan(&outcome.plan_bytes)?;
    assert_eq!(account.record().body.account_anchor, plan.agent_anchor);
    Ok(())
}

#[test]
fn deny_cancel_and_expiry_after_the_commit_delete_nothing() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN)?;
    let desk = MemoryPrimaryVault::default();
    let phone = phone(&owner_anchor())?;
    let outcome = begin_for_human(&fixture, &store, &desk, "req-late", None)?;
    approve_for_human(&fixture, &phone, &store, &desk, &outcome)?;
    let committed = commit_approved(&store, &desk, HUMAN, "req-late", fixture.now + 2)?;
    let refs = committed.vault_refs.clone();
    assert!(!refs.is_empty(), "the committed request still names its vault items");

    // The approval is one-shot per plan hash, so no second decision can be signed. An exact
    // replay of the saved approval is accepted without effect; altered bytes are refused.
    let saved = committed.decision_bytes()?.ok_or("the approval must be saved")?;
    let replay =
        apply_decision(&store, &desk, "req-late", &saved, &phone.branch_public, fixture.now + 3)?;
    assert_eq!(replay.state, AgentCreationState::PublicationPending, "a replay changes nothing");
    let mut altered = saved.clone();
    let last = altered.last_mut().ok_or("the decision is not empty")?;
    *last ^= 0x01;
    assert!(
        apply_decision(&store, &desk, "req-late", &altered, &phone.branch_public, fixture.now + 3)
            .is_err(),
        "a different decision after the commit is not applied"
    );
    let cancel_bytes = encode_register_cancel(&RegisterCancel {
        request_id: "req-late".into(),
        request_hash: outcome.request_hash.clone(),
    })?;
    assert!(cancel(&store, &desk, &cancel_bytes, fixture.now + 3).is_err());
    let expired_at = decode_register_plan(&outcome.plan_bytes)?.expires_at + 1;
    let after = resume_request(&store, &desk, "req-late", expired_at)?;
    assert_eq!(after.state, AgentCreationState::PublicationPending, "expiry never cleans a commit");
    assert_eq!(after.vault_refs, refs, "no pending item is removed after the commit");
    assert_items_present(&desk, &refs)?;
    assert!(store.committed(&committed)?);
    Ok(())
}

#[test]
fn restart_in_publication_pending_keeps_the_bundle() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN)?;
    let desk = MemoryPrimaryVault::default();
    let phone = phone(&owner_anchor())?;
    let outcome = begin_for_human(&fixture, &store, &desk, "req-restart", None)?;
    approve_for_human(&fixture, &phone, &store, &desk, &outcome)?;
    let committed = commit_approved(&store, &desk, HUMAN, "req-restart", fixture.now + 2)?;
    let reopened = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN)?;
    let resumed = resume_request(&reopened, &desk, "req-restart", fixture.now + 4)?;
    assert_eq!(resumed.state, AgentCreationState::PublicationPending);
    assert_items_present(&desk, &committed.vault_refs)?;
    assert!(reopened.committed(&committed)?);
    Ok(())
}

#[test]
fn a_crash_after_the_authority_write_is_recovered_as_committed() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN)?;
    let desk = MemoryPrimaryVault::default();
    let phone = phone(&owner_anchor())?;
    let outcome = begin_for_human(&fixture, &store, &desk, "req-crash", None)?;
    let authorized = approve_for_human(&fixture, &phone, &store, &desk, &outcome)?;
    commit_approved(&store, &desk, HUMAN, "req-crash", fixture.now + 2)?;
    // Simulate the crash window: the authority exists but the record still says authorized.
    store.save(&AgentCreationRecord { state: AgentCreationState::Authorized, ..authorized })?;
    let expired_at = decode_register_plan(&outcome.plan_bytes)?.expires_at + 1;
    let recovered = resume_request(&store, &desk, "req-crash", expired_at)?;
    assert_eq!(recovered.state, AgentCreationState::PublicationPending);
    assert_items_present(&desk, &recovered.vault_refs)?;
    Ok(())
}

#[test]
fn commit_refuses_a_changed_human_head_and_cleans_up_before_the_commit() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN)?;
    let desk = MemoryPrimaryVault::default();
    let phone = phone(&owner_anchor())?;
    let stale = encode_base64url([0x5a_u8; 32]);
    let outcome = begin_for_human(&fixture, &store, &desk, "req-head", Some(stale.as_str()))?;
    let refs = store.load("req-head")?.ok_or("record")?.vault_refs;
    approve_for_human(&fixture, &phone, &store, &desk, &outcome)?;
    assert!(commit_approved(&store, &desk, HUMAN, "req-head", fixture.now + 2).is_err());
    let refused = store.load("req-head")?.ok_or("record")?;
    assert_eq!(refused.state, AgentCreationState::Refused);
    assert_eq!(refused.failure, Some(AgentFailure::CreationPrimaryChanged));
    assert_items_gone(&desk, &refs)?;
    Ok(())
}

#[test]
fn commit_refuses_a_desktop_missing_from_the_authority_and_cleans_up() -> TestResult {
    let fixture = human_fixture()?;
    let store = AgentCreationStore::open(fixture.root.0.to_path_buf(), HUMAN)?;
    let desk = MemoryPrimaryVault::default();
    let phone = phone(&owner_anchor())?;
    // The plan names a desktop device with no branch in the human authority at commit time.
    let absent = DeviceRef {
        account_anchor: fixture.anchor.clone(),
        device_id: "removed-desktop".into(),
        device_epoch: 1,
    };
    let outcome = begin_for_human_as(&fixture, &store, &desk, "req-desktop", None, &absent)?;
    let refs = store.load("req-desktop")?.ok_or("record")?.vault_refs;
    approve_for_human(&fixture, &phone, &store, &desk, &outcome)?;
    assert!(commit_approved(&store, &desk, HUMAN, "req-desktop", fixture.now + 2).is_err());
    let refused = store.load("req-desktop")?.ok_or("record")?;
    assert_eq!(refused.state, AgentCreationState::Refused);
    assert_eq!(refused.failure, Some(AgentFailure::CreationPrimaryChanged));
    assert!(
        !agent_account_dir(&fixture.root.0, &account_id_of(&refused)?).exists(),
        "a refused enrollment writes no account directory"
    );
    assert_items_gone(&desk, &refs)?;
    Ok(())
}

#[test]
fn desktop_enrollment_needs_a_present_unexpired_sync_branch() -> TestResult {
    let fixture = human_fixture()?;
    let account = crate::custody::store::load_account(&fixture.root.0, HUMAN, fixture.now)?;
    let record = account.record();
    let device = record
        .body
        .devices
        .iter()
        .find(|device| device.device_id == DESKTOP_DEVICE)
        .ok_or("the human authority names the desktop device")?;
    let branch = device.branch_certificate.as_ref().ok_or("the desktop device has a branch")?;
    let desktop = DeviceRef {
        account_anchor: fixture.anchor.clone(),
        device_id: device.device_id.clone(),
        device_epoch: device.device_epoch,
    };
    assert!(
        desktop_is_enrolled(record, &desktop, fixture.now),
        "an active branch valid at now with the sync capability is enrolled"
    );
    assert!(
        !desktop_is_enrolled(record, &desktop, branch.body.expires_at),
        "at its expiry instant the branch is no longer enrolled"
    );
    assert!(
        !desktop_is_enrolled(record, &desktop, branch.body.not_before.saturating_sub(1)),
        "before its not_before the branch is not enrolled"
    );
    let mut revoked = record.clone();
    if let Some(entry) = revoked.body.devices.iter_mut().find(|entry| entry.device_id == DESKTOP_DEVICE) {
        entry.status = DeviceSetStatus::Revoked;
    }
    assert!(
        !desktop_is_enrolled(&revoked, &desktop, fixture.now),
        "a revoked device is not enrolled, whatever its branch says"
    );
    Ok(())
}

/// Every named vault item of a committed bundle must still be present.
fn assert_items_present(vault: &MemoryPrimaryVault, refs: &[String]) -> TestResult {
    assert!(!refs.is_empty(), "the bundle must name its vault items");
    let device = DeviceRef {
        account_anchor: owner_anchor(),
        device_id: DESKTOP_DEVICE.into(),
        device_epoch: 1,
    };
    for reference in refs {
        let present = if reference.starts_with("agent-master:") {
            // Storing succeeds only when the item is absent; a refusal means it is present.
            vault.store_agent_master(reference, &MasterKey::generate()?).is_err()
        } else if reference.starts_with("branch:") {
            vault.load_branch(reference, PRINCIPAL, &device).is_ok()
        } else if reference.starts_with("agent-provisioning:") {
            vault.load_provisioning_secret(reference).is_ok()
        } else {
            vault.load_primary(reference).is_ok()
        };
        assert!(present, "committed vault item {reference} must still exist");
    }
    Ok(())
}
