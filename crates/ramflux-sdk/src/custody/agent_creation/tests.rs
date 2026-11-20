// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stage B exit tests: the vault operations and the creation state machine, driven by the real
//! `MemoryPrimaryVault`, real key generation and a `TempDir` store. Time is always an argument.
use super::{
    AgentCreationState, AgentCreationStore, AgentFailure, BeginInput, PrimarySigning,
    apply_decision, begin, cancel, primary_sign_decision, resume_request,
};
use crate::SdkError;
use crate::custody::vault::agent_master_item::AgentMasterCells;
use crate::custody::{PrimaryVault, memory_vault::MemoryPrimaryVault};
use ramflux_crypto::create_device_branch_from_seed;
use ramflux_crypto::custody::{
    AgentMasterPurpose, AgentMasterRequest, MasterKey, SelfSigningKey, master_anchor,
    verify_register_decision,
};
use ramflux_protocol::custody::{
    AgentRegisterProfile, DeviceRef, RegisterCancel, RegisterOutcome, decode_register_decision,
    encode_register_cancel, object_hash,
};
use ramflux_protocol::encode_base64url;
use tempfile::TempDir;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const NOW: u64 = 1_000;
const PRIMARY_DEVICE: &str = "primary-device";
const PRINCIPAL: &str = "agent-principal-1";
const DESKTOP_DEVICE: &str = "desktop-device";

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
    Ok((AgentCreationStore::open(dir.path().join("creation"))?, MemoryPrimaryVault::default()))
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
    let store = AgentCreationStore::open(dir.path().join("creation"))?;
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
    let reopened = AgentCreationStore::open(dir.path().join("creation"))?;
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
