// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Desktop creation state machine for one agent (contract §7.2 steps 1–3 and §7.4), without
//! transport and without node calls. Every function takes its clock as `now` (unix seconds);
//! nothing reads the system clock. Byte inputs and outputs are canonical plan and decision bytes.
use super::state::{AgentCreationState, AgentFailure};
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use crate::custody::vault::AGENT_MASTER_PREFIX;
use crate::custody::{AgentDecisionSigning, PrimaryVault, valid_id};
use ramflux_crypto::custody::{MasterKey, SelfSigningKey, master_anchor, verify_register_decision};
use ramflux_crypto::{X25519KeyPair, create_device_branch_from_seed, random_32};
use ramflux_protocol::custody::{
    AGENT_REGISTER_VERSION, AgentDecisionRequest, AgentRegisterProfile, DeviceRef,
    GENESIS_BRANCH_CAPABILITIES, MAX_BRANCH_LEASE_SECONDS, REGISTER_PLAN_SCHEMA,
    REGISTER_TTL_SECONDS, RegisterCancel, RegisterOutcome, RegisterPlan, RegisterPurpose,
    decode_register_cancel, decode_register_decision, decode_register_plan,
    encode_register_decision, encode_register_plan, register_decision_body, register_plan_hash,
    validate_register_plan,
};
use ramflux_protocol::{encode_base64url, normalize_profile_display_name};
use zeroize::Zeroizing;

/// Public inputs of a creation request, all known on the desktop before the phone is asked.
pub struct BeginInput {
    pub request_id: String,
    pub owner_anchor: String,
    pub human_head_hash: String,
    pub human_primary: DeviceRef,
    pub desktop: DeviceRef,
    pub principal_id: String,
    pub display_name: String,
    pub profile: AgentRegisterProfile,
    /// Expiry of the current primary branch certificate; the plan never outlives it.
    pub primary_branch_expires_at: u64,
}

/// Result of `begin`: the exact plan that the phone reviews.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeginOutcome {
    pub request_id: String,
    pub request_hash: String,
    pub plan_bytes: Vec<u8>,
    pub state: AgentCreationState,
}

/// Fixed vault references of the pending agent secrets of one request.
struct PendingRefs {
    master: String,
    primary: String,
    branch: String,
    provisioning: String,
}

/// Inputs of the primary side that signs a decision.
pub struct PrimarySigning<'a> {
    /// The verified device of the current human primary; the plan must name exactly this device.
    pub primary_device: &'a DeviceRef,
    pub primary_reference: &'a str,
    pub expected_primary_public_key: &'a str,
    pub branch_reference: &'a str,
    pub principal_id: &'a str,
}

/// Start a creation request: choose the agent account id and its final vault references, keep the
/// pending agent secrets under those references and persist the plan. A repeated request id returns
/// the saved request (after the deadline check) and creates no second anchor.
/// # Errors
/// `CustodyExpired` when the primary branch is already invalid at `now`; typed vault refusals
/// when a pending secret cannot be stored (the request closes and its items are cleaned up).
pub fn begin(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    input: &BeginInput,
    now: u64,
) -> Result<BeginOutcome, SdkError> {
    valid_id(&input.request_id)?;
    if let Some(existing) = store.load(&input.request_id)? {
        let record = resume(store, vault, existing, now)?;
        return outcome(&record);
    }
    if input.primary_branch_expires_at <= now {
        return Err(SdkError::CustodyExpired);
    }
    let display_name = normalize_profile_display_name(&input.display_name)
        .map_err(|_| SdkError::CustodySetupInvalid)?;
    let master = MasterKey::generate().map_err(|_| SdkError::CustodyRandomUnavailable)?;
    let anchor = master_anchor(&master).map_err(|_| SdkError::CustodySetupInvalid)?;
    let account_id = random_id()?;
    // The final references of the committed account. Pending secrets are stored under them from
    // the start, so commit only writes the registry entry that points at them (no promotion).
    let reference =
        crate::custody::store::custody_vault_reference(store.root(), &account_id, &anchor)?;
    let refs = PendingRefs {
        master: format!("{AGENT_MASTER_PREFIX}{reference}"),
        primary: reference.clone(),
        branch: format!("branch:{reference}"),
        provisioning: format!("agent-provisioning:{reference}"),
    };
    // Record the references before any secret is written, so cleanup can always find them.
    let mut record = AgentCreationRecord {
        request_id: input.request_id.clone(),
        account_id: Some(account_id),
        request_hash: String::new(),
        plan_b64: String::new(),
        state: AgentCreationState::Preparing,
        issued_at: now,
        expires_at: now,
        vault_refs: vec![
            refs.master.clone(),
            refs.primary.clone(),
            refs.branch.clone(),
            refs.provisioning.clone(),
        ],
        intended: None,
        failure: None,
        decision_b64: None,
        master_range: 0,
        profile_b64: None,
        receipt_b64: None,
        agent_record_b64: None,
        intent_b64: None,
    };
    store.save(&record)?;

    let plan = match stage_secrets(vault, &refs, input, display_name, &master, now) {
        Ok(plan) => plan,
        Err(error) => {
            finish(
                store,
                vault,
                record,
                AgentCreationState::Refused,
                Some(AgentFailure::CustodyKeyUnavailable),
            )?;
            return Err(error);
        }
    };
    drop(master);
    let plan_bytes = encode_register_plan(&plan).map_err(|_| SdkError::CustodySetupInvalid)?;
    record.request_hash = register_plan_hash(&plan).map_err(|_| SdkError::CustodySetupInvalid)?;
    record.plan_b64 = encode_base64url(&plan_bytes);
    record.expires_at = plan.expires_at;
    record.state = AgentCreationState::AuthorizationPending;
    store.save(&record)?;
    outcome(&record)
}

/// Verify a phone decision against the exact stored plan and the independently refreshed primary
/// branch key, then apply it. Approve moves the request to `authorized`; deny cleans up.
/// An exact replay of the saved decision returns the saved record.
/// # Errors
/// `CustodyExpired` past the deadline; `CustodySetupInvalid` for a missing request, a body that
/// does not equal the one derived from the plan, or a signature that does not verify.
pub fn apply_decision(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    request_id: &str,
    decision_bytes: &[u8],
    primary_branch_public_key: &str,
    now: u64,
) -> Result<AgentCreationRecord, SdkError> {
    let record = store.load(request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
    let record = resume(store, vault, record, now)?;
    let encoded = encode_base64url(decision_bytes);
    if record.state != AgentCreationState::AuthorizationPending {
        return match record.state {
            AgentCreationState::Expired => Err(SdkError::CustodyExpired),
            _ if record.decision_b64.as_deref() == Some(encoded.as_str()) => Ok(record),
            _ => Err(SdkError::CustodySetupInvalid),
        };
    }
    let decision =
        decode_register_decision(decision_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    let expected = register_decision_body(&AgentDecisionRequest {
        plan_bytes: record.plan_bytes()?,
        plan_hash: record.request_hash.clone(),
        decision: decision.body.decision,
        signer: decision.body.signer.clone(),
        issued_at: decision.body.issued_at,
        expires_at: decision.body.expires_at,
    })
    .map_err(|_| SdkError::CustodySetupInvalid)?;
    if expected != decision.body {
        return Err(SdkError::CustodySetupInvalid);
    }
    verify_register_decision(primary_branch_public_key, &decision)
        .map_err(|_| SdkError::CustodySetupInvalid)?;
    if decision.body.expires_at <= now {
        return Err(SdkError::CustodyExpired);
    }
    let mut record = record;
    record.decision_b64 = Some(encoded);
    match decision.body.decision {
        RegisterOutcome::Approve => {
            record.state = AgentCreationState::Authorized;
            store.save(&record)?;
            Ok(record)
        }
        RegisterOutcome::Deny => finish(
            store,
            vault,
            record,
            AgentCreationState::Refused,
            Some(AgentFailure::AuthorizationRefused),
        ),
    }
}

/// Phone side: store a plan received over the own-device channel as an authorization-pending
/// request. It holds no secret; the phone keeps only the decision it later signs. An exact
/// replay returns the saved record. The same request id with a different plan refuses.
/// # Errors
/// `CustodyExpired` when `now` is before the plan issue time or at/after its expiry;
/// `CustodySetupInvalid` for a plan that fails validation or conflicts with the saved plan.
pub fn receive_plan(
    store: &AgentCreationStore,
    plan_bytes: &[u8],
    now: u64,
) -> Result<AgentCreationRecord, SdkError> {
    let plan = decode_register_plan(plan_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    validate_register_plan(&plan).map_err(|_| SdkError::CustodySetupInvalid)?;
    valid_id(&plan.request_id)?;
    let hash = register_plan_hash(&plan).map_err(|_| SdkError::CustodySetupInvalid)?;
    if let Some(existing) = store.load(&plan.request_id)? {
        return if existing.request_hash == hash {
            Ok(existing)
        } else {
            Err(SdkError::CustodySetupInvalid)
        };
    }
    if now < plan.issued_at || now >= plan.expires_at {
        return Err(SdkError::CustodyExpired);
    }
    let record = AgentCreationRecord {
        request_id: plan.request_id.clone(),
        account_id: None,
        request_hash: hash,
        plan_b64: encode_base64url(plan_bytes),
        state: AgentCreationState::AuthorizationPending,
        issued_at: plan.issued_at,
        expires_at: plan.expires_at,
        vault_refs: Vec::new(),
        intended: None,
        failure: None,
        decision_b64: None,
        master_range: 0,
        profile_b64: None,
        receipt_b64: None,
        agent_record_b64: None,
        intent_b64: None,
    };
    store.save(&record)?;
    Ok(record)
}

/// Apply a cancel from the initiating desktop. It closes pending intent and never touches a
/// request that already completed.
/// # Errors
/// `CustodySetupInvalid` for a request-hash mismatch or a request that cannot be cancelled.
pub fn cancel(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    cancel_bytes: &[u8],
    now: u64,
) -> Result<AgentCreationRecord, SdkError> {
    let RegisterCancel { request_id, request_hash } =
        decode_register_cancel(cancel_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    let record = store.load(&request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
    if record.request_hash != request_hash {
        return Err(SdkError::CustodySetupInvalid);
    }
    let record = resume(store, vault, record, now)?;
    match record.state {
        AgentCreationState::AuthorizationPending | AgentCreationState::Authorized => {
            finish(store, vault, record, AgentCreationState::Cancelled, None)
        }
        AgentCreationState::Refused
        | AgentCreationState::Expired
        | AgentCreationState::Cancelled
        | AgentCreationState::CleanupPending => Ok(record),
        _ => Err(SdkError::CustodySetupInvalid),
    }
}

/// Reopen one request after a restart: enforce the stored deadline and finish pending cleanup.
/// # Errors
/// Propagates store and vault failures; a request with no record is `CustodySetupInvalid`.
pub fn resume_request(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    request_id: &str,
    now: u64,
) -> Result<AgentCreationRecord, SdkError> {
    let record = store.load(request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
    resume(store, vault, record, now)
}

/// Primary side: sign the exact plan with the primary branch after user presence. The decision
/// is bound to the plan's human primary and expires with the plan.
/// # Errors
/// `CustodyExpired` outside the plan's validity window; vault refusals (no presence, wrong
/// signer, missing branch) pass through typed.
pub fn primary_sign_decision(
    vault: &dyn PrimaryVault,
    signing: &PrimarySigning<'_>,
    plan_bytes: &[u8],
    decision: RegisterOutcome,
    now: u64,
) -> Result<Vec<u8>, SdkError> {
    let plan = decode_register_plan(plan_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    if plan.human_primary != *signing.primary_device {
        return Err(SdkError::CustodySetupInvalid);
    }
    if now < plan.issued_at || now >= plan.expires_at {
        return Err(SdkError::CustodyExpired);
    }
    let request = AgentDecisionRequest {
        plan_bytes: plan_bytes.to_vec(),
        plan_hash: register_plan_hash(&plan).map_err(|_| SdkError::CustodySetupInvalid)?,
        decision,
        signer: plan.human_primary.clone(),
        issued_at: now,
        expires_at: plan.expires_at,
    };
    let signed = vault.sign_agent_register_decision(AgentDecisionSigning {
        primary_reference: signing.primary_reference,
        expected_primary_public_key: signing.expected_primary_public_key,
        branch_reference: signing.branch_reference,
        principal_id: signing.principal_id,
        request: &request,
    })?;
    encode_register_decision(&signed).map_err(|_| SdkError::CustodySetupInvalid)
}

/// Build the plan and create every pending secret, in the vault, under the final references.
fn stage_secrets(
    vault: &dyn PrimaryVault,
    refs: &PendingRefs,
    input: &BeginInput,
    display_name: String,
    master: &MasterKey,
    now: u64,
) -> Result<RegisterPlan, SdkError> {
    let anchor = master_anchor(master).map_err(|_| SdkError::CustodySetupInvalid)?;
    let self_signing =
        SelfSigningKey::generate().map_err(|_| SdkError::CustodyRandomUnavailable)?;
    let device_id = format!("device-{}", random_id()?);
    let signing_seed = Zeroizing::new(random_32().map_err(|_| SdkError::CustodyRandomUnavailable)?);
    let agreement_seed =
        Zeroizing::new(random_32().map_err(|_| SdkError::CustodyRandomUnavailable)?);
    let provisioning = agent_passphrase()?;
    let branch = create_device_branch_from_seed(&input.principal_id, &device_id, 1, &signing_seed);
    let agreement = X25519KeyPair::from_seed_ref(&agreement_seed);

    vault.store_agent_master(&refs.master, master)?;
    vault.store_new(&refs.primary, &self_signing)?;
    let mut seeds = Zeroizing::new([0_u8; 64]);
    seeds
        .iter_mut()
        .zip(signing_seed.iter().chain(agreement_seed.iter()))
        .for_each(|(slot, byte)| *slot = *byte);
    vault.store_branch(&refs.branch, &seeds)?;
    vault.store_provisioning_secret(&refs.provisioning, provisioning.as_bytes())?;

    let expires_at = now
        .checked_add(REGISTER_TTL_SECONDS)
        .map(|ttl| ttl.min(input.primary_branch_expires_at))
        .ok_or(SdkError::CustodyExpired)?;
    let branch_expires_at = now
        .checked_add(MAX_BRANCH_LEASE_SECONDS)
        .map(|lease| lease.min(input.primary_branch_expires_at))
        .ok_or(SdkError::CustodyExpired)?;
    let plan = RegisterPlan {
        schema: REGISTER_PLAN_SCHEMA.into(),
        version: AGENT_REGISTER_VERSION,
        request_id: input.request_id.clone(),
        purpose: RegisterPurpose::Create,
        owner_anchor: input.owner_anchor.clone(),
        human_head_hash: input.human_head_hash.clone(),
        human_primary: input.human_primary.clone(),
        desktop: input.desktop.clone(),
        agent_anchor: anchor.clone(),
        principal_id: input.principal_id.clone(),
        agent_device: DeviceRef { account_anchor: anchor, device_id, device_epoch: 1 },
        master_public_key: master.public_key(),
        self_signing_public_key: self_signing.public_key(),
        branch_signing_public_key: encode_base64url(branch.signing_key.verifying_key().to_bytes()),
        agreement_public_key: encode_base64url(agreement.public),
        capabilities: GENESIS_BRANCH_CAPABILITIES.iter().map(|value| (*value).to_owned()).collect(),
        display_name,
        certificate_issued_at: now,
        branch_not_before: now,
        branch_expires_at,
        master_cert_id: random_id()?,
        branch_cert_id: random_id()?,
        profile: input.profile.clone(),
        issued_at: now,
        expires_at,
        previous_agent_head_hash: None,
        previous_master_certificate_hash: None,
        next_range: 1,
    };
    Ok(plan)
}

/// Refuse a deadline that has passed, and a clock that moved behind the stored issue time.
fn deadline_passed(record: &AgentCreationRecord, now: u64) -> bool {
    now < record.issued_at || now >= record.expires_at
}

/// Apply the stored deadline and finish a cleanup that a previous run left pending.
pub(super) fn resume(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    record: AgentCreationRecord,
    now: u64,
) -> Result<AgentCreationRecord, SdkError> {
    match record.state {
        AgentCreationState::CleanupPending => {
            let target = record.intended.ok_or(SdkError::CustodySetupInvalid)?;
            finish(store, vault, record, target, None)
        }
        AgentCreationState::Authorized if store.committed(&record)? => {
            mark_publication_pending(store, record)
        }
        AgentCreationState::AuthorizationPending | AgentCreationState::Authorized
            if deadline_passed(&record, now) =>
        {
            finish(store, vault, record, AgentCreationState::Expired, None)
        }
        _ => Ok(record),
    }
}

/// Close a request: persist `cleanup_pending`, delete every pending vault item, then persist the
/// target state. A failed delete leaves the request in `cleanup_pending` and is never success.
pub(super) fn finish(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    mut record: AgentCreationRecord,
    target: AgentCreationState,
    failure: Option<AgentFailure>,
) -> Result<AgentCreationRecord, SdkError> {
    if record.state != AgentCreationState::CleanupPending {
        record.intended = Some(target);
        record.failure = failure.or(record.failure);
        record.state = AgentCreationState::CleanupPending;
        store.save(&record)?;
    }
    let target = record.intended.ok_or(SdkError::CustodySetupInvalid)?;
    let mut remaining = Vec::new();
    for reference in &record.vault_refs {
        // The agent master is deleted with every certificate item up to the recorded range.
        let deleted = if reference.starts_with(AGENT_MASTER_PREFIX) {
            vault.delete_agent_master(reference, record.master_range)
        } else {
            vault.delete(reference)
        };
        if deleted.is_err() {
            remaining.push(reference.clone());
        }
    }
    if remaining.is_empty() {
        record.vault_refs.clear();
        record.state = target;
    } else {
        record.vault_refs = remaining;
        record.state = AgentCreationState::CleanupPending;
    }
    store.save(&record)?;
    Ok(record)
}

/// The account authority exists: the commit happened (a crash came before the record was
/// updated). Nothing is cleaned up from here on; only the state moves on.
pub(super) fn mark_publication_pending(
    store: &AgentCreationStore,
    mut record: AgentCreationRecord,
) -> Result<AgentCreationRecord, SdkError> {
    record.state = AgentCreationState::PublicationPending;
    store.save(&record)?;
    Ok(record)
}

fn outcome(record: &AgentCreationRecord) -> Result<BeginOutcome, SdkError> {
    Ok(BeginOutcome {
        request_id: record.request_id.clone(),
        request_hash: record.request_hash.clone(),
        plan_bytes: record.plan_bytes()?,
        state: record.state,
    })
}

/// The agent's data passphrase: 32 random bytes as unpadded base64url text (43 characters), the
/// form `creation_confirm` gives agents. It is the sealed data secret and the activation
/// passphrase of the committed account, so it passes the same policy check as a new passphrase.
fn agent_passphrase() -> Result<Zeroizing<String>, SdkError> {
    let bytes = Zeroizing::new(random_32().map_err(|_| SdkError::CustodyRandomUnavailable)?);
    let text = Zeroizing::new(encode_base64url(*bytes));
    crate::passphrase::check_new_passphrase(&text)?;
    Ok(text)
}

pub(super) fn random_id() -> Result<String, SdkError> {
    Ok(encode_base64url(random_32().map_err(|_| SdkError::CustodyRandomUnavailable)?))
}
