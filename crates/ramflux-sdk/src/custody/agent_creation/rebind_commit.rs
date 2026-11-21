// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit of an authorized rebind (AGENT-IDENTITY-01 stage D4, contract 7.5). The agent master
//! certifies the next range against the stored certificate; the agent's self-signing key recertifies
//! the unchanged branch against the new certificate and signs the new `DeviceSet` and the new profile.
//! Nothing widens: keys, capabilities and the branch lease are the approved plan's, which must equal
//! the stored agent. Commit point: the rebind record moves to `publication_pending` once the
//! authority file carries the new record. Every step before it is idempotent, so a replay after a
//! crash reuses the recorded range and writes the same bytes.
//!
//! Pattern copied: `commit.rs` `commit_approved` (checks before any write, write-ahead of the range,
//! profile saved before the authority, the record state as the commit point).
use super::capability::require_agent_custody_authorization;
use super::commit::{agent_profile_bytes, desktop_is_enrolled};
use super::machine::finish;
use super::rebind::{RebindBinding, RebindEntry};
use super::rebind_plan::{check_decision_context, is_rebind};
use super::state::{AgentCreationState, AgentFailure};
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use crate::custody::vault::AGENT_MASTER_PREFIX;
use crate::custody::{PrimaryVault, store as custody_store};
use ramflux_crypto::custody::{
    AgentMasterPurpose, AgentMasterRequest, SelfSigningKey, verify_record,
};
use ramflux_protocol::PrincipalKind;
use ramflux_protocol::custody::{
    DeviceSet, Envelope, MasterCertificate, RegisterPlan, decode_register_plan, encode_epoch,
    object_hash,
};

/// Commit an authorized rebind of one agent against the verified current human authority `human`.
/// A repeated call on a committed request returns the saved record and writes nothing.
/// # Errors
/// `AgentCustodyUnsupported` when the capability is absent (nothing written); `CustodySetupInvalid`
/// for a request that is not an authorized rebind, or a stored agent that does not match the plan
/// (nothing written); a stale head, a primary that moved or a desktop that is not enrolled refuses
/// the request (`Refused`, with its typed reason); a master item or a self-signing key that is
/// missing or refused gives `CustodyVault(KeyUnavailable)` (`custody_key_unavailable`), the rebind
/// stays `Authorized`, the inventory says `rebind_pending` with that reason, and nothing is forged.
pub fn commit_rebind(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    human: &Envelope<DeviceSet>,
    request_id: &str,
    client_capabilities: &[String],
    now: u64,
) -> Result<AgentCreationRecord, SdkError> {
    require_agent_custody_authorization(client_capabilities)?;
    let mut record = store.load(request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
    if !is_rebind(&record) {
        return Err(SdkError::CustodySetupInvalid);
    }
    match record.state {
        AgentCreationState::PublicationPending
        | AgentCreationState::PublicationUnknown
        | AgentCreationState::Complete => return Ok(record),
        AgentCreationState::Authorized => {}
        _ => return Err(SdkError::CustodySetupInvalid),
    }
    let plan =
        decode_register_plan(&record.plan_bytes()?).map_err(|_| SdkError::CustodySetupInvalid)?;
    let account_id = record.account_id.clone().ok_or(SdkError::CustodySetupInvalid)?;
    if !desktop_is_enrolled(human, &plan.desktop, now) {
        finish(
            store,
            vault,
            record,
            AgentCreationState::Refused,
            Some(AgentFailure::CreationPairingRequired),
        )?;
        return Err(SdkError::AgentCreationRefused("creation_pairing_required"));
    }
    if check_decision_context(&plan, human, &plan.human_primary).is_err() {
        finish(
            store,
            vault,
            record,
            AgentCreationState::Refused,
            Some(AgentFailure::CreationPrimaryChanged),
        )?;
        return Err(SdkError::AgentCreationRefused("creation_primary_changed"));
    }
    let verified_human = verify_record(human, now, None, None)?;
    let stored = custody_store::stored_record_unverified(store.root(), &account_id)?;
    // A crash after the authority was written, before the commit point: the stored agent is already
    // the rebound record. Only the commit point is missing.
    if stored.body.master_certificate.body.range_index == plan.next_range
        && stored.body.master_certificate.body.primary_device_ref == plan.human_primary
    {
        return commit_point(store, record, &plan);
    }
    check_predecessors(&plan, &stored)?;
    check_no_widening(&plan, &stored)?;

    let reference =
        custody_store::custody_vault_reference(store.root(), &account_id, &plan.agent_anchor)?;
    let master_reference = format!("{AGENT_MASTER_PREFIX}{reference}");
    let Ok(self_signing) = vault.load_primary(&reference) else {
        return key_unavailable(store, &account_id, &plan);
    };
    // Write-ahead: the range is recorded before the certificate is requested, so a replay asks for
    // the same range and a cleanup would find it.
    record.master_range = plan.next_range;
    store.save(&record)?;
    let previous = stored.body.master_certificate.clone();
    let Ok(certificate) = vault.certify_agent_master(
        &master_reference,
        AgentMasterRequest {
            purpose: AgentMasterPurpose::Rebind,
            anchor: plan.agent_anchor.clone(),
            principal_id: plan.principal_id.clone(),
            principal_kind: PrincipalKind::HeadlessAi,
            cert_id: plan.master_cert_id.clone(),
            self_signing_public_key: plan.self_signing_public_key.clone(),
            external_ref: plan.human_primary.clone(),
            range: plan.next_range,
            previous: Some(previous),
            issued_at: plan.certificate_issued_at,
        },
    ) else {
        return key_unavailable(store, &account_id, &plan);
    };
    if certificate.body.master_public_key != plan.master_public_key
        || certificate.body.self_signing_public_key != plan.self_signing_public_key
    {
        return key_unavailable(store, &account_id, &plan);
    }
    let rebound = rebound_record(&stored, &plan, &self_signing, certificate)?;
    verify_record(&rebound, now, None, Some(&verified_human))?;
    // The profile is saved before the authority, so a crash after the authority still finds it.
    record.profile_b64 =
        Some(agent_profile_bytes(&self_signing, &plan, &rebound, &verified_human, now)?);
    store.save(&record)?;
    custody_store::replace_rebound_authority(
        store.root(),
        &account_id,
        &rebound,
        Some(&verified_human),
        now,
    )?;
    commit_point(store, record, &plan)
}

/// The commit point: the record moves to `publication_pending` and the inventory says `committed`.
/// Both are written after the authority, so a restart finds the authority in place.
fn commit_point(
    store: &AgentCreationStore,
    mut record: AgentCreationRecord,
    plan: &RegisterPlan,
) -> Result<AgentCreationRecord, SdkError> {
    let account_id = record.account_id.clone().ok_or(SdkError::CustodySetupInvalid)?;
    record.state = AgentCreationState::PublicationPending;
    store.save(&record)?;
    store.save_rebind(&RebindEntry {
        agent_account_id: account_id,
        binding: RebindBinding::Committed,
        bound_primary: plan.human_primary.clone(),
        master_range: plan.next_range,
        request_id: Some(plan.request_id.clone()),
        failure: None,
    })?;
    Ok(record)
}

/// The predecessors the plan names must be the stored agent's head and certificate.
fn check_predecessors(plan: &RegisterPlan, stored: &Envelope<DeviceSet>) -> Result<(), SdkError> {
    let head = object_hash(stored).map_err(|_| SdkError::CustodySetupInvalid)?;
    let certificate =
        object_hash(&stored.body.master_certificate).map_err(|_| SdkError::CustodySetupInvalid)?;
    if plan.previous_agent_head_hash.as_deref() != Some(head.as_str())
        || plan.previous_master_certificate_hash.as_deref() != Some(certificate.as_str())
    {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(())
}

/// Nothing widens and nothing changes: the approved keys, capabilities and branch lease equal the
/// stored agent's. A plan that differs refuses before any write.
fn check_no_widening(plan: &RegisterPlan, stored: &Envelope<DeviceSet>) -> Result<(), SdkError> {
    let certificate = &stored.body.master_certificate.body;
    let [device] = stored.body.devices.as_slice() else {
        return Err(SdkError::CustodySetupInvalid);
    };
    let branch = device
        .branch_certificate
        .as_ref()
        .map(|cert| &cert.body)
        .ok_or(SdkError::CustodySetupInvalid)?;
    let same = certificate.master_public_key == plan.master_public_key
        && certificate.self_signing_public_key == plan.self_signing_public_key
        && branch.branch_signing_public_key == plan.branch_signing_public_key
        && branch.agreement_identity_public_key == plan.agreement_public_key
        && branch.capabilities == plan.capabilities
        && branch.not_before == plan.branch_not_before
        && branch.expires_at == plan.branch_expires_at
        && device.device_id == plan.agent_device.device_id
        && device.device_epoch == plan.agent_device.device_epoch
        && stored.body.profile.display_name == plan.display_name;
    if same { Ok(()) } else { Err(SdkError::CustodySetupInvalid) }
}

/// The agent's new `DeviceSet`: the new master certificate, the branch recertified against it with
/// the plan's certificate id, the next epoch, the new custodian, and the previous record's hash.
/// Signed by the agent's self-signing key; no other field changes.
fn rebound_record(
    stored: &Envelope<DeviceSet>,
    plan: &RegisterPlan,
    self_signing: &SelfSigningKey,
    certificate: Envelope<MasterCertificate>,
) -> Result<Envelope<DeviceSet>, SdkError> {
    if stored.body.revoked_device_checkpoint.is_some() {
        return Err(SdkError::CustodySetupInvalid);
    }
    let master_hash = object_hash(&certificate).map_err(|_| SdkError::CustodySetupInvalid)?;
    let mut body = stored.body.clone();
    let [device] = body.devices.as_mut_slice() else {
        return Err(SdkError::CustodySetupInvalid);
    };
    let mut branch =
        device.branch_certificate.as_ref().ok_or(SdkError::CustodySetupInvalid)?.body.clone();
    branch.master_certificate_hash = master_hash;
    branch.cert_id.clone_from(&plan.branch_cert_id);
    device.branch_certificate =
        Some(self_signing.certify_branch(branch).map_err(|_| SdkError::CustodySetupInvalid)?);
    body.master_certificate = certificate;
    body.device_set_epoch =
        encode_epoch(plan.next_range, 1).map_err(|_| SdkError::CustodySetupInvalid)?;
    body.previous_record_hash =
        Some(object_hash(stored).map_err(|_| SdkError::CustodySetupInvalid)?);
    body.issued_at = plan.certificate_issued_at;
    body.profile.custodian = Some(plan.human_primary.clone());
    self_signing.sign_record(body).map_err(|_| SdkError::CustodySetupInvalid)
}

/// The master or the self-signing key is missing or refused: the inventory records the reason and
/// the request stays authorized (a retry can succeed once the key is back). Nothing is forged.
fn key_unavailable(
    store: &AgentCreationStore,
    account_id: &str,
    plan: &RegisterPlan,
) -> Result<AgentCreationRecord, SdkError> {
    let mut entry = store.load_rebind(account_id)?.unwrap_or(RebindEntry {
        agent_account_id: account_id.to_owned(),
        binding: RebindBinding::RebindPending,
        bound_primary: plan.human_primary.clone(),
        master_range: plan.next_range.saturating_sub(1).max(1),
        request_id: None,
        failure: None,
    });
    entry.binding = RebindBinding::RebindPending;
    entry.request_id = Some(plan.request_id.clone());
    entry.failure = Some(AgentFailure::CustodyKeyUnavailable);
    store.save_rebind(&entry)?;
    Err(crate::custody::vault::agent_key_unavailable())
}
