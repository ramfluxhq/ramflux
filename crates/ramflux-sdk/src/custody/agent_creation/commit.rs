// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit of an approved agent creation (contract 7.2 step 4, controller decision r6 answer 2).
//! After the phone's approval is verified and consumed, the complete local bundle is written once
//! as the account registry entry in `NetworkingPending`. Nothing is deleted from here on.
use super::machine::{finish, mark_publication_pending, resume_request};
use super::state::{AgentCreationState, AgentFailure};
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use crate::custody::store::GenesisMaterial;
use crate::custody::{CreateInput, PrimaryVault, store as custody_store};
use ramflux_crypto::custody::{
    AgentMasterPurpose, AgentMasterRequest, GenesisDraft, create_genesis_from_draft,
};
use ramflux_protocol::custody::{
    DeviceRef, DeviceSet, Envelope, MasterCertificate, RegisterPlan, decode_register_plan,
    object_hash,
};
use ramflux_protocol::{DeviceSetStatus, PrincipalKind};

/// Commit an authorized request exactly once. The complete bundle is written by one persist call
/// after the human head, the primary and the desktop enrollment are re-read; the record then moves
/// to `publication_pending`. A repeated call returns the saved record and writes nothing.
/// # Errors
/// `CustodySetupInvalid` for a request that is not authorized; `CustodyExpired` past the deadline
/// before the commit. A human head, a primary or a desktop enrollment that no longer matches the
/// plan refuses the request (its pending secrets are cleaned up before the commit).
pub fn commit_approved(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    human_account_id: &str,
    request_id: &str,
    now: u64,
) -> Result<AgentCreationRecord, SdkError> {
    let record = store.load(request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
    if matches!(
        record.state,
        AgentCreationState::PublicationPending
            | AgentCreationState::PublicationUnknown
            | AgentCreationState::Complete
    ) {
        return Ok(record);
    }
    let record = resume_request(store, vault, request_id, now)?;
    match record.state {
        AgentCreationState::PublicationPending => return Ok(record),
        AgentCreationState::Authorized => {}
        AgentCreationState::Expired => return Err(SdkError::CustodyExpired),
        _ => return Err(SdkError::CustodySetupInvalid),
    }
    let plan = decode_register_plan(&record.plan_bytes()?).map_err(|_| SdkError::CustodySetupInvalid)?;
    let account = custody_store::load_account(store.root(), human_account_id, now)?;
    let human_record = account.record();
    let human_head = object_hash(human_record).map_err(|_| SdkError::CustodySetupInvalid)?;
    let human_primary = &human_record.body.master_certificate.body.primary_device_ref;
    if human_head != plan.human_head_hash
        || *human_primary != plan.human_primary
        || human_record.body.account_anchor != plan.owner_anchor
        || !desktop_is_enrolled(human_record, &plan.desktop, now)
    {
        finish_refused(store, vault, record)?;
        return Err(SdkError::CustodySetupInvalid);
    }
    let refs = StagedRefs::for_record(store, &record, &plan)?;
    let primary_key = vault.load_primary(&refs.primary)?;
    let provisioning = vault.load_provisioning_secret(&refs.provisioning)?;
    let genesis = create_genesis_from_draft(
        |body| issue_agent_master(vault, &refs, body),
        &primary_key,
        &plan_draft(&plan),
    )?;
    let account_id = record.account_id.clone().ok_or(SdkError::CustodySetupInvalid)?;
    let input = CreateInput {
        local_account_id: account_id,
        principal_id: plan.principal_id.clone(),
        device_id: plan.agent_device.device_id.clone(),
        display_name: plan.display_name.clone(),
        principal_kind: PrincipalKind::HeadlessAi,
        custodian_account_id: Some(human_account_id.to_owned()),
    };
    custody_store::persist(
        store.root(),
        &input,
        GenesisMaterial {
            record: genesis,
            primary: &primary_key,
            branch: None,
            now,
            data_secret: Some(&provisioning[..]),
            commit_gate: None,
            pre_staged: true,
        },
        vault,
    )?;
    mark_publication_pending(store, record)
}

/// Desktop enrollment (contract 7.2 step 4): the sending desktop must still be an active device of
/// the human account, with a branch that is valid at `now` and holds the `sync` capability. Checked
/// in the same compare-and-set as the human head and the primary.
pub(super) fn desktop_is_enrolled(record: &Envelope<DeviceSet>, desktop: &DeviceRef, now: u64) -> bool {
    record.body.devices.iter().any(|device| {
        device.device_id == desktop.device_id
            && device.device_epoch == desktop.device_epoch
            && matches!(device.status, DeviceSetStatus::Active)
            && device.revoked_at.is_none()
            && device.branch_certificate.as_ref().is_some_and(|branch| {
                let body = &branch.body;
                body.account_anchor == record.body.account_anchor
                    && body.device_id == desktop.device_id
                    && body.device_epoch == desktop.device_epoch
                    && body.not_before <= now
                    && now < body.expires_at
                    && body.capabilities.iter().any(|capability| capability == "sync")
            })
    })
}

/// The vault references of one request, derived from its final account reference. A stored record
/// that does not match the derivation is refused (nothing is deleted on that path).
struct StagedRefs {
    master: String,
    primary: String,
    branch: String,
    provisioning: String,
}

impl StagedRefs {
    fn for_record(
        store: &AgentCreationStore,
        record: &AgentCreationRecord,
        plan: &RegisterPlan,
    ) -> Result<Self, SdkError> {
        let account_id = record.account_id.as_deref().ok_or(SdkError::CustodySetupInvalid)?;
        let reference =
            custody_store::custody_vault_reference(store.root(), account_id, &plan.agent_anchor)?;
        let refs = Self {
            master: format!("{}{reference}", crate::custody::vault::AGENT_MASTER_PREFIX),
            branch: format!("branch:{reference}"),
            provisioning: format!("agent-provisioning:{reference}"),
            primary: reference,
        };
        let stored = record.vault_refs.as_slice();
        let expected = [&refs.master, &refs.primary, &refs.branch, &refs.provisioning];
        if stored.len() != expected.len()
            || stored.iter().zip(expected).any(|(stored, expected)| stored != expected)
        {
            return Err(SdkError::CustodySetupInvalid);
        }
        Ok(refs)
    }
}

/// Close a request whose human head, primary or desktop enrollment changed before the commit.
fn finish_refused(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    record: AgentCreationRecord,
) -> Result<(), SdkError> {
    finish(
        store,
        vault,
        record,
        AgentCreationState::Refused,
        Some(AgentFailure::CreationPrimaryChanged),
    )
    .map(|_| ())
}

/// Every genesis value of an approved plan. Nothing is recomputed from the clock or the device.
fn plan_draft(plan: &RegisterPlan) -> GenesisDraft {
    GenesisDraft {
        account_anchor: plan.agent_anchor.clone(),
        principal_id: plan.principal_id.clone(),
        principal_kind: PrincipalKind::HeadlessAi,
        display_name: plan.display_name.clone(),
        primary_device_ref: plan.human_primary.clone(),
        custodian: Some(plan.human_primary.clone()),
        master_public_key: plan.master_public_key.clone(),
        self_signing_public_key: plan.self_signing_public_key.clone(),
        master_cert_id: plan.master_cert_id.clone(),
        device_id: plan.agent_device.device_id.clone(),
        device_epoch: plan.agent_device.device_epoch,
        branch_signing_public_key: plan.branch_signing_public_key.clone(),
        agreement_public_key: plan.agreement_public_key.clone(),
        branch_cert_id: plan.branch_cert_id.clone(),
        branch_capabilities: plan.capabilities.clone(),
        issued_at: plan.certificate_issued_at,
        branch_not_before: plan.branch_not_before,
        branch_expires_at: plan.branch_expires_at,
    }
}

/// The master certificate is issued by the vault (the master never leaves it). The request is
/// built from the body the genesis fixed; the genesis rejects any returned body that differs.
fn issue_agent_master(
    vault: &dyn PrimaryVault,
    refs: &StagedRefs,
    body: MasterCertificate,
) -> Result<Envelope<MasterCertificate>, SdkError> {
    vault.certify_agent_master(
        &refs.master,
        AgentMasterRequest {
            purpose: AgentMasterPurpose::Create,
            anchor: body.account_anchor,
            principal_id: body.principal_id,
            principal_kind: body.principal_kind,
            cert_id: body.cert_id,
            self_signing_public_key: body.self_signing_public_key,
            external_ref: body.primary_device_ref,
            range: body.range_index,
            previous: None,
            issued_at: body.issued_at,
        },
    )
}
