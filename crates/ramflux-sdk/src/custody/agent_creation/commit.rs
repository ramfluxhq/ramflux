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
use ramflux_crypto::custody::{AgentMasterPurpose, AgentMasterRequest, SelfSigningKey};
use ramflux_protocol::custody::{
    BranchCertificate, Device, DeviceSet, Envelope, MigrationState, Profile, RegisterPlan,
    SectionHashes, decode_register_plan, encode_epoch, object_hash,
};
use ramflux_protocol::{DeviceSetStatus, PrincipalKind, domain};

/// Commit an authorized request exactly once. The complete bundle is written by one persist call
/// after the human head and primary are re-read; the record then moves to `publication_pending`.
/// A repeated call returns the saved record and writes nothing.
/// # Errors
/// `CustodySetupInvalid` for a request that is not authorized, or a human head or primary that no
/// longer matches the plan (the request is refused and its pending secrets are cleaned up);
/// `CustodyExpired` past the deadline before the commit.
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
    {
        finish_refused(store, vault, record)?;
        return Err(SdkError::CustodySetupInvalid);
    }
    let refs = StagedRefs::for_record(store, &record, &plan)?;
    let primary_key = vault.load_primary(&refs.primary)?;
    let provisioning = vault.load_provisioning_secret(&refs.provisioning)?;
    let genesis = build_genesis(vault, &refs, &plan, &primary_key)?;
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

/// Close a request whose human head or primary changed before the commit.
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

/// Build the native genesis of the agent from the approved plan. The master certificate is issued
/// by the vault (the master never leaves it); the branch certificate and the `DeviceSet` are
/// signed by the agent self-signing key. Every field comes from the plan, not from the clock.
fn build_genesis(
    vault: &dyn PrimaryVault,
    refs: &StagedRefs,
    plan: &RegisterPlan,
    primary: &SelfSigningKey,
) -> Result<Envelope<DeviceSet>, SdkError> {
    let master_cert = vault.certify_agent_master(
        &refs.master,
        AgentMasterRequest {
            purpose: AgentMasterPurpose::Create,
            anchor: plan.agent_anchor.clone(),
            principal_id: plan.principal_id.clone(),
            principal_kind: PrincipalKind::HeadlessAi,
            cert_id: plan.master_cert_id.clone(),
            self_signing_public_key: plan.self_signing_public_key.clone(),
            external_ref: plan.human_primary.clone(),
            range: 1,
            previous: None,
            issued_at: plan.certificate_issued_at,
        },
    )?;
    let branch_cert = primary
        .certify_branch(BranchCertificate {
            schema: domain::CUSTODY_BRANCH_CERTIFICATE.into(),
            version: 1,
            account_anchor: plan.agent_anchor.clone(),
            master_certificate_hash: object_hash(&master_cert)
                .map_err(|_| SdkError::CustodySetupInvalid)?,
            device_id: plan.agent_device.device_id.clone(),
            device_epoch: plan.agent_device.device_epoch,
            principal_kind: PrincipalKind::HeadlessAi,
            branch_signing_public_key: plan.branch_signing_public_key.clone(),
            agreement_identity_public_key: plan.agreement_public_key.clone(),
            capabilities: plan.capabilities.clone(),
            not_before: plan.branch_not_before,
            expires_at: plan.branch_expires_at,
            cert_id: plan.branch_cert_id.clone(),
        })
        .map_err(|_| SdkError::CustodySetupInvalid)?;
    let (signing_commitment, agreement_commitment) = ramflux_crypto::device_key_commitments(
        &plan.branch_signing_public_key,
        &plan.agreement_public_key,
    )
    .map_err(|_| SdkError::CustodySetupInvalid)?;
    let device_set = DeviceSet {
        schema: domain::SIGNED_DEVICE_SET_V3.into(),
        version: 3,
        principal_id: plan.principal_id.clone(),
        account_anchor: plan.agent_anchor.clone(),
        principal_kind: PrincipalKind::HeadlessAi,
        origin: "new".into(),
        custody_mode: "v3".into(),
        device_set_epoch: encode_epoch(1, 1).map_err(|_| SdkError::CustodySetupInvalid)?,
        previous_record_hash: None,
        issued_at: plan.certificate_issued_at,
        master_certificate: master_cert,
        legacy_binding: None,
        profile: Profile {
            kind: PrincipalKind::HeadlessAi,
            display_name: plan.display_name.clone(),
            custodian: Some(plan.human_primary.clone()),
        },
        devices: vec![Device {
            device_id: plan.agent_device.device_id.clone(),
            device_epoch: plan.agent_device.device_epoch,
            signing_key_commitment: signing_commitment,
            agreement_key_commitment: agreement_commitment,
            status: DeviceSetStatus::Active,
            revoked_at: None,
            branch_certificate: Some(branch_cert),
            message_layer: None,
            migration_state: MigrationState::Native,
        }],
        delegations: vec![],
        revoked_delegation_ids: vec![],
        migration: None,
        revoked_device_checkpoint: None,
        section_hashes: SectionHashes {
            profile: String::new(),
            devices: String::new(),
            delegations: String::new(),
            revoked_delegation_ids: String::new(),
            migration: String::new(),
            revoked_device_checkpoint: String::new(),
        },
    };
    primary.sign_record(device_set).map_err(|_| SdkError::CustodySetupInvalid)
}
