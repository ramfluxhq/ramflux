// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The one shared test helper that creates an agent account (AGENT-IDENTITY-01 decision D6, stage
//! F4). It runs the REAL creation flow on one data root: the human gets a desktop sibling in its
//! authority, `begin` stores the pending secrets and freezes the plan, the human primary signs an
//! approval through its vault (one-shot presence armed for this plan hash), the desktop verifies
//! the decision, and `commit_approved` writes the account bundle. Only the home-node publication is
//! left out: no node is involved, so the account is marked live the way the old fixtures did.
//! No test writes an agent account any other way.
//!
//! The human is any account on the root that was created by the ordinary ceremony; the primary
//! device and the desktop share the root and the vault of the fixture, which is what a
//! single-process test has. The plan, the decision, the head compare-and-set and the commit are
//! the production code.
use super::{
    AgentCreationState, AgentCreationStore, BeginInput, PrimarySigning, apply_decision, begin,
    commit_approved, primary_sign_decision,
};
use crate::SdkError;
use crate::custody::PrimaryVault;
use crate::custody::store::{load_account, replace_rebound_authority};
use ramflux_crypto::X25519KeyPair;
use ramflux_crypto::create_device_branch_from_seed;
use ramflux_protocol::custody::{
    AgentRegisterProfile, BranchCertificate, Device, DeviceRef, DeviceSet, Envelope,
    MAX_BRANCH_LEASE_SECONDS, MigrationState, RegisterOutcome, object_hash,
};
use ramflux_protocol::{DeviceSetStatus, PrincipalKind, domain, encode_base64url};
use zeroize::Zeroizing;

/// The device id of the desktop sibling the helper enrols in the human authority.
pub(crate) const DESKTOP_DEVICE_ID: &str = "desktop-device";

/// Who creates the agent and with which vaults.
pub(crate) struct AgentRequest<'a> {
    pub(crate) root: &'a std::path::Path,
    pub(crate) human_account_id: &'a str,
    /// The principal id of the human's devices (names its branch seeds).
    pub(crate) human_principal: &'a str,
    /// The vault that holds the human primary's keys and signs the approval.
    pub(crate) human_vault: &'a dyn PrimaryVault,
    /// Arms the one-shot presence approval of `human_vault` for a plan hash.
    pub(crate) arm_approval: &'a dyn Fn(&str) -> Result<(), SdkError>,
    /// The vault that receives the agent's keys (the desktop's vault).
    pub(crate) agent_vault: &'a dyn PrimaryVault,
    pub(crate) agent_principal: &'a str,
    pub(crate) display_name: &'a str,
    pub(crate) request_id: &'a str,
}

/// The agent account the helper created.
pub(crate) struct CreatedAgent {
    pub(crate) account_id: String,
    /// The agent's data passphrase (its provisioning secret), as the export carries it.
    pub(crate) passphrase: Zeroizing<String>,
    pub(crate) device_id: String,
    pub(crate) record: Envelope<DeviceSet>,
}

/// Adds the desktop sibling to the human authority when it is not there yet. The successor record
/// is signed by the human primary key from `vault` and replaces the stored authority through the
/// store function the production refresh uses.
pub(crate) fn enroll_desktop(
    root: &std::path::Path,
    human_account_id: &str,
    human_principal: &str,
    human_vault: &dyn PrimaryVault,
    now: u64,
) -> Result<DeviceRef, SdkError> {
    let account = load_account(root, human_account_id, now)?;
    let base = account.record().clone();
    let anchor = base.body.account_anchor.clone();
    if let Some(device) =
        base.body.devices.iter().find(|device| device.device_id == DESKTOP_DEVICE_ID)
    {
        return Ok(DeviceRef {
            account_anchor: anchor,
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
        });
    }
    let primary = human_vault.load_primary(account.primary_vault_ref())?;
    let seed = Zeroizing::new([27_u8; 32]);
    let branch = create_device_branch_from_seed(human_principal, DESKTOP_DEVICE_ID, 1, &seed);
    let signing = encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let agreement = encode_base64url(X25519KeyPair::from_seed([28_u8; 32]).public);
    let (signing_commitment, agreement_commitment) =
        ramflux_crypto::device_key_commitments(&signing, &agreement)
            .map_err(|_| SdkError::CustodySetupInvalid)?;
    let certificate = primary
        .certify_branch(BranchCertificate {
            schema: domain::CUSTODY_BRANCH_CERTIFICATE.into(),
            version: 1,
            account_anchor: anchor.clone(),
            master_certificate_hash: object_hash(&base.body.master_certificate)
                .map_err(|_| SdkError::CustodySetupInvalid)?,
            device_id: DESKTOP_DEVICE_ID.into(),
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
        })
        .map_err(|_| SdkError::CustodySetupInvalid)?;
    let mut body = base.body.clone();
    // The successor of the stored head: the next revision, naming the record it replaces.
    body.device_set_epoch = base.body.device_set_epoch + 1;
    body.previous_record_hash =
        Some(object_hash(&base).map_err(|_| SdkError::CustodySetupInvalid)?);
    body.devices.push(Device {
        device_id: DESKTOP_DEVICE_ID.into(),
        device_epoch: 1,
        signing_key_commitment: signing_commitment,
        agreement_key_commitment: agreement_commitment,
        status: DeviceSetStatus::Active,
        revoked_at: None,
        branch_certificate: Some(certificate),
        message_layer: None,
        migration_state: MigrationState::Native,
    });
    // The roster stays sorted by device id and unique.
    body.devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    let successor = primary.sign_record(body).map_err(|_| SdkError::CustodySetupInvalid)?;
    replace_rebound_authority(root, human_account_id, &successor, None, now)?;
    Ok(DeviceRef { account_anchor: anchor, device_id: DESKTOP_DEVICE_ID.into(), device_epoch: 1 })
}

/// Creates one agent account through the real flow and returns it live.
///
/// # Errors
/// Any refusal of the creation flow; the helper hides none.
pub(crate) fn create_test_agent(
    request: &AgentRequest<'_>,
    now: u64,
) -> Result<CreatedAgent, SdkError> {
    let desktop = enroll_desktop(
        request.root,
        request.human_account_id,
        request.human_principal,
        request.human_vault,
        now,
    )?;
    let account = load_account(request.root, request.human_account_id, now + 1)?;
    let human = account.record().clone();
    let primary = human.body.master_certificate.body.primary_device_ref.clone();
    let primary_public = human.body.master_certificate.body.self_signing_public_key.clone();
    let primary_branch = human
        .body
        .devices
        .iter()
        .find(|device| device.device_id == primary.device_id)
        .and_then(|device| device.branch_certificate.as_ref())
        .ok_or(SdkError::CustodySetupInvalid)?;
    let store = AgentCreationStore::open(request.root, request.human_account_id)?;
    let outcome = begin(
        &store,
        request.agent_vault,
        &BeginInput {
            request_id: request.request_id.into(),
            owner_anchor: human.body.account_anchor.clone(),
            human_head_hash: object_hash(&human).map_err(|_| SdkError::CustodySetupInvalid)?,
            human_primary: primary.clone(),
            desktop,
            principal_id: request.agent_principal.into(),
            display_name: request.display_name.into(),
            profile: AgentRegisterProfile {
                responsibility: "Test agent".into(),
                provider: "provider-a".into(),
                model: "model-a".into(),
                persona_version: 1,
                persona_hash: encode_base64url([4_u8; 32]),
                profile_epoch: 1,
            },
            primary_branch_expires_at: primary_branch.body.expires_at,
        },
        now + 1,
    )?;
    (request.arm_approval)(&outcome.request_hash)?;
    let decision = primary_sign_decision(
        request.human_vault,
        &PrimarySigning {
            primary_device: &primary,
            primary_reference: account.primary_vault_ref(),
            expected_primary_public_key: &primary_public,
            branch_reference: account.branch_vault_ref(),
            principal_id: request.human_principal,
        },
        &outcome.plan_bytes,
        RegisterOutcome::Approve,
        now + 2,
    )?;
    let authorized = apply_decision(
        &store,
        request.agent_vault,
        &outcome.request_id,
        &decision,
        &primary_branch.body.branch_signing_public_key,
        now + 2,
    )?;
    let capabilities = vec![ramflux_protocol::AGENT_CUSTODY_AUTHORIZATION_CAPABILITY.to_owned()];
    let mut committed = commit_approved(
        &store,
        request.agent_vault,
        request.human_account_id,
        &outcome.request_id,
        &capabilities,
        now + 3,
    )?;
    let account_id = authorized.account_id.clone().ok_or(SdkError::CustodySetupInvalid)?;
    let provisioning = committed
        .vault_refs
        .iter()
        .find(|reference| reference.starts_with("agent-provisioning:"))
        .ok_or(SdkError::CustodySetupInvalid)?;
    let secret = request.agent_vault.load_provisioning_secret(provisioning)?;
    let passphrase = Zeroizing::new(
        std::str::from_utf8(&secret).map_err(|_| SdkError::CustodySetupInvalid)?.to_owned(),
    );
    // No node takes part: the publication step is closed by the fixture, as the old fixtures marked
    // their accounts live. The request is complete, so no advance reconnects it.
    let mut agent = load_account(request.root, &account_id, now + 3)?;
    agent.mark_live_for_test(request.root)?;
    committed.state = AgentCreationState::Complete;
    store.save(&committed)?;
    Ok(CreatedAgent {
        device_id: agent
            .record()
            .body
            .devices
            .first()
            .map(|d| d.device_id.clone())
            .ok_or(SdkError::CustodySetupInvalid)?,
        record: agent.record().clone(),
        account_id,
        passphrase,
    })
}
