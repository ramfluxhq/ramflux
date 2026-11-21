// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Store and transport steps behind the agent creation bus methods (AGENT-IDENTITY-01 C3, contract
//! 2 and 7.3). `agent.create` runs on the paired desktop; `agent.creation.decide` on the current
//! primary; `agent.operation.get` on either. Every refusal is a typed token raised before any key,
//! store or send effect.
use super::agent_custody::AgentCustodySend;
use crate::custody::PrimaryVault;
use crate::custody::agent_creation::{
    AgentCreationRecord, AgentCreationState, AgentCreationStore, AgentFailure, BeginInput,
    PrimarySigning, begin, desktop_is_enrolled, primary_branch_public_key, primary_sign_decision,
};
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_crypto::random_32;
use ramflux_protocol::custody::{
    AgentRegisterProfile, DeviceRef, DeviceSet, Envelope, RegisterOutcome, RegisterPlan,
    decode_register_decision, decode_register_plan, object_hash, register_plan_hash,
};
use ramflux_protocol::message as g;
use ramflux_protocol::{decode_base64url, encode_base64url, hash_base64url};

/// Domain of the persona hash that the plan carries.
const PERSONA_DOMAIN: &str = "ramflux.agent.persona.v1";

fn refuse(token: &'static str) -> SdkError {
    SdkError::AgentCreationRefused(token)
}

/// The human authority read at one instant, with this device named in it.
struct Human<'a> {
    record: &'a Envelope<DeviceSet>,
    primary: DeviceRef,
    local: DeviceRef,
}

/// Validate the access policy against its closed tokens (dm, group inviters, allowed humans).
fn check_access(access: &g::AgentAccessPolicy) -> Result<(), SdkError> {
    let closed = |token: &str| matches!(token, "owner" | "contacts" | "allowlist" | "open");
    if !closed(&access.dm) || !closed(&access.group_inviters) {
        return Err(refuse("access_policy_invalid"));
    }
    let allowlist = access.dm == "allowlist" || access.group_inviters == "allowlist";
    if !allowlist && !access.allowed_humans.is_empty() {
        return Err(refuse("access_policy_invalid"));
    }
    Ok(())
}

/// The primary branch expiry of the human authority, when the primary has a branch.
fn primary_branch_expiry(record: &Envelope<DeviceSet>, primary: &DeviceRef) -> Option<u64> {
    record
        .body
        .devices
        .iter()
        .find(|device| {
            device.device_id == primary.device_id && device.device_epoch == primary.device_epoch
        })
        .and_then(|device| device.branch_certificate.as_ref())
        .map(|branch| branch.body.expires_at)
}

/// Build the `AgentCustodyStatus` of one stored request. The request and receipt bytes travel as
/// their canonical form; failures are closed tokens.
pub(crate) fn status_of(record: &AgentCreationRecord) -> Result<g::AgentCustodyStatus, SdkError> {
    let plan = record.plan_bytes().ok().filter(|bytes| !bytes.is_empty());
    let agent_anchor = match plan.as_deref() {
        Some(bytes) => Some(
            decode_register_plan(bytes).map_err(|_| SdkError::CustodySetupInvalid)?.agent_anchor,
        ),
        None => None,
    };
    let receipt_json = match record.receipt_b64.as_deref() {
        Some(text) => Some(decode_base64url(text).map_err(|_| SdkError::CustodySetupInvalid)?),
        None => None,
    };
    Ok(g::AgentCustodyStatus {
        request_id: record.request_id.clone(),
        state: record.state.as_str().to_owned(),
        agent_anchor,
        expires_at: Some(record.expires_at),
        request_json: plan,
        receipt_json,
        error: record.failure.map(failure_body),
    })
}

fn failure_body(failure: AgentFailure) -> g::AgentFailure {
    g::AgentFailure {
        reason_code: failure.as_str().to_owned(),
        current_revision: None,
        retry_after_ms: None,
        effects: "none".to_owned(),
        restored: None,
        http_status: None,
        current_incarnation: None,
    }
}

impl RamfluxClient {
    /// The unlocked human account this device belongs to, with this device as the named desktop.
    fn human_authority(&self) -> Result<Human<'_>, SdkError> {
        let account = self.born_v3_account.as_deref().ok_or(SdkError::AccountDbNotUnlocked)?;
        let record = account.record();
        let own = self.owned_device_identity()?;
        let local = DeviceRef {
            account_anchor: own.root_commitment().into(),
            device_id: own.device_id().into(),
            device_epoch: self.device_epoch_of(&own)?,
        };
        Ok(Human {
            record,
            primary: record.body.master_certificate.body.primary_device_ref.clone(),
            local,
        })
    }

    /// `agent.create` on the paired desktop: prepare the request, freeze the plan and send it
    /// point-to-point to the current primary. Returns the operation in `authorization_pending`.
    /// # Errors
    /// Typed refusals (`confirmation_required`, `role_not_supported`, `host_not_supported`,
    /// `desktop_required`, `creation_pairing_required`, `metadata_pending`, `access_policy_invalid`)
    /// before any effect; store, vault and send failures pass through.
    pub(crate) fn agent_create(
        &self,
        vault: &dyn PrimaryVault,
        body: &g::AgentCreate,
        now: u64,
    ) -> Result<g::AgentCustodyStatus, SdkError> {
        if body.confirmed != Some(true) {
            return Err(refuse("confirmation_required"));
        }
        if body.role != "named" {
            return Err(refuse("role_not_supported"));
        }
        if body.host.is_some() {
            return Err(refuse("host_not_supported"));
        }
        let human = self.human_authority()?;
        if human.primary.device_id == human.local.device_id
            && human.primary.device_epoch == human.local.device_epoch
        {
            return Err(refuse("desktop_required"));
        }
        let primary_expiry = primary_branch_expiry(human.record, &human.primary)
            .filter(|expiry| *expiry > now)
            .ok_or_else(|| refuse("creation_pairing_required"))?;
        if primary_branch_public_key(human.record, &human.primary, now).is_err()
            || !desktop_is_enrolled(human.record, &human.local, now)
        {
            return Err(refuse("creation_pairing_required"));
        }
        let (Some(persona), Some(config), Some(access)) =
            (&body.persona, &body.config, &body.access)
        else {
            return Err(refuse("metadata_pending"));
        };
        if persona.responsibility.is_empty()
            || config.provider.is_empty()
            || config.model.is_empty()
        {
            return Err(refuse("metadata_pending"));
        }
        check_access(access)?;
        let persona_bytes = serde_json::to_vec(&serde_json::json!({
            "avatar": persona.avatar,
            "name": persona.name,
            "responsibility": persona.responsibility,
        }))?;
        let request_id =
            encode_base64url(random_32().map_err(|_| SdkError::CustodyRandomUnavailable)?);
        let principal_id = format!(
            "principal-{}",
            encode_base64url(random_32().map_err(|_| SdkError::CustodyRandomUnavailable)?)
        );
        let input = BeginInput {
            request_id: request_id.clone(),
            owner_anchor: human.record.body.account_anchor.clone(),
            human_head_hash: object_hash(human.record)
                .map_err(|_| SdkError::CustodySetupInvalid)?,
            human_primary: human.primary.clone(),
            desktop: human.local.clone(),
            principal_id,
            display_name: persona.name.clone(),
            profile: AgentRegisterProfile {
                responsibility: persona.responsibility.clone(),
                provider: config.provider.clone(),
                model: config.model.clone(),
                persona_version: 1,
                persona_hash: hash_base64url(PERSONA_DOMAIN, &persona_bytes),
                profile_epoch: 1,
            },
            primary_branch_expires_at: primary_expiry,
        };
        let store = self.agent_creation_store()?;
        let outcome = begin(&store, vault, &input, now)?;
        let plan =
            decode_register_plan(&outcome.plan_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
        let target = RootQualifiedDeviceRef::from_custody_record(
            self.born_v3_account.as_deref().ok_or(SdkError::AccountDbNotUnlocked)?.verified(),
            &human.primary.device_id,
        )?;
        self.stage_agent_custody(AgentCustodySend {
            target: &target,
            owner_anchor: &human.record.body.account_anchor,
            agent_anchor: &plan.agent_anchor,
            correlation_id: &request_id,
            custody: g::AgentCustodyPacket {
                value: Some(g::agent_custody_packet::Value::RequestJson(outcome.plan_bytes)),
            },
            now,
        })?;
        let record = store.load(&request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
        status_of(&record)
    }

    /// `agent.creation.decide` on the current primary: sign approve or deny for a stored request
    /// after user presence, persist the decision, then send it point-to-point to the desktop.
    /// An exact replay returns the saved decision without signing again.
    /// # Errors
    /// Typed refusals (`approval_required`, `creation_request_unknown`, `creation_plan_changed`,
    /// `creation_not_primary`, `creation_already_decided`) before any signature; vault refusals
    /// (no presence, consumed approval) pass through.
    pub(crate) fn agent_creation_decide(
        &self,
        vault: &dyn PrimaryVault,
        body: &g::AgentCreationDecide,
        now: u64,
    ) -> Result<g::AgentCustodyStatus, SdkError> {
        let approved = body.approved.ok_or_else(|| refuse("approval_required"))?;
        let store = self.agent_creation_store()?;
        // A stored record that fails the store's own consistency check was altered after it was
        // stored: that is the plan-changed refusal, not a store failure.
        let mut record = match store.load(&body.request_id) {
            Ok(Some(record)) => record,
            Ok(None) => return Err(refuse("creation_request_unknown")),
            Err(SdkError::CustodySetupInvalid) => return Err(refuse("creation_plan_changed")),
            Err(error) => return Err(error),
        };
        let plan_bytes = record.plan_bytes().map_err(|_| refuse("creation_plan_changed"))?;
        let plan =
            decode_register_plan(&plan_bytes).map_err(|_| refuse("creation_plan_changed"))?;
        let hash = register_plan_hash(&plan).map_err(|_| refuse("creation_plan_changed"))?;
        if hash != record.request_hash || hash != body.request_hash {
            return Err(refuse("creation_plan_changed"));
        }
        let human = self.human_authority()?;
        if plan.human_primary != human.local || plan.human_primary != human.primary {
            return Err(refuse("creation_not_primary"));
        }
        let wanted = if approved { RegisterOutcome::Approve } else { RegisterOutcome::Deny };
        if let Some(saved) = record.decision_bytes()? {
            let decided =
                decode_register_decision(&saved).map_err(|_| SdkError::CustodySetupInvalid)?;
            return if decided.body.decision == wanted {
                status_of(&record)
            } else {
                Err(refuse("creation_already_decided"))
            };
        }
        if record.state != AgentCreationState::AuthorizationPending {
            return Err(refuse("creation_already_decided"));
        }
        let decision_bytes = self.sign_primary_decision(vault, &store, &plan_bytes, wanted, now)?;
        record.decision_b64 = Some(encode_base64url(&decision_bytes));
        if approved {
            record.state = AgentCreationState::Authorized;
        } else {
            record.state = AgentCreationState::Refused;
            record.failure = Some(AgentFailure::AuthorizationRefused);
        }
        store.save(&record)?;
        self.send_decision(&plan, decision_bytes, now)?;
        status_of(&record)
    }

    /// Sign the stored plan with the primary branch after presence (`primary_sign_decision`).
    fn sign_primary_decision(
        &self,
        vault: &dyn PrimaryVault,
        store: &AgentCreationStore,
        plan_bytes: &[u8],
        outcome: RegisterOutcome,
        now: u64,
    ) -> Result<Vec<u8>, SdkError> {
        let human = self.human_authority()?;
        let account_id = self.account_db()?.local_account_id.clone();
        // The current branch must exist; the vault compares the primary's self-signing key.
        primary_branch_public_key(human.record, &human.primary, now)?;
        let primary_public =
            human.record.body.master_certificate.body.self_signing_public_key.clone();
        let reference = crate::custody::custody_vault_reference(
            store.root(),
            &account_id,
            &human.record.body.account_anchor,
        )?;
        let branch_reference = format!("branch:{reference}");
        let signing = PrimarySigning {
            primary_device: &human.primary,
            primary_reference: &reference,
            expected_primary_public_key: &primary_public,
            branch_reference: &branch_reference,
            principal_id: &human.record.body.principal_id,
        };
        primary_sign_decision(vault, &signing, plan_bytes, outcome, now)
    }

    /// Send the signed decision to the desktop that owns the request.
    fn send_decision(
        &self,
        plan: &RegisterPlan,
        decision_bytes: Vec<u8>,
        now: u64,
    ) -> Result<(), SdkError> {
        let verified =
            self.born_v3_account.as_deref().ok_or(SdkError::AccountDbNotUnlocked)?.verified();
        let target =
            RootQualifiedDeviceRef::from_custody_record(verified, &plan.desktop.device_id)?;
        self.stage_agent_custody(AgentCustodySend {
            target: &target,
            owner_anchor: &plan.owner_anchor,
            agent_anchor: &plan.agent_anchor,
            correlation_id: &plan.request_id,
            custody: g::AgentCustodyPacket {
                value: Some(g::agent_custody_packet::Value::DecisionJson(decision_bytes)),
            },
            now,
        })
    }

    /// `agent.operation.get`: the stored status of one request on this root.
    /// # Errors
    /// `creation_request_unknown` when no request with this id is stored here.
    pub(crate) fn agent_operation_status(
        &self,
        operation_id: &str,
    ) -> Result<g::AgentCustodyStatus, SdkError> {
        let record = self
            .agent_creation_store()?
            .load(operation_id)?
            .ok_or_else(|| refuse("creation_request_unknown"))?;
        status_of(&record)
    }
}
