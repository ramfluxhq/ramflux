// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publication of an approved agent (contract 7.2 step 5, controller decision r6 answer 3). The
//! saved plan, decision and profile are replayed byte for byte, so a lost reply is answered by the
//! identical `AgentPublish`. The receipt is compared field by field before it is persisted.
use super::state::AgentCreationState;
use super::store::{AgentCreationRecord, AgentCreationStore};
use crate::SdkError;
use crate::custody::BornAccount;
use ramflux_protocol::agent_profile::{AgentProfileEnvelope, decode_agent_profile};
use ramflux_protocol::custody::{
    AgentPublishReceipt, CustodyProofAction, CustodyRefusal, DeviceSet, Envelope, Publication,
    RegisterDecision, RegisterPlan, decode_register_decision, decode_register_plan, object_hash,
    register_plan_hash,
};
use ramflux_protocol::{PrincipalKind, canonical_json_bytes, decode_base64url, encode_base64url};
use std::path::Path;

/// The saved approval of one agent account: its plan, its decision and its signed profile, all
/// read from the creation record of the human account that owns the request.
#[derive(Clone)]
pub(crate) struct AgentPublishing {
    store: AgentCreationStore,
    record: AgentCreationRecord,
    plan: RegisterPlan,
    decision: RegisterDecision,
    profile: AgentProfileEnvelope,
}

/// The saved publication material of a headless account on `root`. `None` when the account has no
/// creation record (such an account cannot register).
/// # Errors
/// Refuses a record that is not in a publishing state or whose saved bytes do not decode.
pub(crate) fn load_publishing(
    root: &Path,
    account: &BornAccount,
) -> Result<Option<AgentPublishing>, SdkError> {
    if account.record().body.principal_kind != PrincipalKind::HeadlessAi {
        return Ok(None);
    }
    let Some(human) = account.custodian_account_id() else {
        return Ok(None);
    };
    let store = AgentCreationStore::open(root, human)?;
    match store.find_by_account(account.local_account_id())? {
        Some(record) => AgentPublishing::from_record(store, record).map(Some),
        None => Ok(None),
    }
}

/// The first proof action of a registration. A human account publishes as before. A headless
/// account publishes only with its saved approval; without one it is refused.
/// # Errors
/// `CustodyRefusal::AgentAuthorizationRequired` for a headless account without a saved approval.
pub(crate) fn first_action(
    kind: PrincipalKind,
    publishing: Option<&AgentPublishing>,
    publication: &Publication,
) -> Result<CustodyProofAction, SdkError> {
    match (kind, publishing) {
        (PrincipalKind::HeadlessAi, Some(saved)) => Ok(saved.publish_action(publication)),
        (PrincipalKind::HeadlessAi, None) => Err(CustodyRefusal::AgentAuthorizationRequired.into()),
        _ => Ok(CustodyProofAction::Publish { publication: Box::new(publication.clone()) }),
    }
}

impl AgentPublishing {
    fn from_record(store: AgentCreationStore, record: AgentCreationRecord) -> Result<Self, SdkError> {
        if !matches!(
            record.state,
            AgentCreationState::PublicationPending
                | AgentCreationState::PublicationUnknown
                | AgentCreationState::Complete
        ) {
            return Err(SdkError::CustodySetupInvalid);
        }
        let plan = decode_register_plan(&record.plan_bytes()?).map_err(|_| SdkError::CustodySetupInvalid)?;
        if register_plan_hash(&plan).map_err(|_| SdkError::CustodySetupInvalid)? != record.request_hash {
            return Err(SdkError::CustodySetupInvalid);
        }
        let decision_bytes = record.decision_bytes()?.ok_or(SdkError::CustodySetupInvalid)?;
        let decision =
            decode_register_decision(&decision_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
        let profile_bytes = decode_base64url(
            record.profile_b64.as_deref().ok_or(SdkError::CustodySetupInvalid)?,
        )
        .map_err(|_| SdkError::CustodySetupInvalid)?;
        let profile =
            decode_agent_profile(&profile_bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
        Ok(Self { store, record, plan, decision, profile })
    }

    /// The `AgentPublish` action built from the saved bytes. Built the same way on every attempt,
    /// so a repeated send is byte-identical and the node returns the saved receipt.
    #[must_use]
    pub(crate) fn publish_action(&self, publication: &Publication) -> CustodyProofAction {
        CustodyProofAction::AgentPublish {
            publication: Box::new(publication.clone()),
            agent_profile: Box::new(self.profile.clone()),
            plan: Box::new(self.plan.clone()),
            authorization: Box::new(self.decision.clone()),
        }
    }

    /// Compare every receipt field with the stored request and the record that was published.
    /// # Errors
    /// `CustodySetupInvalid` for the first field that differs (the caller marks the publication
    /// unknown and does not activate the account).
    pub(crate) fn check_receipt(
        &self,
        receipt: &AgentPublishReceipt,
        record: &Envelope<DeviceSet>,
    ) -> Result<(), SdkError> {
        let record_hash = object_hash(record).map_err(|_| SdkError::CustodySetupInvalid)?;
        let profile_hash = object_hash(&self.profile).map_err(|_| SdkError::CustodySetupInvalid)?;
        let matches = receipt.request_id == self.plan.request_id
            && receipt.request_hash == self.record.request_hash
            && receipt.record_hash == record_hash
            && receipt.profile_hash == profile_hash
            && receipt.custodian_head_hash == self.plan.human_head_hash
            && receipt.custodian_primary == self.plan.human_primary
            && receipt.accepted_at >= self.plan.issued_at
            && receipt.accepted_at < self.plan.expires_at;
        if matches { Ok(()) } else { Err(SdkError::CustodySetupInvalid) }
    }

    /// Persist the verified receipt with the record.
    /// # Errors
    /// Propagates store failures and refuses a receipt that does not encode.
    pub(crate) fn save_receipt(&self, receipt: &AgentPublishReceipt) -> Result<(), SdkError> {
        let mut record = self.reload()?;
        let bytes = canonical_json_bytes(receipt).map_err(|_| SdkError::CustodySetupInvalid)?;
        record.receipt_b64 = Some(encode_base64url(bytes));
        self.store.save(&record)
    }

    /// The publication outcome is unknown (a reply was lost or a receipt did not match).
    /// # Errors
    /// Propagates store failures.
    pub(crate) fn mark_unknown(&self) -> Result<(), SdkError> {
        let mut record = self.reload()?;
        if record.state == AgentCreationState::PublicationPending {
            record.state = AgentCreationState::PublicationUnknown;
            self.store.save(&record)?;
        }
        Ok(())
    }

    /// The account is live and its receipt was verified.
    /// # Errors
    /// Propagates store failures.
    pub(crate) fn mark_complete(&self) -> Result<(), SdkError> {
        let mut record = self.reload()?;
        if record.state != AgentCreationState::Complete {
            record.state = AgentCreationState::Complete;
            self.store.save(&record)?;
        }
        Ok(())
    }

    fn reload(&self) -> Result<AgentCreationRecord, SdkError> {
        self.store.load(&self.record.request_id)?.ok_or(SdkError::CustodySetupInvalid)
    }
}
