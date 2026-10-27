// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed action payloads and bounded evidence on the custody connection.
use super::{
    Action, Authorization, BacklogProgress, CommitProof, Control, DeliveryMapEntry,
    HomeAttestation, HomeRecord, NoncommitFence, Offer, Prepare, Receipt, RecordEvidence,
    ResolveResult, Signed,
};
use crate::custody::{BranchProofV3, Envelope, NodeIdentityRecord, Publication, RelayAcceptance};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealPayload {
    pub authorization_hash: String,
    pub offer_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitPayload {
    pub authorization_hash: String,
    pub offer_hash: String,
    pub seal_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivatePayload {
    pub home_record_hash: String,
    pub commit_proof_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPayload {
    pub account_anchor: String,
    pub migration_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvePayload {
    pub target_anchor: String,
    pub after_home_hash: Option<String>,
    pub limit: u64,
    pub old_node_hint: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencePayload {
    pub noncommit_fence_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawRequest")]
pub struct Request {
    pub control: Signed<Control>,
    pub payload: ActionPayload,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_record: Option<crate::WellKnownClientRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_record: Option<Envelope<NodeIdentityRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepare: Option<Signed<Prepare>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer: Option<Signed<Offer>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Signed<Authorization>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_receipt: Option<Signed<Receipt>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_proof: Option<Signed<CommitProof>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_record: Option<HomeRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Publication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_proof: Option<Envelope<BranchProofV3>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_map: Option<Vec<DeliveryMapEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Signed<HomeAttestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_identity_record: Option<Envelope<NodeIdentityRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_receipt: Option<Envelope<RelayAcceptance>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessors: Option<Vec<RecordEvidence>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noncommit_fence: Option<Signed<NoncommitFence>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub receipt: Signed<Receipt>,
    pub offer: Option<Signed<Offer>>,
    pub commit_proof: Option<Signed<CommitProof>>,
    pub noncommit_fence: Option<Signed<NoncommitFence>>,
    pub resolve_result: Option<ResolveResult>,
    pub backlog_progress: Option<BacklogProgress>,
    pub attestation: Option<Signed<HomeAttestation>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestPayload {
    pub account_anchor: String,
    pub destination_node: String,
    pub nonce: String,
}
/// Owner consent survives the admitted destination relaying this request to A.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestRequest {
    pub control: Signed<Control>,
    pub payload: AttestPayload,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionPayload {
    Attest(AttestPayload),
    Prepare(Box<Signed<Prepare>>),
    Seal(SealPayload),
    Commit(CommitPayload),
    Activate(ActivatePayload),
    Operation(OperationPayload),
    Resolve(ResolvePayload),
    Fence(FencePayload),
}
// JSON exists only at the strict action-selected decoding boundary, never as an admitted payload.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest {
    control: Signed<Control>,
    payload: serde_json::Value,
    evidence: Evidence,
}
impl TryFrom<RawRequest> for Request {
    type Error = serde_json::Error;
    fn try_from(raw: RawRequest) -> Result<Self, Self::Error> {
        let payload = match raw.control.body.action {
            Action::Attest => ActionPayload::Attest(serde_json::from_value(raw.payload)?),
            Action::Prepare => ActionPayload::Prepare(serde_json::from_value(raw.payload)?),
            Action::Seal => ActionPayload::Seal(serde_json::from_value(raw.payload)?),
            Action::Commit => ActionPayload::Commit(serde_json::from_value(raw.payload)?),
            Action::Activate => ActionPayload::Activate(serde_json::from_value(raw.payload)?),
            Action::Status | Action::Abort => {
                ActionPayload::Operation(serde_json::from_value(raw.payload)?)
            }
            Action::Resolve => ActionPayload::Resolve(serde_json::from_value(raw.payload)?),
            Action::Fence => ActionPayload::Fence(serde_json::from_value(raw.payload)?),
        };
        Ok(Self { control: raw.control, payload, evidence: raw.evidence })
    }
}
