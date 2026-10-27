// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home history carries the evidence of each individual transition.
use super::{Authorization, CommitProof, Genesis, Signed};
use crate::custody::{
    BranchCertificate, DeviceRef, Envelope, MasterCertificate, NodeIdentityRecord, Publication,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HomeRecord {
    Genesis { genesis: Box<Signed<Genesis>> },
    Committed { authorization: Box<Signed<Authorization>>, commit_proof: Box<Signed<CommitProof>> },
}
impl HomeRecord {
    #[must_use]
    pub fn epoch(&self) -> u64 {
        match self {
            Self::Genesis { genesis } => genesis.body.home_epoch,
            Self::Committed { authorization, .. } => authorization.body.next_home_epoch,
        }
    }
    #[must_use]
    pub fn account_anchor(&self) -> &str {
        match self {
            Self::Genesis { genesis } => &genesis.body.account_anchor,
            Self::Committed { authorization, .. } => &authorization.body.account_anchor,
        }
    }
    #[must_use]
    pub fn home(&self) -> (&str, &str) {
        match self {
            Self::Genesis { genesis } => (&genesis.body.home_node, &genesis.body.home_node_key),
            Self::Committed { authorization, .. } => {
                (&authorization.body.destination_node, &authorization.body.destination_key)
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordEvidence {
    pub authority: Publication,
    pub record: HomeRecord,
    pub management_certificate_chain: Vec<Envelope<MasterCertificate>>,
    pub actor_certificate: Option<Envelope<BranchCertificate>>,
    pub node_record: Envelope<NodeIdentityRecord>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveResult {
    pub home: RecordEvidence,
    pub predecessors: Vec<RecordEvidence>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryMapEntry {
    pub device_ref: DeviceRef,
    pub target_delivery_id: String,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacklogProgress {
    pub scheduled: u64,
    pub forwarded: u64,
    pub receiver_acked: u64,
    pub expired: u64,
    pub rejected: u64,
    pub evidence_required: u64,
    pub remaining: u64,
}
