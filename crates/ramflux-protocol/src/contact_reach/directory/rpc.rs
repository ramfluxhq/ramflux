// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed home-to-centre RPC. Exact-name resolve sends no requesting account identity.
use super::{DirectoryAuth, IndexReceipt, IndexResolve, NameOperation};
use crate::custody::Envelope as Signed;
use crate::{
    contact_reach::{Challenge, ChallengeRequest, Cost, HistoricalCustodian},
    custody::CustodyAuthority,
    home_migration::ResolveResult,
};
use serde::{Deserialize, Serialize};

pub const MUTATE_PATH: &str = "/v1/usernames/mutate";
pub const PREPARE_PATH: &str = "/v1/usernames/prepare";
pub const COMMIT_PATH: &str = "/v1/usernames/commit";
pub const STATUS_PATH: &str = "/v1/usernames/status";
pub const RESOLVE_PATH: &str = "/v1/usernames/resolve";
pub const COST_PATH: &str = "/v1/usernames/cost";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRequest<T> {
    pub auth: Signed<DirectoryAuth>,
    pub payload: T,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutatePayload {
    pub operation: Signed<NameOperation>,
    pub home: ResolveResult,
    pub custodian_history: Vec<HistoricalCustodian>,
    pub custody: CustodyAuthority,
    pub cost: Option<Cost>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPayload {
    pub operation_id: String,
    pub operation_hash: String,
    pub account_anchor: String,
    pub home: ResolveResult,
    pub custodian_history: Vec<HistoricalCustodian>,
    pub custody: CustodyAuthority,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvePayload {
    pub name: String,
    pub nonce: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryResult {
    Receipt { receipt: Signed<IndexReceipt> },
    Resolve { resolve: Signed<IndexResolve> },
    Challenge { challenge: Signed<Challenge> },
    Error { reason: crate::username_directory::DirectoryCode, retry_after_ms: Option<u64> },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResponse {
    pub nonce: String,
    pub result: DirectoryResult,
}
/// The cost endpoint uses this exact body, already shared with receiving homes.
pub type DirectoryCostPayload = ChallengeRequest;
