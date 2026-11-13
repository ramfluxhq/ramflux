// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Service/peer query carrier contains no session, account credential or administration token.
use super::*;
pub const FOREIGN_PATH: &str = "/internal/contact/foreign/v1";
pub const PEER_QUERY_PATH: &str = "/contact/foreign/v1";
pub const SNAPSHOT_PATH: &str = "/internal/contact/snapshot/v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerQueryKind {
    Query,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerQueryRequest {
    pub kind: PeerQueryKind,
    pub request_id: String,
    pub remaining_ms: u64,
    pub query: Query,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerQueryResultKind {
    QueryResult,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerQueryResult {
    Query { reply: Box<PeerReply> },
    Error { reason: Reason, retry_after_ms: Option<u64>, current_revision: Option<u64> },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerQueryResponse {
    pub kind: PeerQueryResultKind,
    pub request_id: String,
    pub result: PeerQueryResult,
}
impl PeerQueryRequest {
    /// Validate the bounded correlated query before dialing or executing a public read.
    /// # Errors
    /// Refuses invalid identifiers, unsafe deadlines and an oversized Q.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        digest(&self.request_id)?;
        self.query.validate()?;
        if !(1..=10_000).contains(&self.remaining_ms) {
            return Err(invalid("peer query remaining deadline"));
        }
        Ok(())
    }
    /// Check carrier correlation; peer evidence still needs independent key/home verification.
    /// # Errors
    /// Refuses changed requests, account/node/query correlation or invalid error metadata.
    pub fn validate_response(
        &self,
        response: &PeerQueryResponse,
    ) -> Result<(), crate::ProtocolError> {
        self.validate()?;
        if response.request_id != self.request_id {
            return Err(invalid("peer query request mismatch"));
        }
        match &response.result {
            PeerQueryResult::Query { reply } => {
                let b = &reply.snapshot.body;
                if b.source_node != self.query.target_node
                    || b.target_node != self.query.source_node
                    || b.account_anchor != self.query.account_anchor
                    || b.request_nonce != self.query.nonce
                    || b.request_hash
                        != crate::custody::framed_hash(QUERY_HASH_DOMAIN, &self.query)?
                {
                    return Err(invalid("peer query snapshot mismatch"));
                }
            }
            PeerQueryResult::Error { reason, retry_after_ms, current_revision } => {
                let rate =
                    matches!(reason, Reason::ForeignRateLimited | Reason::ForeignSpamLimited);
                if current_revision.is_some() || *retry_after_ms != rate.then_some(1000) {
                    return Err(invalid("peer query error metadata"));
                }
            }
        }
        Ok(())
    }
}
