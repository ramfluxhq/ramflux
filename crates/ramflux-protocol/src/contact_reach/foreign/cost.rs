// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cost issuer hops preserve the public request and closed challenge/error result grammar.
use super::{ChallengeRequest, OperationResult, Reason, digest, invalid, node};
use serde::{Deserialize, Serialize};
pub const PEER_COST_PATH: &str = "/contact/reach/cost/v1";
pub const ISSUER_COST_PATH: &str = "/internal/contact/cost/v1";
pub const MAX_COST_REQUEST_BYTES: usize = 2048;
pub const MAX_COST_RESPONSE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCostKind {
    Cost,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCostResultKind {
    CostResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCostRequest {
    pub kind: SourceCostKind,
    pub request_id: String,
    pub remaining_ms: u64,
    pub target_node_id: String,
    pub request: ChallengeRequest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostRequest {
    pub request_id: String,
    pub remaining_ms: u64,
    pub request: ChallengeRequest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCostResponse {
    pub kind: SourceCostResultKind,
    pub request_id: String,
    pub result: OperationResult,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostResponse {
    pub request_id: String,
    pub result: OperationResult,
}

impl SourceCostRequest {
    /// # Errors
    /// Refuses invalid selectors, deadline budgets or oversized complete requests.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        node(&self.target_node_id)?;
        self.public_request().validate()?;
        if crate::canonical_json_bytes(self)?.len() > MAX_COST_REQUEST_BYTES {
            return Err(invalid("source cost request budget"));
        }
        Ok(())
    }
    #[must_use]
    pub fn public_request(&self) -> CostRequest {
        CostRequest {
            request_id: self.request_id.clone(),
            remaining_ms: self.remaining_ms,
            request: self.request.clone(),
        }
    }
    /// # Errors
    /// Refuses uncorrelated or semantically invalid replies; the issuer's arm is unchanged.
    pub fn validate_response(
        &self,
        response: &SourceCostResponse,
    ) -> Result<(), crate::ProtocolError> {
        self.validate()?;
        if crate::canonical_json_bytes(response)?.len() > MAX_COST_RESPONSE_BYTES {
            return Err(invalid("source cost reply budget"));
        }
        self.public_request().validate_response(
            &CostResponse {
                request_id: response.request_id.clone(),
                result: response.result.clone(),
            },
            &self.target_node_id,
        )
    }
}
impl CostRequest {
    /// # Errors
    /// Refuses malformed request identities, purposes or expired/oversized hop budgets.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        digest(&self.request_id)?;
        self.request.validate()?;
        if !(1..=10_000).contains(&self.remaining_ms)
            || crate::canonical_json_bytes(&self.request)?.len() > 1024
            || crate::canonical_json_bytes(self)?.len() > MAX_COST_REQUEST_BYTES
        {
            return Err(invalid("cost request budget"));
        }
        Ok(())
    }
    /// # Errors
    /// Refuses changed correlation, issuer/purpose/target bindings and out-of-set errors.
    pub fn validate_response(
        &self,
        response: &CostResponse,
        issuer: &str,
    ) -> Result<(), crate::ProtocolError> {
        self.validate()?;
        digest(&response.request_id)?;
        if self.request_id != response.request_id
            || crate::canonical_json_bytes(response)?.len() > MAX_COST_RESPONSE_BYTES
        {
            return Err(invalid("cost response correlation or budget"));
        }
        match &response.result {
            OperationResult::Challenge { .. } => super::Operation::Cost {
                request: self.request.clone(),
                target_node_id: issuer.to_owned(),
            }
            .validate_result(&response.result),
            OperationResult::Error { reason, retry_after_ms, current_revision }
                if cost_error_reason(*reason)
                    && current_revision.is_none()
                    && *retry_after_ms
                        == (*reason == Reason::ForeignRateLimited).then_some(1000) =>
            {
                Ok(())
            }
            _ => Err(invalid("cost result arm or metadata")),
        }
    }
}

#[must_use]
pub const fn cost_error_reason(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::FeatureDisabled
            | Reason::ForeignInvalidFrame
            | Reason::ForeignPolicyDenied
            | Reason::ForeignUnavailable
            | Reason::ForeignRateLimited
            | Reason::ForeignCapacity
            | Reason::ForeignCapabilityMissing
            | Reason::CostInvalid
            | Reason::ForeignReadRefused
            | Reason::CustodyRefused
            | Reason::ForeignStorageUnavailable
    )
}

#[cfg(test)]
mod tests;
