// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Correlated source submission results preserve the existing owner result bytes.
use super::{OperationResult, Reason, SourceSubmitRequest, SubmitOutcome, digest, invalid};
use serde::{Deserialize, Serialize};

pub const MAX_SUBMIT_RESPONSE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSubmitResponseKind {
    SubmitResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedResponse")]
pub struct SourceSubmitResponse {
    pub kind: SourceSubmitResponseKind,
    pub request_id: String,
    pub result: OperationResult,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedResponse {
    kind: SourceSubmitResponseKind,
    request_id: String,
    result: OperationResult,
}

impl TryFrom<UncheckedResponse> for SourceSubmitResponse {
    type Error = crate::ProtocolError;
    fn try_from(value: UncheckedResponse) -> Result<Self, Self::Error> {
        let result = Self { kind: value.kind, request_id: value.request_id, result: value.result };
        result.validate()?;
        Ok(result)
    }
}

impl SourceSubmitResponse {
    /// Validate the closed result and reason sets before serialization or owner mapping.
    /// # Errors
    /// Refuses other result arms, invalid nulls/hints, malformed ids and oversized replies.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        digest(&self.request_id)?;
        match &self.result {
            OperationResult::Submit { envelope_id, outcome, reason } => {
                super::super::text(envelope_id)?;
                if (*outcome == SubmitOutcome::Refused) != reason.is_some()
                    || reason.is_some_and(|reason| !refusal_reason(reason))
                {
                    return Err(invalid("source submit result reason"));
                }
            }
            OperationResult::Error { reason, retry_after_ms, current_revision } => {
                if !error_reason(*reason)
                    || current_revision.is_some()
                    || *retry_after_ms != (*reason == Reason::ForeignRateLimited).then_some(1000)
                {
                    return Err(invalid("source submit error metadata"));
                }
            }
            _ => return Err(invalid("source submit result arm")),
        }
        if crate::canonical_json_bytes(self)?.len() > MAX_SUBMIT_RESPONSE_BYTES {
            return Err(invalid("source submit response byte budget"));
        }
        Ok(())
    }
}

impl SourceSubmitRequest {
    /// Require exact response correlation before using any source-service result.
    /// # Errors
    /// A caller treats a malformed or mismatched reply as unknown and retries unchanged.
    pub fn validate_response(
        &self,
        response: &SourceSubmitResponse,
    ) -> Result<(), crate::ProtocolError> {
        self.validate()?;
        response.validate()?;
        if response.request_id != self.request_id
            || matches!(&response.result, OperationResult::Submit { envelope_id, .. }
                if envelope_id != &self.submission.envelope.envelope_id)
        {
            return Err(invalid("source submit response correlation"));
        }
        Ok(())
    }

    /// Preserve the original envelope identity when a forwarding attempt cannot be established.
    #[must_use]
    pub fn unknown_result(&self) -> OperationResult {
        OperationResult::Submit {
            envelope_id: self.submission.envelope.envelope_id.clone(),
            outcome: SubmitOutcome::Unknown,
            reason: None,
        }
    }

    /// Map the correlated inner result unchanged; a mismatched reply leaves delivery unknown.
    #[must_use]
    pub fn owner_result(&self, response: SourceSubmitResponse) -> OperationResult {
        if self.validate_response(&response).is_err() {
            self.unknown_result()
        } else {
            response.result
        }
    }
}

const fn refusal_reason(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::ForeignReadRefused
            | Reason::ReachPolicyRequired
            | Reason::ConversationGrantExpired
            | Reason::ReachRouteInvalid
            | Reason::CostRequired
            | Reason::CostInvalid
            | Reason::ForeignSpamLimited
            | Reason::ForeignRateLimited
            | Reason::ForeignCapacity
            | Reason::ForeignCapabilityMissing
            | Reason::GroupEpochStale
    )
}

const fn error_reason(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::FeatureDisabled
            | Reason::ForeignInvalidFrame
            | Reason::ForeignPayloadTooLarge
            | Reason::ForeignPolicyDenied
            | Reason::ForeignCapabilityMissing
            | Reason::ForeignUnavailable
            | Reason::ForeignRateLimited
            | Reason::ForeignCapacity
            | Reason::ReachRouteInvalid
            | Reason::CostInvalid
    )
}

#[cfg(test)]
mod tests;
