// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiving-home results, authenticated by the mesh connection and correlated to frozen bytes.
use super::{OperationResult, SubmitOutcome, invalid, node};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardResultKind {
    ForwardResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedResult")]
pub struct ForwardResult {
    pub kind: ForwardResultKind,
    pub source_node_id: String,
    pub target_node_id: String,
    pub envelope_id: String,
    pub result: OperationResult,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedResult {
    kind: ForwardResultKind,
    source_node_id: String,
    target_node_id: String,
    envelope_id: String,
    result: OperationResult,
}

impl TryFrom<UncheckedResult> for ForwardResult {
    type Error = crate::ProtocolError;
    fn try_from(value: UncheckedResult) -> Result<Self, Self::Error> {
        let result = Self {
            kind: value.kind,
            source_node_id: value.source_node_id,
            target_node_id: value.target_node_id,
            envelope_id: value.envelope_id,
            result: value.result,
        };
        result.validate()?;
        Ok(result)
    }
}

/// Check the bare receiving-router arm; a receiver cannot claim source spooling.
/// # Errors
/// Refuses non-submit/error arms, malformed reasons/hints, spooled outcomes and oversized replies.
pub fn validate_receiving_result(result: &OperationResult) -> Result<(), crate::ProtocolError> {
    super::submit_response::validate_submit_result(result)?;
    if matches!(result, OperationResult::Submit { outcome: SubmitOutcome::Spooled, .. })
        || crate::canonical_json_bytes(result)?.len() > super::MAX_SUBMIT_RESPONSE_BYTES
    {
        return Err(invalid("receiving submit result"));
    }
    Ok(())
}

impl ForwardResult {
    /// Check the closed receiver grammar and both envelope identities.
    /// # Errors
    /// Refuses malformed node names, identities, arms, metadata and oversized replies.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        node(&self.source_node_id)?;
        node(&self.target_node_id)?;
        super::super::text(&self.envelope_id)?;
        validate_receiving_result(&self.result)?;
        if matches!(&self.result, OperationResult::Submit { envelope_id, .. }
            if envelope_id != &self.envelope_id)
            || crate::canonical_json_bytes(self)?.len() > super::MAX_SUBMIT_RESPONSE_BYTES
        {
            return Err(invalid("forward result identity or byte budget"));
        }
        Ok(())
    }

    /// Map an authenticated HTTP reply against the immutable request selectors.
    /// # Errors
    /// Invalid correlation returns unknown with the original envelope identity.
    #[must_use]
    pub fn source_result(
        response: Option<&Self>,
        status: u16,
        source_node: &str,
        target_node: &str,
        envelope: &str,
    ) -> OperationResult {
        if let Some(response) = response
            && status == 200
            && response.validate().is_ok()
            && response.source_node_id == source_node
            && response.target_node_id == target_node
            && response.envelope_id == envelope
        {
            return response.result.clone();
        }
        OperationResult::Submit {
            envelope_id: envelope.to_owned(),
            outcome: SubmitOutcome::Unknown,
            reason: None,
        }
    }
}

#[cfg(test)]
mod tests;
