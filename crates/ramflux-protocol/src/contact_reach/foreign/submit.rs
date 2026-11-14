// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The specified own-router to federation Submit request; no owner credentials leave the node.
use super::{MAX_FRAME_BYTES, Submission, digest, invalid, node};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSubmitKind {
    Submit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSubmitRequest {
    pub kind: SourceSubmitKind,
    pub request_id: String,
    pub remaining_ms: u64,
    pub target_node_id: String,
    pub submission: Submission,
}

impl SourceSubmitRequest {
    /// Validate correlation, target and hop budget before source submission dispatch.
    /// Transport role, current source authority and receiving admission remain separate checks.
    /// # Errors
    /// Refuses malformed selectors/routes, an expired hop budget or oversized complete request.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        digest(&self.request_id)?;
        node(&self.target_node_id)?;
        self.submission.route.body.validate()?;
        if !(1..=10_000).contains(&self.remaining_ms)
            || crate::canonical_json_bytes(&self.submission.route)?.len() > 4096
            || self.submission.cost.as_ref().is_some_and(|cost| {
                crate::canonical_json_bytes(cost).map_or(true, |bytes| bytes.len() > 2048)
            })
            || crate::canonical_json_bytes(self)?.len() > MAX_FRAME_BYTES
        {
            return Err(invalid("source submit budget"));
        }
        Ok(())
    }
}
