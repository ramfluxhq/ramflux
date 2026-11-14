// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Existing federation rotation fields and signing transcript remain byte compatible.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeKeyRotation {
    pub node_id: String,
    pub old_node_public_key: String,
    pub new_node_public_key: String,
    pub rotated_at: u64,
    pub signature: String,
}
impl NodeKeyRotation {
    /// Validate the existing proof's shape without changing its signed-bytes domain.
    /// # Errors
    /// Refuses malformed node/keys/time, no-op key changes and noncanonical signatures.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        super::node(&self.node_id)?;
        super::digest(&self.old_node_public_key)?;
        super::digest(&self.new_node_public_key)?;
        super::safe(self.rotated_at)?;
        let signature = crate::decode_base64url(&self.signature)
            .map_err(|_| super::invalid("invalid rotation signature encoding"))?;
        if self.old_node_public_key == self.new_node_public_key
            || signature.len() != 64
            || crate::encode_base64url(&signature) != self.signature
        {
            return Err(super::invalid("invalid existing node rotation"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeContinuityKind {
    NodeContinuity,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeContinuityDocument {
    pub kind: NodeContinuityKind,
    pub node_id: String,
    pub rotations: Vec<NodeKeyRotation>,
}
impl NodeContinuityDocument {
    /// # Errors
    /// Refuses irrelevant nodes, malformed rotations and aggregate or proof-count overflow.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        super::node(&self.node_id)?;
        super::original_document(self, 1024 * 1024)?;
        if self.rotations.len() > 32 {
            return Err(super::invalid("node continuity proof count"));
        }
        for rotation in &self.rotations {
            rotation.validate()?;
            if rotation.node_id != self.node_id {
                return Err(super::invalid("irrelevant node continuity proof"));
            }
        }
        Ok(())
    }
}
