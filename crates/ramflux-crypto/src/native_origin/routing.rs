// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed authenticated routing and retained receive provenance, never execution state.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Direct,
    GroupMessage,
    GroupControl,
    Receipt,
    Control,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    pub kind: Kind,
    pub conversation_id: String,
    pub group_id: Option<String>,
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_message_id: Option<String>,
    #[serde(default)]
    pub attachments: bool,
}
/// Only immutable authenticated receive provenance is retained, never a fresh authority grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: String,
    pub conversation: String,
    pub message: String,
    pub envelope_id: String,
    pub payload_hash: String,
    pub expires_at: i64,
    pub original_mode: String,
    pub source_epoch: u64,
    pub original_route: String,
    pub outer_receipt_key: String,
    #[serde(default)]
    pub source_evidence_copy: Option<String>,
    pub received_erasure_generation: i64,
}
