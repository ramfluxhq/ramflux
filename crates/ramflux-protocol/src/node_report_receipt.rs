// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::{Deserialize, Serialize};

/// Independently signed acceptance evidence. Not part of the sender AEAD.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReportReceipt {
    pub node_id: String,
    pub envelope_id: String,
    pub source_ref: String,
    pub target_delivery_id: String,
    pub report_commitment: String,
    pub payload_hash: String,
    pub accepted_at: u64,
    pub signature: String,
}
