// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact branch-possession and receiving-node acceptance bodies.

use super::DeviceRef;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingMode {
    DirectExporter,
    HomeRelayReceipt,
    NoChannelBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchProofV3 {
    pub schema: String,
    pub version: u32,
    pub device_ref: DeviceRef,
    pub certificate_hash: String,
    pub record_hash: String,
    pub proof_id: String,
    pub challenge_nonce: String,
    pub audience: String,
    pub binding_mode: BindingMode,
    pub transport_binding: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Unsigned verifier state transported over an authenticated connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchChallenge {
    pub challenge_nonce: String,
    pub audience: String,
    pub binding_mode: BindingMode,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceIssuer {
    HomeRelay,
    NodeProxy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptancePurpose {
    Message,
    BranchProof,
    TimeProbe,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAcceptance {
    pub schema: String,
    pub version: u32,
    pub issuer_kind: AcceptanceIssuer,
    pub relay_id: String,
    pub relay_key_id: String,
    pub node_identity_record_hash: String,
    pub client_exporter_hash: Option<String>,
    pub receipt_id: String,
    pub message_hash: String,
    pub purpose: AcceptancePurpose,
    pub audience: String,
    pub source_device_ref: Option<DeviceRef>,
    pub branch_certificate_hash: Option<String>,
    pub target_anchor: Option<String>,
    pub challenge_nonce: Option<String>,
    pub accepted_at: u64,
}
