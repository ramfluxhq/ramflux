// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiving-node identity and distinct receipt/proxy signing roles.

use super::BindingMode;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKeyStatus {
    Active,
    Retiring,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptKey {
    pub key_id: String,
    pub public_key: String,
    pub not_before: u64,
    pub sign_until: u64,
    pub overlap_until: u64,
    pub status: ReceiptKeyStatus,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyKey {
    pub key_id: String,
    pub public_key: String,
    pub not_before: u64,
    pub sign_until: u64,
    pub overlap_until: u64,
    pub status: ReceiptKeyStatus,
    pub proxy_id: String,
    pub audiences: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentityRecord {
    pub schema: String,
    pub version: u32,
    pub node_id: String,
    pub node_signing_public_key: String,
    pub epoch: u64,
    pub previous_record_hash: Option<String>,
    pub issued_at: u64,
    pub receipt_keys: Vec<ReceiptKey>,
    pub revoked_receipt_key_ids: Vec<String>,
    pub proxy_keys: Vec<ProxyKey>,
    pub revoked_proxy_key_ids: Vec<String>,
    pub channel_binding_modes: Vec<BindingMode>,
}
