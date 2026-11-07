// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Wire envelopes of the attachment renewal route, shared by the home gateway, the home
//! router and the source relay so the three never drift. JSON carries byte arrays only;
//! signed native bytes are never reserialized.
use serde::{Deserialize, Serialize};

/// Requester identity on the wire, taken only from the authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequesterWire {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub signing_public_key: [u8; 32],
    pub home_node_id: String,
}

/// Challenge request from the home gateway. `grant_id` is derived from the capability at
/// the source, not sent; `home_node` is the sending node, never a client field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeEnvelope {
    pub capability: Vec<u8>,
    pub target_operation: Vec<u8>,
    pub requester: RequesterWire,
    pub home_node: String,
}

/// The seven forwarded byte fields; `grant` is the complete registered capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardedRenewal {
    pub operation: Vec<u8>,
    pub body: Vec<u8>,
    pub attestation: Vec<u8>,
    pub home_signature: Vec<u8>,
    pub proof: Vec<u8>,
    pub requester_signature: Vec<u8>,
    pub grant: Vec<u8>,
}
