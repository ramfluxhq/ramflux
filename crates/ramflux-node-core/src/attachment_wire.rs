// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Mesh body the gateway forwards to the home relay. The session frame types live in
//! `ramflux-protocol` so the client SDK shares them without a node dependency.

use serde::{Deserialize, Serialize};

pub use ramflux_protocol::attachment_wire::{
    ATTACHMENT_CALL_BODY_MAX, AttachmentAuthorityReply, AttachmentCall, AttachmentFrame,
    AttachmentReplyFrame, WireBytes,
};

use crate::RequesterWire;

/// Relay mesh route. The relay accepts it only from the local gateway identity.
pub const ATTACHMENT_MESH_PATH: &str = "/attachments/v1/call";

/// Gateway to relay. `requester` comes from the authenticated session only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeshRequest {
    pub requester: RequesterWire,
    pub call: AttachmentCall,
}

/// Relay to gateway. Success and refusal are both HTTP 200 with a typed `code`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeshReply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default)]
    pub body: WireBytes,
}
