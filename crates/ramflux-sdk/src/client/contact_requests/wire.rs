// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-signed first-contact consent, independently bound to encrypted transport and endpoints.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
pub(super) const TTL: i64 = 7 * 24 * 3600;
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Decision {
    Request,
    Accept,
    Decline,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Body {
    pub schema: String,
    pub kind: Decision,
    pub request_id: String,
    pub requester_root: String,
    pub target_root: String,
    pub actor_root: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
    pub note: Option<String>,
    pub manifest: crate::prekey::SdkDeviceManifestResponse,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Control {
    pub body: Body,
    pub signature: String,
}

pub(super) fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.into())
}

pub(crate) fn conversation(requester: &str, target: &str) -> Result<String, SdkError> {
    Ok(format!(
        "contact-request:{}",
        ramflux_protocol::hash_base64url(
            "ramflux.contact_request.conversation.v1",
            &ramflux_protocol::canonical_json_bytes(&(requester, target))?
        )
    ))
}
pub(super) fn request_id(requester: &str, nonce: &str) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.contact_request.id.v1",
        &ramflux_protocol::canonical_json_bytes(&(requester, nonce))?,
    ))
}

impl RamfluxClient {
    pub(crate) fn verify_contact_control(
        &self,
        entry: &GatewayInboxEntry,
        route: &crate::client::routed::Routing,
        bytes: &[u8],
    ) -> Result<Control, SdkError> {
        let consent = super::native::decode(bytes)?
            .ok_or_else(|| invalid("generated contact consent required"))?;
        self.verify_native_contact_control(entry, route, consent)
    }
}
