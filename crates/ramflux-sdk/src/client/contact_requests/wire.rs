// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-signed first-contact consent, independently bound to encrypted transport and endpoints.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
pub(super) const DOMAIN: &str = "ramflux.contact_request.v1";
pub(crate) const ENVELOPE_SCHEMA: &str = "ramflux.sdk.contact_request.envelope.v1";
pub(super) const MAX_WIRE_BYTES: usize = 131_072;
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
fn signed_bytes(body: &Body) -> Result<Vec<u8>, SdkError> {
    Ok(ramflux_protocol::canonical_json_bytes(&serde_json::json!({"domain":DOMAIN,"body":body}))?)
}
pub(super) fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.into())
}
fn valid_hash(value: &str) -> bool {
    ramflux_protocol::decode_base64url(value)
        .is_ok_and(|bytes| bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == value)
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
pub(super) fn sign(root: &ramflux_crypto::IdentityRoot, body: Body) -> Result<Control, SdkError> {
    if body.actor_root
        != ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key())
    {
        return Err(invalid("contact request signer differs from actor root"));
    }
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &signed_bytes(&body)?,
        root.signing_key.to_bytes(),
    );
    let control = Control { body, signature };
    if serde_json::to_vec(&control)?.len() > MAX_WIRE_BYTES {
        return Err(invalid("contact request exceeds wire budget"));
    }
    Ok(control)
}
impl RamfluxClient {
    pub(crate) fn verify_contact_control(
        &self,
        entry: &GatewayInboxEntry,
        route: &crate::client::routed::Routing,
        bytes: &[u8],
    ) -> Result<Control, SdkError> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(invalid("contact request exceeds wire budget"));
        }
        let control: Control = ramflux_protocol::parse_i_json(bytes)?;
        let body = &control.body;
        let now = now_unix_timestamp();
        let own = self.owned_device_identity()?;
        let source = self.authenticated_device_identity(entry)?;
        let (actor, target) = if body.kind == Decision::Request {
            (&body.requester_root, &body.target_root)
        } else {
            (&body.target_root, &body.requester_root)
        };
        if body.schema != DOMAIN
            || ![
                &body.request_id,
                &body.requester_root,
                &body.target_root,
                &body.actor_root,
                &body.nonce,
            ]
            .into_iter()
            .all(|id| valid_hash(id))
            || body.request_id != request_id(&body.requester_root, &body.nonce)?
            || body.requester_root == body.target_root
            || actor != &body.actor_root
            || target != own.root_commitment()
            || actor != source.root_commitment()
            || route.kind != crate::client::routed::Kind::Control
            || route.group_id.is_some()
            || route.attachments
            || route.conversation_id != conversation(&body.requester_root, &body.target_root)?
            || body.issued_at > now.saturating_add(60)
            || body.expires_at <= now
            || body.issued_at.checked_add(TTL) != Some(body.expires_at)
            || body.note.as_ref().is_some_and(|note| {
                note.chars().count() > 140
                    || !ramflux_protocol::text_safety::single_line_is_safe(note)
            })
        {
            return Err(invalid("contact request endpoint, lifetime or routing mismatch"));
        }
        crate::client::contact::verify_device_manifest(&body.manifest, actor)?;
        let trusted = self.trusted_device(&source)?;
        if body.manifest.principal_id != entry.envelope.source_principal_id
            || !body.manifest.devices.iter().any(|device| {
                device.device_id == source.device_id()
                    && trusted["signing_public_key"] == device.branch_public_key
            })
        {
            return Err(invalid("contact request does not bind the authenticated source key"));
        }
        ramflux_crypto::verify_canonical_signature(
            &signed_bytes(body)?,
            &control.signature,
            &body.manifest.root_public_key,
        )?;
        Ok(control)
    }
}
