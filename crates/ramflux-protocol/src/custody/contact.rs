// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary-approved consent bodies, with authority resolved by exact signed record hashes.
use super::{DeviceRef, invalid};
use crate::{MAX_SAFE_JSON_INTEGER, ProtocolError, domain};
use serde::{Deserialize, Serialize};

pub const CONTACT_CONSENT_TTL_SECONDS: u64 = 604_800;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactDecision {
    Request,
    Accept,
    Decline,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContactConsentV2 {
    pub schema: String,
    pub version: u32,
    pub kind: ContactDecision,
    pub request_id: String,
    pub nonce: String,
    pub requester_root: String,
    pub target_root: String,
    pub actor_root: String,
    pub sending_device_ref: DeviceRef,
    pub issued_at: u64,
    pub expires_at: u64,
    pub note: Option<String>,
    pub actor_record_hash: String,
    pub master_certificate_hash: String,
}

/// Validate exact v2 body structure and endpoint bindings without granting any authority.
/// # Errors
/// Rejects malformed ids, noncanonical anchors, inconsistent endpoints and invalid lifetimes.
pub fn validate_contact_consent(body: &ContactConsentV2) -> Result<(), ProtocolError> {
    let actor = match body.kind {
        ContactDecision::Request => &body.requester_root,
        ContactDecision::Accept | ContactDecision::Decline => &body.target_root,
    };
    let identifiers = [
        &body.request_id,
        &body.nonce,
        &body.requester_root,
        &body.target_root,
        &body.actor_root,
        &body.actor_record_hash,
        &body.master_certificate_hash,
    ];
    if body.schema != domain::CONTACT_REQUEST_V2
        || body.version != 2
        || body.requester_root == body.target_root
        || actor != &body.actor_root
        || body.sending_device_ref.account_anchor != body.actor_root
        || body.sending_device_ref.device_epoch == 0
        || body.sending_device_ref.device_epoch > MAX_SAFE_JSON_INTEGER
        || body.issued_at > MAX_SAFE_JSON_INTEGER
        || body.expires_at > MAX_SAFE_JSON_INTEGER
        || body.issued_at.checked_add(CONTACT_CONSENT_TTL_SECONDS) != Some(body.expires_at)
        || identifiers.into_iter().any(|id| {
            crate::decode_base64url(id)
                .map_or(true, |bytes| bytes.len() != 32 || crate::encode_base64url(bytes) != *id)
        })
        || body.note.as_ref().is_some_and(|note| {
            note.chars().count() > 140 || !crate::text_safety::single_line_is_safe(note)
        })
    {
        return Err(invalid("invalid custody contact consent"));
    }
    crate::validate_device_name(&body.sending_device_ref.device_id)?;
    if body.request_id
        != crate::hash_base64url(
            "ramflux.contact_request.id.v1",
            &crate::canonical_json_bytes(&(&body.requester_root, &body.nonce))?,
        )
    {
        return Err(invalid("custody contact request id mismatch"));
    }
    Ok(())
}
