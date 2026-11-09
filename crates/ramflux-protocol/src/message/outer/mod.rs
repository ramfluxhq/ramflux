// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate outer envelope, named `delivery_mode` profile, and size preflight (S10a P06).
//!
//! Dormant until the storage generation flips to message schema v1. Live
//! [`crate::Envelope`] and `ext.delivery_mode` stay the wire profile while the
//! gate is off.

use crate::schema_profile::schema_v1_live;
use crate::{ProtocolError, SignedFields, ephemeral};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Candidate envelope schema installed at the profile reset.
pub const CANDIDATE_ENVELOPE_SCHEMA: &str = "ramflux.envelope.v2";
/// Framing length prefix before Inner.
pub const FRAME_PREFIX_BYTES: usize = 4;
/// Reporting opening appended after Inner.
pub const REPORT_OPENING_BYTES: usize = 32;
/// Maximum exact Inner bytes (§1.2).
pub const MAX_INNER_BYTES: usize = crate::message::validation::MAX_INNER_BYTES;
/// Maximum unpadded plaintext: prefix + Inner + opening.
pub const MAX_UNPADDED_PLAINTEXT_BYTES: usize = 524_288;
/// Maximum padded plaintext.
pub const MAX_PADDED_PLAINTEXT_BYTES: usize = 524_288;
/// Normal encrypted-header plaintext bytes.
pub const MAX_ENCRYPTED_HEADER_BYTES: usize = 512;
/// Bootstrap capsule plaintext cap.
pub const MAX_BOOTSTRAP_CAPSULE_BYTES: usize = 16 * 1024;
/// Outer metadata budget.
pub const MAX_OUTER_METADATA_BYTES: usize = 64 * 1024;
/// UTF-8 identifier cap.
pub const MAX_IDENTIFIER_BYTES: usize = 256;
/// Complete sender-signed envelope/frame cap (transport and bus).
pub const MAX_COMPLETE_FRAME_BYTES: usize = 1_048_576;
/// Normal `CryptoBox` overhead above padded body (design section 5.5).
pub const CRYPTOBOX_OVERHEAD_BYTES: usize = 581;
/// Discovery token an old node must advertise to accept the v1 profile.
pub const MESSAGE_SCHEMA_V1_PROFILE: &str = "message-schema.v1";

/// Named sender-signed/AEAD-bound delivery mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedDeliveryMode {
    Durable,
    Ephemeral,
}

/// Collapsed delivery class after the reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateDeliveryClass {
    Message,
    CallWake,
}

/// Candidate outer envelope. Live [`crate::Envelope`] is unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateOuterEnvelope {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    pub envelope_id: String,
    pub source_principal_id: String,
    pub source_device_id: String,
    pub target_delivery_id: String,
    pub delivery_class: CandidateDeliveryClass,
    pub priority: crate::Priority,
    pub ttl_seconds: u32,
    pub created_at: i64,
    pub encrypted_payload: String,
    pub payload_hash: String,
    pub collapse_tag: String,
    pub delivery_mode: NamedDeliveryMode,
    #[serde(default)]
    pub node_report_receipt: Option<Value>,
    #[serde(flatten)]
    pub signed: SignedFields,
}

/// Profile and size refusals for the candidate outer codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OuterProfileError {
    #[error("new profile rejects ext.delivery_mode bridge")]
    Bridge,
    #[error("new profile rejects dual delivery_mode fields")]
    DualField,
    #[error("new profile rejects unknown delivery_mode")]
    UnknownMode,
    #[error("delivery_mode is required")]
    MissingMode,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("candidate outer envelope is malformed")]
    Malformed,
    #[error("collapse_tag must be 32 bytes")]
    CollapseTag,
    #[error("identifier exceeds 256 bytes")]
    Identifier,
}

/// Measured sizes checked before any ratchet or outbox commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressSizes {
    pub inner_bytes: usize,
    pub unpadded_plaintext_bytes: usize,
    pub padded_plaintext_bytes: usize,
    pub encrypted_header_bytes: usize,
    pub bootstrap_capsule_bytes: usize,
    pub outer_metadata_bytes: usize,
    pub identifier_bytes: usize,
    pub complete_frame_bytes: usize,
}

/// Temporary send ratchet; only a size-accepted copy may commit it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TemporaryRatchet {
    committed: bool,
}

impl TemporaryRatchet {
    #[must_use]
    pub const fn new() -> Self {
        Self { committed: false }
    }

    fn commit(&mut self) {
        self.committed = true;
    }

    #[must_use]
    pub const fn is_committed(&self) -> bool {
        self.committed
    }
}

impl IngressSizes {
    /// Derive framed sizes from an Inner length. Padmé equalization is S10b.
    ///
    /// # Errors
    /// Returns [`OuterProfileError::PayloadTooLarge`] when the framed length overflows.
    pub fn from_inner(inner_bytes: usize) -> Result<Self, OuterProfileError> {
        let unpadded = inner_bytes
            .checked_add(FRAME_PREFIX_BYTES)
            .and_then(|n| n.checked_add(REPORT_OPENING_BYTES))
            .ok_or(OuterProfileError::PayloadTooLarge)?;
        let complete = unpadded
            .checked_add(CRYPTOBOX_OVERHEAD_BYTES)
            .ok_or(OuterProfileError::PayloadTooLarge)?;
        Ok(Self {
            inner_bytes,
            unpadded_plaintext_bytes: unpadded,
            padded_plaintext_bytes: unpadded,
            encrypted_header_bytes: MAX_ENCRYPTED_HEADER_BYTES,
            bootstrap_capsule_bytes: 0,
            outer_metadata_bytes: 0,
            identifier_bytes: 0,
            complete_frame_bytes: complete,
        })
    }
}

/// Classify a candidate JSON object before typed decode.
///
/// # Errors
/// Bridge, dual-field, unknown, or missing named `delivery_mode`.
pub fn validate_candidate_delivery_mode(
    value: &Value,
) -> Result<NamedDeliveryMode, OuterProfileError> {
    let named = value.get("delivery_mode");
    let bridge =
        value.get("ext").and_then(Value::as_object).and_then(|ext| ext.get("delivery_mode"));
    match (named, bridge) {
        (Some(_), Some(_)) => Err(OuterProfileError::DualField),
        (None, Some(_)) => Err(OuterProfileError::Bridge),
        (None, None) => Err(OuterProfileError::MissingMode),
        (Some(Value::String(mode)), None) if mode == "durable" => Ok(NamedDeliveryMode::Durable),
        (Some(Value::String(mode)), None) if mode == "ephemeral" => {
            Ok(NamedDeliveryMode::Ephemeral)
        }
        (Some(_), None) => Err(OuterProfileError::UnknownMode),
    }
}

/// Decode candidate outer JSON through I-JSON, then the named-mode profile.
///
/// # Errors
/// I-JSON, profile, or schema failures.
pub fn decode_candidate_outer_ijson(
    bytes: &[u8],
) -> Result<CandidateOuterEnvelope, OuterProfileError> {
    let value: Value = crate::parse_i_json(bytes).map_err(|_| OuterProfileError::Malformed)?;
    validate_candidate_delivery_mode(&value)?;
    let outer: CandidateOuterEnvelope =
        serde_json::from_value(value).map_err(|_| OuterProfileError::Malformed)?;
    validate_candidate_outer(&outer)?;
    Ok(outer)
}

/// Bound fields on an already-typed candidate envelope.
///
/// # Errors
/// Schema, collapse tag, identifier, or TTL refusals.
pub fn validate_candidate_outer(outer: &CandidateOuterEnvelope) -> Result<(), OuterProfileError> {
    if outer.schema != CANDIDATE_ENVELOPE_SCHEMA {
        return Err(OuterProfileError::Malformed);
    }
    if decode_collapse_tag(&outer.collapse_tag)?.len() != 32 {
        return Err(OuterProfileError::CollapseTag);
    }
    for id in [
        outer.envelope_id.as_str(),
        outer.source_principal_id.as_str(),
        outer.source_device_id.as_str(),
        outer.target_delivery_id.as_str(),
    ] {
        if id.len() > MAX_IDENTIFIER_BYTES {
            return Err(OuterProfileError::Identifier);
        }
    }
    if outer.delivery_mode == NamedDeliveryMode::Ephemeral
        && !(ephemeral::MIN_EPHEMERAL_TTL_SECONDS..=ephemeral::MAX_EPHEMERAL_TTL_SECONDS)
            .contains(&outer.ttl_seconds)
    {
        return Err(OuterProfileError::Malformed);
    }
    Ok(())
}

/// Check every ingress arithmetic/native size cap.
///
/// # Errors
/// [`OuterProfileError::PayloadTooLarge`] when any cap overflows.
pub fn check_ingress_caps(sizes: IngressSizes) -> Result<(), OuterProfileError> {
    let framed = sizes
        .inner_bytes
        .checked_add(FRAME_PREFIX_BYTES)
        .and_then(|n| n.checked_add(REPORT_OPENING_BYTES))
        .ok_or(OuterProfileError::PayloadTooLarge)?;
    if framed != sizes.unpadded_plaintext_bytes {
        return Err(OuterProfileError::PayloadTooLarge);
    }
    if sizes.inner_bytes > MAX_INNER_BYTES
        || sizes.unpadded_plaintext_bytes > MAX_UNPADDED_PLAINTEXT_BYTES
        || sizes.padded_plaintext_bytes > MAX_PADDED_PLAINTEXT_BYTES
        || sizes.encrypted_header_bytes > MAX_ENCRYPTED_HEADER_BYTES
        || sizes.bootstrap_capsule_bytes > MAX_BOOTSTRAP_CAPSULE_BYTES
        || sizes.outer_metadata_bytes > MAX_OUTER_METADATA_BYTES
        || sizes.identifier_bytes > MAX_IDENTIFIER_BYTES
        || sizes.complete_frame_bytes > MAX_COMPLETE_FRAME_BYTES
    {
        return Err(OuterProfileError::PayloadTooLarge);
    }
    Ok(())
}

/// Preflight every cap, then commit the temporary ratchet.
///
/// # Errors
/// [`OuterProfileError::PayloadTooLarge`] leaves the ratchet uncommitted.
pub fn accept_after_size_preflight(
    sizes: IngressSizes,
    ratchet: &mut TemporaryRatchet,
) -> Result<(), OuterProfileError> {
    check_ingress_caps(sizes)?;
    ratchet.commit();
    Ok(())
}

/// Sender-signed candidate bytes. Node receipt is excluded from the signature.
///
/// # Errors
/// Canonical JSON failures.
pub fn candidate_outer_sender_signed_bytes(
    outer: &CandidateOuterEnvelope,
) -> Result<Vec<u8>, ProtocolError> {
    let mut sender = outer.clone();
    sender.node_report_receipt = None;
    crate::signed_bytes(&sender)
}

/// Refuse a live envelope that still carries the signed ext bridge.
///
/// # Errors
/// [`OuterProfileError::Bridge`] when `ext.delivery_mode` is present.
pub fn refuse_live_bridge(envelope: &crate::Envelope) -> Result<(), OuterProfileError> {
    if envelope.delivery_mode_bridge().is_some() {
        return Err(OuterProfileError::Bridge);
    }
    Ok(())
}

/// Candidate profile token on a discovery record. Old nodes are rejected.
///
/// # Errors
/// [`ProtocolError::InvalidDomain`] when the v1 profile is absent.
pub fn discover_candidate_message_schema(
    record: &crate::WellKnownClientRecord,
) -> Result<(), ProtocolError> {
    if record.protocol_versions.iter().any(|version| version == MESSAGE_SCHEMA_V1_PROFILE)
        || record.client_capabilities.iter().any(|cap| cap == MESSAGE_SCHEMA_V1_PROFILE)
    {
        return Ok(());
    }
    Err(ProtocolError::InvalidDomain {
        expected: MESSAGE_SCHEMA_V1_PROFILE,
        actual: record.protocol_versions.first().cloned().unwrap_or_default(),
    })
}

/// Run candidate discovery only after activation.
///
/// # Errors
/// Propagates [`discover_candidate_message_schema`] when the v1 profile is live.
pub fn admit_discovered_profile(
    record: &crate::WellKnownClientRecord,
) -> Result<(), ProtocolError> {
    if !schema_v1_live() {
        return Ok(());
    }
    discover_candidate_message_schema(record)
}

fn decode_collapse_tag(tag: &str) -> Result<Vec<u8>, OuterProfileError> {
    crate::decode_base64url(tag).map_err(|_| OuterProfileError::CollapseTag)
}

#[cfg(test)]
mod tests;
