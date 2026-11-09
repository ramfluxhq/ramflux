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
/// Maximum sealed `CryptoBox` for a max-padded Inner (node-side decoded bound).
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_PADDED_PLAINTEXT_BYTES + CRYPTOBOX_OVERHEAD_BYTES;
/// Unpadded base64url length of [`MAX_CIPHERTEXT_BYTES`] (524,869 bytes, remainder 1).
pub const MAX_CIPHERTEXT_B64_CHARS: usize = 699_826;
/// Discovery token an old node must advertise to accept the v1 profile.
pub const MESSAGE_SCHEMA_V1_PROFILE: &str = "message-schema.v1";

const _: () = assert!(MAX_CIPHERTEXT_BYTES == 524_869);
const _: () = assert!(
    MAX_INNER_BYTES + FRAME_PREFIX_BYTES + REPORT_OPENING_BYTES == MAX_UNPADDED_PLAINTEXT_BYTES
);

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
    pub ciphertext_bytes: usize,
    pub unpadded_plaintext_bytes: usize,
    pub padded_plaintext_bytes: usize,
    pub encrypted_header_bytes: usize,
    pub bootstrap_capsule_bytes: usize,
    pub outer_metadata_bytes: usize,
    pub identifier_bytes: usize,
    pub complete_frame_bytes: usize,
}

/// Pair-session snapshot; only a size-accepted envelope may replace it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TemporaryRatchet {
    snapshot: Vec<u8>,
}

impl TemporaryRatchet {
    #[must_use]
    pub const fn new() -> Self {
        Self { snapshot: Vec::new() }
    }

    /// Wrap the currently persisted pair-session bytes.
    #[must_use]
    pub const fn wrap_session(snapshot: Vec<u8>) -> Self {
        Self { snapshot }
    }

    fn commit(&mut self, advanced: Vec<u8>) {
        self.snapshot = advanced;
    }

    #[must_use]
    pub fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }
}

impl IngressSizes {
    /// Framed Inner arithmetic. Header, metadata, identifiers and the complete
    /// frame stay 0 until [`Self::measure_candidate`] or [`Self::measure_live`]
    /// reads them from real input. Padmé equalization is S10b.
    ///
    /// # Errors
    /// Returns [`OuterProfileError::PayloadTooLarge`] when the framed length overflows.
    pub fn from_inner(inner_bytes: usize) -> Result<Self, OuterProfileError> {
        let unpadded = inner_bytes
            .checked_add(FRAME_PREFIX_BYTES)
            .and_then(|n| n.checked_add(REPORT_OPENING_BYTES))
            .ok_or(OuterProfileError::PayloadTooLarge)?;
        let ciphertext = unpadded
            .checked_add(CRYPTOBOX_OVERHEAD_BYTES)
            .ok_or(OuterProfileError::PayloadTooLarge)?;
        Ok(Self {
            inner_bytes,
            ciphertext_bytes: ciphertext,
            unpadded_plaintext_bytes: unpadded,
            padded_plaintext_bytes: unpadded,
            encrypted_header_bytes: 0,
            bootstrap_capsule_bytes: 0,
            outer_metadata_bytes: 0,
            identifier_bytes: 0,
            complete_frame_bytes: 0,
        })
    }

    /// Measure a candidate outer from its real fields and decoded ciphertext.
    ///
    /// # Errors
    /// Returns [`OuterProfileError::Malformed`] when the payload is not base64url
    /// or the envelope cannot be canonicalized, or [`OuterProfileError::PayloadTooLarge`]
    /// when framed Inner arithmetic overflows.
    pub fn measure_candidate(
        outer: &CandidateOuterEnvelope,
        encrypted_header: &[u8],
        bootstrap_capsule: &[u8],
    ) -> Result<Self, OuterProfileError> {
        let ciphertext = crate::decode_base64url(&outer.encrypted_payload)
            .map_err(|_| OuterProfileError::Malformed)?;
        Ok(Self {
            inner_bytes: 0,
            ciphertext_bytes: ciphertext.len(),
            unpadded_plaintext_bytes: 0,
            padded_plaintext_bytes: 0,
            encrypted_header_bytes: encrypted_header.len(),
            bootstrap_capsule_bytes: bootstrap_capsule.len(),
            identifier_bytes: identifier_len(&[
                outer.envelope_id.as_str(),
                outer.source_principal_id.as_str(),
                outer.source_device_id.as_str(),
                outer.target_delivery_id.as_str(),
            ]),
            outer_metadata_bytes: metadata_len(outer.node_report_receipt.as_ref())?,
            complete_frame_bytes: crate::canonical_json_bytes(outer)
                .map_err(|_| OuterProfileError::Malformed)?
                .len(),
        })
    }

    /// Measure a live envelope the node actually receives.
    ///
    /// `encrypted_payload` is `SdkDmEncryptedEnvelope` JSON. `CryptoBox` size is
    /// the nested `ciphertext.ciphertext` length (AEAD bytes), not the JSON
    /// wrapper. Complete-frame size uses the `CryptoBox` wire encoding
    /// (base64url of those bytes) in the envelope payload field.
    ///
    /// # Errors
    /// Returns [`OuterProfileError::Malformed`] when the payload is not base64url
    /// or the envelope cannot be canonicalized.
    pub fn measure_live(
        envelope: &crate::Envelope,
        encrypted_header: &[u8],
        bootstrap_capsule: &[u8],
    ) -> Result<Self, OuterProfileError> {
        let decoded = crate::decode_base64url(&envelope.encrypted_payload)
            .map_err(|_| OuterProfileError::Malformed)?;
        let nested = live_cryptobox(&decoded, encrypted_header, bootstrap_capsule)?;
        Ok(Self {
            inner_bytes: 0,
            ciphertext_bytes: nested.ciphertext.len(),
            unpadded_plaintext_bytes: 0,
            padded_plaintext_bytes: 0,
            encrypted_header_bytes: nested.header.len(),
            bootstrap_capsule_bytes: nested.bootstrap.len(),
            outer_metadata_bytes: if envelope.ext.ext.is_empty() {
                0
            } else {
                crate::canonical_json_bytes(&envelope.ext.ext)
                    .map_err(|_| OuterProfileError::Malformed)?
                    .len()
            },
            identifier_bytes: identifier_len(&[
                envelope.envelope_id.as_str(),
                envelope.source_principal_id.as_str(),
                envelope.source_device_id.as_str(),
                envelope.target_delivery_id.as_str(),
            ]),
            complete_frame_bytes: complete_frame_with_cryptobox(envelope, &nested.ciphertext)?,
        })
    }

    /// SDK send-side sizes from the real Inner, the real sealed `CryptoBox`, and
    /// the real encoded frame.
    ///
    /// # Errors
    /// Returns [`OuterProfileError::PayloadTooLarge`] when framed Inner overflows.
    pub fn measure_sealed_send(send: &SealedSendSizes<'_>) -> Result<Self, OuterProfileError> {
        let mut sizes = Self::from_inner(send.inner_bytes)?;
        sizes.ciphertext_bytes = send.ciphertext.len();
        sizes.encrypted_header_bytes = send.encrypted_header.len();
        sizes.bootstrap_capsule_bytes = send.bootstrap_capsule.len();
        sizes.identifier_bytes = identifier_len(&send.identifiers);
        sizes.outer_metadata_bytes = metadata_len(send.metadata)?;
        sizes.complete_frame_bytes = send.complete_frame_bytes;
        Ok(sizes)
    }
}

/// Real send-side buffers measured before pair-session persist.
pub struct SealedSendSizes<'a> {
    pub inner_bytes: usize,
    pub ciphertext: &'a [u8],
    pub encrypted_header: &'a [u8],
    pub bootstrap_capsule: &'a [u8],
    pub identifiers: [&'a str; 4],
    pub metadata: Option<&'a Value>,
    pub complete_frame_bytes: usize,
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
    if sizes.inner_bytes > 0 {
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
        {
            return Err(OuterProfileError::PayloadTooLarge);
        }
    }
    if sizes.ciphertext_bytes > MAX_CIPHERTEXT_BYTES
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

/// Preflight every cap, then replace the wrapped pair-session snapshot.
///
/// # Errors
/// [`OuterProfileError::PayloadTooLarge`] leaves the snapshot byte-identical.
pub fn accept_after_size_preflight(
    sizes: IngressSizes,
    ratchet: &mut TemporaryRatchet,
    advanced_snapshot: Vec<u8>,
) -> Result<(), OuterProfileError> {
    check_ingress_caps(sizes)?;
    ratchet.commit(advanced_snapshot);
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

/// Candidate profile token on a verified, identity-bound discovery record.
/// The token is read from `protocol_versions` only.
///
/// # Errors
/// [`ProtocolError::InvalidDomain`] when the v1 profile is absent.
pub fn discover_candidate_message_schema(
    record: &crate::VerifiedWellKnownClientRecord,
) -> Result<(), ProtocolError> {
    let versions = &record.record().protocol_versions;
    if versions.iter().any(|version| version == MESSAGE_SCHEMA_V1_PROFILE) {
        return Ok(());
    }
    Err(ProtocolError::InvalidDomain {
        expected: MESSAGE_SCHEMA_V1_PROFILE,
        actual: versions.first().cloned().unwrap_or_default(),
    })
}

/// Verify the record, then require the canonical profile token.
///
/// # Errors
/// Signature, freshness, identity, or missing-token refusals.
pub fn discover_verified_message_schema(
    record: &crate::WellKnownClientRecord,
    now: u64,
) -> Result<(), ProtocolError> {
    let verified = crate::VerifiedWellKnownClientRecord::verify(record, now)?;
    discover_candidate_message_schema(&verified)
}

/// Run candidate discovery only after activation. The record must already be verified.
///
/// # Errors
/// Propagates [`discover_candidate_message_schema`] when the v1 profile is live.
pub fn admit_discovered_profile(
    record: &crate::VerifiedWellKnownClientRecord,
) -> Result<(), ProtocolError> {
    if !schema_v1_live() {
        return Ok(());
    }
    discover_candidate_message_schema(record)
}

/// Protocol versions advertised on the well-known client record. The v1 token
/// is appended only after the schema gate is on.
#[must_use]
pub fn advertised_client_protocol_versions(base: &[String]) -> Vec<String> {
    let mut versions = base.to_vec();
    if schema_v1_live() && !versions.iter().any(|version| version == MESSAGE_SCHEMA_V1_PROFILE) {
        versions.push(MESSAGE_SCHEMA_V1_PROFILE.to_owned());
    }
    versions
}

fn decode_collapse_tag(tag: &str) -> Result<Vec<u8>, OuterProfileError> {
    crate::decode_base64url(tag).map_err(|_| OuterProfileError::CollapseTag)
}

fn identifier_len(ids: &[&str]) -> usize {
    let mut max = 0;
    for id in ids {
        max = max.max(id.len());
    }
    max
}

fn metadata_len(value: Option<&Value>) -> Result<usize, OuterProfileError> {
    let Some(value) = value else {
        return Ok(0);
    };
    if value.is_null() {
        return Ok(0);
    }
    Ok(crate::canonical_json_bytes(value).map_err(|_| OuterProfileError::Malformed)?.len())
}

#[derive(Deserialize)]
struct NestedSdkEnvelope {
    #[serde(default)]
    x3dh: Option<Value>,
    ciphertext: NestedCiphertext,
}

#[derive(Deserialize)]
struct NestedCiphertext {
    ciphertext: Vec<u8>,
    #[serde(default)]
    canonical_header_bytes: Vec<u8>,
}

struct LiveCryptobox {
    ciphertext: Vec<u8>,
    header: Vec<u8>,
    bootstrap: Vec<u8>,
}

fn live_cryptobox(
    decoded: &[u8],
    encrypted_header: &[u8],
    bootstrap_capsule: &[u8],
) -> Result<LiveCryptobox, OuterProfileError> {
    if let Ok(nested) = crate::parse_i_json::<NestedSdkEnvelope>(decoded) {
        let bootstrap = if bootstrap_capsule.is_empty() {
            match nested.x3dh {
                Some(header) => crate::canonical_json_bytes(&header)
                    .map_err(|_| OuterProfileError::Malformed)?,
                None => Vec::new(),
            }
        } else {
            bootstrap_capsule.to_vec()
        };
        let header = if encrypted_header.is_empty() {
            nested.ciphertext.canonical_header_bytes
        } else {
            encrypted_header.to_vec()
        };
        return Ok(LiveCryptobox { ciphertext: nested.ciphertext.ciphertext, header, bootstrap });
    }
    Ok(LiveCryptobox {
        ciphertext: decoded.to_vec(),
        header: encrypted_header.to_vec(),
        bootstrap: bootstrap_capsule.to_vec(),
    })
}

fn complete_frame_with_cryptobox(
    envelope: &crate::Envelope,
    cryptobox: &[u8],
) -> Result<usize, OuterProfileError> {
    let payload = crate::encode_base64url(cryptobox);
    if envelope.encrypted_payload == payload {
        return crate::canonical_json_bytes(envelope)
            .map(|bytes| bytes.len())
            .map_err(|_| OuterProfileError::Malformed);
    }
    let compact = crate::Envelope {
        schema: envelope.schema.clone(),
        version: envelope.version,
        domain: envelope.domain.clone(),
        ext: envelope.ext.clone(),
        signed: envelope.signed.clone(),
        envelope_id: envelope.envelope_id.clone(),
        source_principal_id: envelope.source_principal_id.clone(),
        source_device_id: envelope.source_device_id.clone(),
        target_delivery_id: envelope.target_delivery_id.clone(),
        routing_set_id: envelope.routing_set_id.clone(),
        delivery_class: envelope.delivery_class.clone(),
        priority: envelope.priority.clone(),
        ttl: envelope.ttl,
        created_at: envelope.created_at,
        encrypted_payload: payload,
        payload_hash: envelope.payload_hash.clone(),
    };
    crate::canonical_json_bytes(&compact)
        .map(|bytes| bytes.len())
        .map_err(|_| OuterProfileError::Malformed)
}

#[cfg(test)]
mod tests;
