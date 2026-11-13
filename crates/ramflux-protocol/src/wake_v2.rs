// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed `WakeV2` and `CallIntentV1` bodies.
//!
//! Sign every body field with strict Ed25519 over `ASCII(domain) || 0x00 || JCS(body)`.
//! Domains are [`crate::domain::NOTIFICATION_WAKE_V2`] and
//! [`crate::domain::NOTIFICATION_CALL_INTENT_V1`]. The call-intent digest is
//! BLAKE3 over `ramflux.notification.call_intent_digest.v1` , a NUL, and the JCS
//! of the signed start. Closed I-JSON: unknown fields, duplicates, `ext`, and
//! null optionals are rejected. `created_at` is the original source creation
//! time; callers must not restamp it on redelivery.

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::ProtocolError;

/// Notify service audience bound into every `WakeV2` body.
pub const NOTIFY_WAKE_AUDIENCE: &str = "ramflux-notify";
/// Audience bound into `CallIntentV1`. The receiving gateway is the verifier.
pub const GATEWAY_CALL_INTENT_AUDIENCE: &str = "ramflux-gateway";
/// Tolerated clock uncertainty. It is not extra lifetime.
pub const CLOCK_UNCERTAINTY_SECONDS: u64 = 5;
/// Maximum signed lifetime of a message wake, in seconds.
pub const MESSAGE_MAX_LIFETIME_SECONDS: u64 = 86_400;
/// Maximum signed lifetime of a call wake or call intent, in seconds.
pub const CALL_MAX_LIFETIME_SECONDS: u64 = 30;
/// Maximum UTF-8 length of an identifier on this contract.
pub const MAX_NOTIFICATION_ID_BYTES: usize = 512;

const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const WAKE_ID_BYTES: usize = 16;

/// Closed signature algorithm. The only wire value is `ed25519`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeSignatureAlg {
    /// Strict Ed25519.
    Ed25519,
}

/// What the notify service should do with an admitted wake.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeAction {
    /// Deliver a provider wake when a current route exists.
    Enqueue,
    /// Record cancellation and emit no provider push. Call wakes only.
    Cancel,
}

/// Provider class carried by a wake. The six internal delivery classes are not on this wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeClass {
    /// Ordinary notification. Requires a device collapse key at the provider boundary.
    Message,
    /// One-to-one call wake authorized by a [`CallIntentV1`] start.
    CallWake,
}

/// Call-intent action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallIntentAction {
    /// Begin a one-to-one call. `seq` is 0 and `start_digest` is absent.
    Start,
    /// Cancel that call. `seq` is 1 and `start_digest` binds the original start.
    Cancel,
}

/// The only call kind that may authorize `call_wake`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallIntentKind {
    /// A two-party call. Conferences are not this kind.
    OneToOne,
}

/// Signed wake body. Field absence is significant: optional digests are omitted, never null.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeV2 {
    /// Integer 2.
    pub version: u64,
    /// Identifier of the authorized gateway service key.
    pub signing_key_id: String,
    /// Always `ed25519`.
    pub signature_alg: WakeSignatureAlg,
    /// Notify service audience this wake is for.
    pub audience: String,
    /// Enqueue or cancel.
    pub action: WakeAction,
    /// Opaque 16-byte wake id, unpadded base64url.
    pub wake_id: String,
    /// Target delivery identifier. Not a provider token.
    pub target_delivery_id: String,
    /// Authenticated epoch of the target device owner.
    pub target_owner_epoch: u64,
    /// Source envelope id. It never reaches a provider payload.
    pub source_event_id: String,
    /// `message` or `call_wake`.
    pub class: WakeClass,
    /// Original source creation time, Unix seconds.
    pub created_at: u64,
    /// Absolute expiry, Unix seconds.
    pub expires_at: u64,
    /// Required for `call_wake`, forbidden for `message`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "reject_null_string"
    )]
    pub call_intent_digest: Option<String>,
}

/// `WakeV2` plus its Ed25519 signature over [`wake_signing_bytes`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWakeV2 {
    /// The signed body.
    pub body: WakeV2,
    /// Unpadded base64url of the 64-byte signature.
    pub signature: String,
}

/// Signed one-to-one call intent. Notify stores the digest, not this object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallIntentV1 {
    /// Integer 1.
    pub version: u64,
    /// Current caller device branch key id.
    pub signing_key_id: String,
    /// Always `ed25519`.
    pub signature_alg: WakeSignatureAlg,
    /// Gateway audience that will receive the intent.
    pub audience: String,
    /// Root-qualified caller device.
    pub sender_device: String,
    /// Caller device epoch.
    pub sender_epoch: u64,
    /// Root-qualified callee device.
    pub target_device: String,
    /// Callee device epoch.
    pub target_epoch: u64,
    /// Callee delivery id.
    pub target_delivery_id: String,
    /// Fresh per-target call reference, 16 bytes, unpadded base64url.
    pub call_ref: String,
    /// Source envelope id.
    pub source_event_id: String,
    /// Always `one_to_one`.
    pub kind: CallIntentKind,
    /// Start or cancel.
    pub action: CallIntentAction,
    /// 0 for start, 1 for cancel.
    pub seq: u64,
    /// Original call creation time, Unix seconds.
    pub created_at: u64,
    /// Start uses `created_at`. Cancel is `created_at..=now+5`.
    pub issued_at: u64,
    /// Absolute deadline shared by start and cancel.
    pub expires_at: u64,
    /// Absent on start. On cancel, the digest of the signed start.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "reject_null_string"
    )]
    pub start_digest: Option<String>,
}

/// `CallIntentV1` plus its Ed25519 signature over [`call_intent_signing_bytes`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCallIntentV1 {
    /// The signed body.
    pub body: CallIntentV1,
    /// Unpadded base64url of the 64-byte signature.
    pub signature: String,
}

fn contract(reason: &'static str) -> ProtocolError {
    ProtocolError::NotificationContract(reason)
}

fn reject_null_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RejectNull;
    impl<'de> Visitor<'de> for RejectNull {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an omitted field or a string")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Err(E::custom("null optional is rejected"))
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Err(E::custom("null optional is rejected"))
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            String::deserialize(deserializer).map(Some)
        }
    }
    deserializer.deserialize_option(RejectNull)
}

fn validate_id(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_NOTIFICATION_ID_BYTES
        || value.chars().any(char::is_control)
        || value != value.trim()
    {
        return Err(contract(field));
    }
    Ok(())
}

fn validate_device_id(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    validate_id(field, value)?;
    match crate::parse_qualified_device_id(value) {
        Ok(Some(_)) => Ok(()),
        Ok(None) | Err(_) => Err(contract(field)),
    }
}

fn validate_u(field: &'static str, value: u64) -> Result<(), ProtocolError> {
    if value > crate::MAX_SAFE_JSON_INTEGER {
        return Err(contract(field));
    }
    Ok(())
}

fn validate_fixed(field: &'static str, value: &str, nbytes: usize) -> Result<(), ProtocolError> {
    let decoded = crate::decode_base64url(value).map_err(|_source| contract(field))?;
    if decoded.len() != nbytes || crate::encode_base64url(&decoded) != value {
        return Err(contract(field));
    }
    Ok(())
}

fn validate_lifetime(created_at: u64, expires_at: u64, max_span: u64) -> Result<(), ProtocolError> {
    if created_at >= expires_at {
        return Err(contract("lifetime"));
    }
    if expires_at.saturating_sub(created_at) > max_span {
        return Err(contract("lifetime"));
    }
    Ok(())
}

fn frame(domain: &str, jcs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len().saturating_add(1).saturating_add(jcs.len()));
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(jcs);
    out
}

impl WakeV2 {
    /// Check the closed shape. This does not read the clock.
    ///
    /// # Errors
    /// Returns [`ProtocolError::NotificationContract`] when a field, version, lifetime,
    /// or digest rule fails.
    pub fn validate_shape(&self) -> Result<(), ProtocolError> {
        if self.version != 2 {
            return Err(contract("version"));
        }
        validate_id("signing_key_id", &self.signing_key_id)?;
        validate_id("audience", &self.audience)?;
        validate_fixed("wake_id", &self.wake_id, WAKE_ID_BYTES)?;
        validate_id("target_delivery_id", &self.target_delivery_id)?;
        validate_id("source_event_id", &self.source_event_id)?;
        validate_u("target_owner_epoch", self.target_owner_epoch)?;
        validate_u("created_at", self.created_at)?;
        validate_u("expires_at", self.expires_at)?;
        let max_span = match self.class {
            WakeClass::Message => MESSAGE_MAX_LIFETIME_SECONDS,
            WakeClass::CallWake => CALL_MAX_LIFETIME_SECONDS,
        };
        validate_lifetime(self.created_at, self.expires_at, max_span)?;
        self.validate_class_rules()
    }

    fn validate_class_rules(&self) -> Result<(), ProtocolError> {
        match (self.class, self.action, self.call_intent_digest.as_deref()) {
            (WakeClass::Message, WakeAction::Enqueue, None) => Ok(()),
            (WakeClass::Message, WakeAction::Cancel, _)
            | (WakeClass::Message, WakeAction::Enqueue, Some(_)) => {
                Err(contract("message_forbids_cancel_and_digest"))
            }
            (WakeClass::CallWake, WakeAction::Enqueue | WakeAction::Cancel, Some(digest)) => {
                validate_fixed("call_intent_digest", digest, DIGEST_BYTES)
            }
            (WakeClass::CallWake, _, None) => Err(contract("call_intent_digest")),
        }
    }

    /// Reject a wake created too far in the future or already expired.
    ///
    /// # Errors
    /// Returns [`ProtocolError::NotificationContract`] when `created_at > now + 5`
    /// or `now >= expires_at`.
    pub fn validate_times(&self, now: u64) -> Result<(), ProtocolError> {
        if self.created_at > now.saturating_add(CLOCK_UNCERTAINTY_SECONDS) {
            return Err(contract("created_at"));
        }
        if now >= self.expires_at {
            return Err(contract("expires_at"));
        }
        Ok(())
    }

    /// The signed deadline may not outlive the authenticated source envelope.
    ///
    /// # Errors
    /// Returns [`ProtocolError::NotificationContract`] when `expires_at` is later
    /// than the source expiry.
    pub fn bounded_by_source_expiry(&self, source_expires_at: u64) -> Result<(), ProtocolError> {
        if self.expires_at > source_expires_at {
            return Err(contract("expires_after_source"));
        }
        Ok(())
    }

    /// Same wake identity, deadline, and digest. The action may differ.
    #[must_use]
    pub fn shares_wake_identity(&self, other: &Self) -> bool {
        self.version == other.version
            && self.signing_key_id == other.signing_key_id
            && self.signature_alg == other.signature_alg
            && self.audience == other.audience
            && self.wake_id == other.wake_id
            && self.target_delivery_id == other.target_delivery_id
            && self.target_owner_epoch == other.target_owner_epoch
            && self.source_event_id == other.source_event_id
            && self.class == other.class
            && self.created_at == other.created_at
            && self.expires_at == other.expires_at
            && self.call_intent_digest == other.call_intent_digest
    }
}

impl CallIntentV1 {
    /// Check the closed shape. This does not read the clock or the prior start.
    ///
    /// # Errors
    /// Returns [`ProtocolError::NotificationContract`] when a field, device address,
    /// sequence, or lifetime rule fails.
    pub fn validate_shape(&self) -> Result<(), ProtocolError> {
        if self.version != 1 {
            return Err(contract("version"));
        }
        validate_id("signing_key_id", &self.signing_key_id)?;
        validate_id("audience", &self.audience)?;
        validate_device_id("sender_device", &self.sender_device)?;
        validate_device_id("target_device", &self.target_device)?;
        validate_id("target_delivery_id", &self.target_delivery_id)?;
        validate_id("source_event_id", &self.source_event_id)?;
        validate_fixed("call_ref", &self.call_ref, WAKE_ID_BYTES)?;
        validate_u("sender_epoch", self.sender_epoch)?;
        validate_u("target_epoch", self.target_epoch)?;
        validate_u("seq", self.seq)?;
        validate_u("created_at", self.created_at)?;
        validate_u("issued_at", self.issued_at)?;
        validate_u("expires_at", self.expires_at)?;
        validate_lifetime(self.created_at, self.expires_at, CALL_MAX_LIFETIME_SECONDS)?;
        self.validate_action_rules()
    }

    fn validate_action_rules(&self) -> Result<(), ProtocolError> {
        match (self.action, self.seq, self.start_digest.as_deref()) {
            (CallIntentAction::Start, 0, None) if self.issued_at == self.created_at => Ok(()),
            (CallIntentAction::Cancel, 1, Some(digest)) if self.created_at <= self.issued_at => {
                validate_fixed("start_digest", digest, DIGEST_BYTES)
            }
            _ => Err(contract("call_intent_action")),
        }
    }

    /// Reject an intent issued too far in the future or already expired.
    ///
    /// # Errors
    /// Returns [`ProtocolError::NotificationContract`] when `issued_at > now + 5`
    /// or `now >= expires_at`.
    pub fn validate_times(&self, now: u64) -> Result<(), ProtocolError> {
        if self.issued_at > now.saturating_add(CLOCK_UNCERTAINTY_SECONDS) {
            return Err(contract("issued_at"));
        }
        if now >= self.expires_at {
            return Err(contract("expires_at"));
        }
        Ok(())
    }

    /// Cancel binds the same call and deadline as `start`, and carries `start_digest`.
    #[must_use]
    pub fn matches_start(&self, start: &Self, start_digest: &str) -> bool {
        self.action == CallIntentAction::Cancel
            && start.action == CallIntentAction::Start
            && self.start_digest.as_deref() == Some(start_digest)
            && self.signing_key_id == start.signing_key_id
            && self.audience == start.audience
            && self.sender_device == start.sender_device
            && self.sender_epoch == start.sender_epoch
            && self.target_device == start.target_device
            && self.target_epoch == start.target_epoch
            && self.target_delivery_id == start.target_delivery_id
            && self.call_ref == start.call_ref
            && self.source_event_id == start.source_event_id
            && self.kind == start.kind
            && self.created_at == start.created_at
            && self.expires_at == start.expires_at
    }
}

/// Parse a signed wake from original JSON bytes and check its shape.
///
/// # Errors
/// Returns [`ProtocolError::IJson`] for malformed, duplicate, unknown, or null input,
/// and [`ProtocolError::NotificationContract`] when the shape is not `WakeV2`.
pub fn parse_signed_wake_v2(bytes: &[u8]) -> Result<SignedWakeV2, ProtocolError> {
    let signed: SignedWakeV2 = crate::parse_i_json(bytes)?;
    signed.body.validate_shape()?;
    validate_fixed("signature", &signed.signature, SIGNATURE_BYTES)?;
    Ok(signed)
}

/// Parse a signed call intent from original JSON bytes and check its shape.
///
/// # Errors
/// Returns [`ProtocolError::IJson`] for malformed input and
/// [`ProtocolError::NotificationContract`] when the shape is not `CallIntentV1`.
pub fn parse_signed_call_intent_v1(bytes: &[u8]) -> Result<SignedCallIntentV1, ProtocolError> {
    let signed: SignedCallIntentV1 = crate::parse_i_json(bytes)?;
    signed.body.validate_shape()?;
    validate_fixed("signature", &signed.signature, SIGNATURE_BYTES)?;
    Ok(signed)
}

/// Bytes a gateway service key signs for `body`. The signature is not an input.
///
/// # Errors
/// Returns an error when the body shape or canonical JSON encoding fails.
pub fn wake_signing_bytes(body: &WakeV2) -> Result<Vec<u8>, ProtocolError> {
    body.validate_shape()?;
    let jcs = crate::canonical_json_bytes(body)?;
    Ok(frame(crate::domain::NOTIFICATION_WAKE_V2, &jcs))
}

/// Bytes the caller device branch key signs for `body`.
///
/// # Errors
/// Returns an error when the body shape or canonical JSON encoding fails.
pub fn call_intent_signing_bytes(body: &CallIntentV1) -> Result<Vec<u8>, ProtocolError> {
    body.validate_shape()?;
    let jcs = crate::canonical_json_bytes(body)?;
    Ok(frame(crate::domain::NOTIFICATION_CALL_INTENT_V1, &jcs))
}

/// Digest of a signed start. The input is the digest domain, a NUL, then JCS of `signed`.
///
/// # Errors
/// Returns an error when `signed` is not a shape-valid start.
pub fn call_intent_digest(signed: &SignedCallIntentV1) -> Result<String, ProtocolError> {
    signed.body.validate_shape()?;
    if signed.body.action != CallIntentAction::Start {
        return Err(contract("digest_requires_start"));
    }
    validate_fixed("signature", &signed.signature, SIGNATURE_BYTES)?;
    let jcs = crate::canonical_json_bytes(signed)?;
    let framed = frame(crate::domain::NOTIFICATION_CALL_INTENT_DIGEST_V1, &jcs);
    Ok(crate::encode_base64url(blake3::hash(&framed).as_bytes()))
}

/// Immutable digest of the canonical signed wake, used as the dedup request digest.
///
/// This is storage identity. It is not a signature domain and it is not sent to providers.
///
/// # Errors
/// Returns an error when the wake shape, signature encoding, or canonical JSON fails.
pub fn wake_request_digest(signed: &SignedWakeV2) -> Result<String, ProtocolError> {
    signed.body.validate_shape()?;
    validate_fixed("signature", &signed.signature, SIGNATURE_BYTES)?;
    let jcs = crate::canonical_json_bytes(signed)?;
    Ok(crate::encode_base64url(blake3::hash(&jcs).as_bytes()))
}

/// `min(signed expiry, admission_now + class cap)`. Callers persist the first result.
#[must_use]
pub const fn effective_expiry(signed_expires_at: u64, admission_now: u64, class: WakeClass) -> u64 {
    let cap = match class {
        WakeClass::Message => MESSAGE_MAX_LIFETIME_SECONDS,
        WakeClass::CallWake => CALL_MAX_LIFETIME_SECONDS,
    };
    let capped = admission_now.saturating_add(cap);
    if signed_expires_at < capped { signed_expires_at } else { capped }
}

/// Whole seconds remaining until `expires_at`. Zero means the server must not send.
#[must_use]
pub const fn remaining_whole_seconds(expires_at: u64, now: u64) -> u64 {
    expires_at.saturating_sub(now)
}

#[cfg(test)]
mod tests {
    use super::{
        CallIntentAction, CallIntentKind, CallIntentV1, SignedCallIntentV1, SignedWakeV2,
        WakeAction, WakeClass, WakeSignatureAlg, WakeV2, call_intent_digest,
        call_intent_signing_bytes, effective_expiry, parse_signed_call_intent_v1,
        parse_signed_wake_v2, wake_request_digest, wake_signing_bytes,
    };
    use crate::ProtocolError;

    fn signature() -> String {
        crate::encode_base64url([3_u8; 64])
    }

    fn message_body() -> WakeV2 {
        WakeV2 {
            version: 2,
            signing_key_id: "node-service-ed25519-v1".to_owned(),
            signature_alg: WakeSignatureAlg::Ed25519,
            audience: "ramflux-notify".to_owned(),
            action: WakeAction::Enqueue,
            wake_id: crate::encode_base64url([9_u8; 16]),
            target_delivery_id: "delivery-1".to_owned(),
            target_owner_epoch: 4,
            source_event_id: "envelope-1".to_owned(),
            class: WakeClass::Message,
            created_at: 1_000,
            expires_at: 1_000 + 86_400,
            call_intent_digest: None,
        }
    }

    fn wrap_wake(body: WakeV2) -> Result<Vec<u8>, ProtocolError> {
        let signed = SignedWakeV2 { body, signature: signature() };
        Ok(serde_json::to_vec(&signed)?)
    }

    fn intent_start() -> Result<CallIntentV1, ProtocolError> {
        let sender = crate::qualified_device_id("root-a", "phone")?;
        let target = crate::qualified_device_id("root-b", "handset")?;
        Ok(CallIntentV1 {
            version: 1,
            signing_key_id: crate::encode_base64url([5_u8; 32]),
            signature_alg: WakeSignatureAlg::Ed25519,
            audience: "ramflux-gateway".to_owned(),
            sender_device: sender,
            sender_epoch: 2,
            target_device: target,
            target_epoch: 3,
            target_delivery_id: "delivery-1".to_owned(),
            call_ref: crate::encode_base64url([8_u8; 16]),
            source_event_id: "envelope-1".to_owned(),
            kind: CallIntentKind::OneToOne,
            action: CallIntentAction::Start,
            seq: 0,
            created_at: 1_000,
            issued_at: 1_000,
            expires_at: 1_030,
            start_digest: None,
        })
    }

    fn wrap_intent(body: CallIntentV1) -> Result<Vec<u8>, ProtocolError> {
        let signed = SignedCallIntentV1 { body, signature: signature() };
        Ok(serde_json::to_vec(&signed)?)
    }

    #[test]
    fn wake_v2_round_trips_and_signs_the_body_only() -> Result<(), ProtocolError> {
        let bytes = wrap_wake(message_body())?;
        let signed = parse_signed_wake_v2(&bytes)?;
        let transcript = wake_signing_bytes(&signed.body)?;
        let domain = crate::domain::NOTIFICATION_WAKE_V2.as_bytes();
        assert!(transcript.starts_with(domain));
        assert_eq!(transcript.get(domain.len()), Some(&0));
        let mut other = signed.clone();
        other.signature = crate::encode_base64url([4_u8; 64]);
        assert_eq!(wake_signing_bytes(&signed.body)?, wake_signing_bytes(&other.body)?);
        assert_ne!(wake_request_digest(&signed)?, wake_request_digest(&other)?);
        let jcs = crate::canonical_json_string(&signed.body)?;
        assert!(!jcs.contains("call_intent_digest"));
        assert!(!jcs.contains("ext"));
        Ok(())
    }

    #[test]
    fn wake_v2_rejects_v1_unsigned_null_duplicate_and_bad_shape() -> Result<(), ProtocolError> {
        let legacy = br#"{"schema":"notification_wake","version":1,"domain":"ramflux.notification_wake.v1","wake_id":"wake_env","ttl":30,"priority":"high"}"#;
        assert!(matches!(parse_signed_wake_v2(legacy), Err(ProtocolError::IJson(_))));
        let unsigned = serde_json::to_vec(&message_body())?;
        assert!(matches!(parse_signed_wake_v2(&unsigned), Err(ProtocolError::IJson(_))));
        let mut value =
            serde_json::to_value(SignedWakeV2 { body: message_body(), signature: signature() })?;
        value["body"]["call_intent_digest"] = serde_json::Value::Null;
        assert!(matches!(
            parse_signed_wake_v2(&serde_json::to_vec(&value)?),
            Err(ProtocolError::IJson(_))
        ));
        value["body"]["ext"] = serde_json::json!({});
        let body = value["body"].as_object_mut().ok_or_else(contract_probe)?;
        body.remove("call_intent_digest");
        assert!(matches!(
            parse_signed_wake_v2(&serde_json::to_vec(&value)?),
            Err(ProtocolError::IJson(_))
        ));
        let duplicated = br#"{"body":{"version":2,"version":2},"signature":"aa"}"#;
        assert!(matches!(parse_signed_wake_v2(duplicated), Err(ProtocolError::IJson(_))));
        let mut wrong_version = message_body();
        wrong_version.version = 1;
        assert!(matches!(
            parse_signed_wake_v2(&wrap_wake(wrong_version)?),
            Err(ProtocolError::NotificationContract("version"))
        ));
        let mut bad_sig = SignedWakeV2 { body: message_body(), signature: signature() };
        bad_sig.signature.push('=');
        assert!(matches!(
            parse_signed_wake_v2(&serde_json::to_vec(&bad_sig)?),
            Err(ProtocolError::NotificationContract("signature"))
        ));
        Ok(())
    }

    fn contract_probe() -> ProtocolError {
        ProtocolError::NotificationContract("probe")
    }

    #[test]
    fn wake_rules_reject_message_digest_call_without_digest_and_bad_times()
    -> Result<(), ProtocolError> {
        let mut digested = message_body();
        digested.call_intent_digest = Some(crate::encode_base64url([1_u8; 32]));
        assert!(parse_signed_wake_v2(&wrap_wake(digested)?).is_err());
        let mut cancel = message_body();
        cancel.action = WakeAction::Cancel;
        assert!(matches!(
            parse_signed_wake_v2(&wrap_wake(cancel)?),
            Err(ProtocolError::NotificationContract("message_forbids_cancel_and_digest"))
        ));
        let mut call = message_body();
        call.class = WakeClass::CallWake;
        call.expires_at = 1_030;
        assert!(matches!(
            parse_signed_wake_v2(&wrap_wake(call)?),
            Err(ProtocolError::NotificationContract("call_intent_digest"))
        ));
        let mut zero = message_body();
        zero.expires_at = zero.created_at;
        assert!(matches!(
            parse_signed_wake_v2(&wrap_wake(zero)?),
            Err(ProtocolError::NotificationContract("lifetime"))
        ));
        let mut long_call = message_body();
        long_call.class = WakeClass::CallWake;
        long_call.expires_at = 1_031;
        long_call.call_intent_digest = Some(crate::encode_base64url([1_u8; 32]));
        assert!(matches!(
            parse_signed_wake_v2(&wrap_wake(long_call)?),
            Err(ProtocolError::NotificationContract("lifetime"))
        ));
        let body = message_body();
        assert!(body.validate_times(body.created_at.saturating_sub(6)).is_err());
        assert!(body.validate_times(body.created_at.saturating_sub(5)).is_ok());
        assert!(body.validate_times(body.expires_at).is_err());
        assert!(body.validate_times(body.created_at).is_ok());
        assert!(body.bounded_by_source_expiry(body.expires_at - 1).is_err());
        let mut spaced = message_body();
        spaced.audience = " notify".to_owned();
        assert!(matches!(
            parse_signed_wake_v2(&wrap_wake(spaced)?),
            Err(ProtocolError::NotificationContract("audience"))
        ));
        let mut huge = message_body();
        huge.target_delivery_id = "a".repeat(513);
        assert!(parse_signed_wake_v2(&wrap_wake(huge)?).is_err());
        Ok(())
    }

    #[test]
    fn call_intent_digest_covers_the_signed_start_and_cancel_binds_it() -> Result<(), ProtocolError>
    {
        let start = intent_start()?;
        let bytes = wrap_intent(start)?;
        let signed = parse_signed_call_intent_v1(&bytes)?;
        let digest = call_intent_digest(&signed)?;
        let jcs = crate::canonical_json_bytes(&signed)?;
        let mut framed = crate::domain::NOTIFICATION_CALL_INTENT_DIGEST_V1.as_bytes().to_vec();
        framed.push(0);
        framed.extend_from_slice(&jcs);
        assert_eq!(digest, crate::encode_base64url(blake3::hash(&framed).as_bytes()));
        let transcript = call_intent_signing_bytes(&signed.body)?;
        let domain = crate::domain::NOTIFICATION_CALL_INTENT_V1.as_bytes();
        assert!(transcript.starts_with(domain));
        assert_eq!(transcript.get(domain.len()), Some(&0));
        let mut cancel = signed.body.clone();
        cancel.action = CallIntentAction::Cancel;
        cancel.seq = 1;
        cancel.issued_at = 1_004;
        cancel.start_digest = Some(digest.clone());
        let cancel_bytes = wrap_intent(cancel.clone())?;
        let parsed = parse_signed_call_intent_v1(&cancel_bytes)?;
        assert!(parsed.body.matches_start(&signed.body, &digest));
        assert!(call_intent_digest(&parsed).is_err());
        cancel.call_ref = crate::encode_base64url([7_u8; 16]);
        assert!(!cancel.matches_start(&signed.body, &digest));
        let mut bare = intent_start()?;
        bare.sender_device = "phone".to_owned();
        assert!(matches!(
            bare.validate_shape(),
            Err(ProtocolError::NotificationContract("sender_device"))
        ));
        let mut conference = serde_json::to_value(SignedCallIntentV1 {
            body: intent_start()?,
            signature: signature(),
        })?;
        conference["body"]["kind"] = serde_json::json!("conference");
        assert!(parse_signed_call_intent_v1(&serde_json::to_vec(&conference)?).is_err());
        assert_eq!(effective_expiry(1_000, 900, WakeClass::CallWake), 930);
        assert_eq!(effective_expiry(1_000, 900, WakeClass::Message), 1_000);
        Ok(())
    }
}
