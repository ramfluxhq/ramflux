// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed delivery-mode and lifetime rules for ephemeral envelopes.

use crate::{Envelope, Priority};
use serde_json::Value;

/// Name of the signed extension that selects an envelope's delivery mode.
pub const DELIVERY_MODE_EXTENSION: &str = "delivery_mode";
/// Smallest permitted ephemeral TTL, in seconds.
pub const MIN_EPHEMERAL_TTL_SECONDS: u32 = 1;
/// Largest permitted ephemeral TTL, in seconds.
pub const MAX_EPHEMERAL_TTL_SECONDS: u32 = 5;
/// Permitted sender-clock lead over the node clock, in milliseconds.
pub const EPHEMERAL_FUTURE_TOLERANCE_MS: u64 = 2_000;
/// Capability identifier for gateway ephemeral delivery; defined here but not advertised by P01.
pub const GATEWAY_EPHEMERAL_CAPABILITY: &str = "gateway.ephemeral.v1";

/// D1's interpretation of the signed delivery-mode extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryMode {
    Durable,
    Ephemeral,
    Invalid,
}

/// Refusals produced while classifying a mode or validating its ephemeral lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EphemeralModeError {
    #[error("ephemeral delivery is not allowed at a durable sink")]
    EphemeralAtDurableSink,
    #[error("delivery mode is invalid")]
    InvalidDeliveryMode,
    #[error("ephemeral lifetime requested for a durable envelope")]
    NotEphemeral,
    #[error("ephemeral delivery requires low priority")]
    InvalidPriority,
    #[error("ephemeral TTL must be between 1 and 5 seconds")]
    InvalidTtl,
    #[error("created_at plus TTL overflows")]
    CreatedAtTtlOverflow,
    #[error("ephemeral deadline is negative")]
    NegativeDeadline,
    #[error("ephemeral deadline in milliseconds overflows")]
    DeadlineMillisecondsOverflow,
    #[error("node clock plus future tolerance overflows")]
    ClockToleranceOverflow,
    #[error("ephemeral created_at is too far in the future")]
    CreatedAtTooFarInFuture,
    #[error("ephemeral envelope has expired")]
    Expired,
}

/// Classify `ext.delivery_mode`: absent and `durable` are durable, while an
/// unrecognized value is invalid rather than silently falling back to durable.
#[must_use]
pub fn classify_delivery_mode(envelope: &Envelope) -> DeliveryMode {
    match envelope.ext.ext.get(DELIVERY_MODE_EXTENSION) {
        None => DeliveryMode::Durable,
        Some(Value::String(mode)) if mode == "durable" => DeliveryMode::Durable,
        Some(Value::String(mode)) if mode == "ephemeral" => DeliveryMode::Ephemeral,
        Some(_) => DeliveryMode::Invalid,
    }
}

/// Refuse an ephemeral or invalid delivery mode before a durable side effect.
///
/// # Errors
/// Returns [`EphemeralModeError::EphemeralAtDurableSink`] for ephemeral mode or
/// [`EphemeralModeError::InvalidDeliveryMode`] for any unrecognized value.
pub fn require_durable(envelope: &Envelope) -> Result<(), EphemeralModeError> {
    match classify_delivery_mode(envelope) {
        DeliveryMode::Durable => Ok(()),
        DeliveryMode::Ephemeral => Err(EphemeralModeError::EphemeralAtDurableSink),
        DeliveryMode::Invalid => Err(EphemeralModeError::InvalidDeliveryMode),
    }
}

/// Validate an ephemeral envelope and return its checked exclusive deadline in milliseconds.
///
/// `now_ms` is the node's Unix clock in milliseconds. The sender clock may lead
/// it by at most [`EPHEMERAL_FUTURE_TOLERANCE_MS`], inclusive; expiry is exclusive.
///
/// # Errors
/// Returns a typed refusal if the mode, priority, TTL, signed arithmetic, clock
/// skew, or lifetime is invalid.
pub fn deadline(envelope: &Envelope, now_ms: u64) -> Result<u64, EphemeralModeError> {
    match classify_delivery_mode(envelope) {
        DeliveryMode::Ephemeral => {}
        DeliveryMode::Durable => return Err(EphemeralModeError::NotEphemeral),
        DeliveryMode::Invalid => return Err(EphemeralModeError::InvalidDeliveryMode),
    }

    if envelope.priority != Priority::Low {
        return Err(EphemeralModeError::InvalidPriority);
    }
    if !(MIN_EPHEMERAL_TTL_SECONDS..=MAX_EPHEMERAL_TTL_SECONDS).contains(&envelope.ttl) {
        return Err(EphemeralModeError::InvalidTtl);
    }

    let expires_at = envelope
        .created_at
        .checked_add(i64::from(envelope.ttl))
        .ok_or(EphemeralModeError::CreatedAtTtlOverflow)?;
    if expires_at < 0 {
        return Err(EphemeralModeError::NegativeDeadline);
    }
    let expires_at_ms = u64::try_from(expires_at)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or(EphemeralModeError::DeadlineMillisecondsOverflow)?;

    let latest_created_at_ms = now_ms
        .checked_add(EPHEMERAL_FUTURE_TOLERANCE_MS)
        .ok_or(EphemeralModeError::ClockToleranceOverflow)?;
    let created_at_ms = i128::from(envelope.created_at) * 1_000;
    if created_at_ms > i128::from(latest_created_at_ms) {
        return Err(EphemeralModeError::CreatedAtTooFarInFuture);
    }
    if now_ms >= expires_at_ms {
        return Err(EphemeralModeError::Expired);
    }

    Ok(expires_at_ms)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        DELIVERY_MODE_EXTENSION, DeliveryMode, EPHEMERAL_FUTURE_TOLERANCE_MS, EphemeralModeError,
        GATEWAY_EPHEMERAL_CAPABILITY, MAX_EPHEMERAL_TTL_SECONDS, MIN_EPHEMERAL_TTL_SECONDS,
        classify_delivery_mode, deadline, require_durable,
    };
    use crate::canonical_json_bytes;
    use crate::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
    use serde_json::Value;

    /// Reference "now" for every otherwise-valid vector.
    const NOW_MS: u64 = 1_000_000;

    fn valid_envelope() -> Envelope {
        let mut extensions = BTreeMap::new();
        extensions
            .insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("ephemeral".to_owned()));
        Envelope {
            schema: "ramflux.envelope.v1".to_owned(),
            version: 1,
            domain: "ramflux.message".to_owned(),
            ext: Ext { ext: extensions },
            signed: SignedFields {
                signing_key_id: "key".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "signature".to_owned(),
            },
            envelope_id: "envelope".to_owned(),
            source_principal_id: "principal".to_owned(),
            source_device_id: "device".to_owned(),
            target_delivery_id: "target".to_owned(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Low,
            ttl: 5,
            created_at: 1_000,
            encrypted_payload: "payload".to_owned(),
            payload_hash: "hash".to_owned(),
        }
    }

    /// One otherwise-valid envelope with exactly one field replaced.
    fn mutated(change: impl FnOnce(&mut Envelope)) -> Envelope {
        let mut envelope = valid_envelope();
        change(&mut envelope);
        envelope
    }

    fn with_mode(value: Value) -> Envelope {
        mutated(|e| {
            e.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), value);
        })
    }

    /// Canonical wire bytes of a signed envelope (the crate's canonical JSON encoder).
    fn wire(envelope: &Envelope) -> Result<Vec<u8>, crate::ProtocolError> {
        canonical_json_bytes(envelope)
    }

    /// How a row reaches the decoder: canonical wire bytes, or raw bytes for values that the
    /// canonical (I-JSON) encoder cannot carry exactly, such as integers above 2^53.
    enum Input {
        Canonical(Box<Envelope>),
        NonCanonical(Vec<u8>),
    }

    /// One matrix row: the input bytes source, the `now` used for `deadline`, and the exact expected results.
    struct Case {
        id: &'static str,
        input: Input,
        now_ms: u64,
        mode: DeliveryMode,
        require: Result<(), EphemeralModeError>,
        deadline: Result<u64, EphemeralModeError>,
    }

    fn case(
        id: &'static str,
        envelope: &Envelope,
        now_ms: u64,
        mode: DeliveryMode,
        require: Result<(), EphemeralModeError>,
        deadline: Result<u64, EphemeralModeError>,
    ) -> Case {
        Case {
            id,
            input: Input::Canonical(Box::new(envelope.clone())),
            now_ms,
            mode,
            require,
            deadline,
        }
    }

    /// Like [`case`], but the bytes are the plain `serde_json` encoding of the envelope.
    fn raw_case(
        id: &'static str,
        envelope: &Envelope,
        now_ms: u64,
        mode: DeliveryMode,
        require: Result<(), EphemeralModeError>,
        deadline: Result<u64, EphemeralModeError>,
    ) -> Result<Case, Box<dyn std::error::Error>> {
        Ok(Case {
            id,
            input: Input::NonCanonical(serde_json::to_vec(envelope)?),
            now_ms,
            mode,
            require,
            deadline,
        })
    }

    /// Production decode of received bytes; the decoded value must re-encode byte-identically.
    fn receive(bytes: &[u8]) -> Result<Envelope, Box<dyn std::error::Error>> {
        let envelope: Envelope = serde_json::from_slice(bytes)?;
        assert_eq!(wire(&envelope)?, bytes, "decode then canonical encode must be byte-identical");
        Ok(envelope)
    }

    /// Encode the row to canonical wire bytes, decode those bytes, then classify the decoded value.
    fn run(case: &Case) -> Result<(), Box<dyn std::error::Error>> {
        let envelope = match &case.input {
            Input::Canonical(envelope) => receive(&wire(envelope)?)?,
            Input::NonCanonical(bytes) => {
                let envelope: Envelope = serde_json::from_slice(bytes)?;
                assert_ne!(
                    wire(&envelope)?,
                    *bytes,
                    "{}: non-I-JSON integer must not re-encode identically",
                    case.id
                );
                envelope
            }
        };
        assert_eq!(classify_delivery_mode(&envelope), case.mode, "{}: mode", case.id);
        assert_eq!(require_durable(&envelope), case.require, "{}: require_durable", case.id);
        assert_eq!(deadline(&envelope, case.now_ms), case.deadline, "{}: deadline", case.id);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ephemeral_mode_and_lifetime_matrix() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(GATEWAY_EPHEMERAL_CAPABILITY, "gateway.ephemeral.v1");
        assert_eq!(MIN_EPHEMERAL_TTL_SECONDS, 1);
        assert_eq!(MAX_EPHEMERAL_TTL_SECONDS, 5);
        assert_eq!(EPHEMERAL_FUTURE_TOLERANCE_MS, 2_000);

        let ephemeral_ok = Ok(1_005_000);
        let not_ephemeral = Err(EphemeralModeError::NotEphemeral);
        let invalid_mode: Result<(), EphemeralModeError> =
            Err(EphemeralModeError::InvalidDeliveryMode);
        let invalid_deadline: Result<u64, EphemeralModeError> =
            Err(EphemeralModeError::InvalidDeliveryMode);
        let at_durable_sink = Err(EphemeralModeError::EphemeralAtDurableSink);

        // Controls (positive): each is an otherwise-valid vector that must be accepted.
        let controls = [
            case(
                "control: ephemeral, low, ttl 5, now = created_at",
                &valid_envelope(),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                ephemeral_ok,
            ),
            case(
                "control: delivery_mode absent is durable",
                &mutated(|e| {
                    e.ext.ext.remove(DELIVERY_MODE_EXTENSION);
                }),
                NOW_MS,
                DeliveryMode::Durable,
                Ok(()),
                not_ephemeral,
            ),
            case(
                "control: delivery_mode durable is durable",
                &with_mode(Value::String("durable".to_owned())),
                NOW_MS,
                DeliveryMode::Durable,
                Ok(()),
                not_ephemeral,
            ),
            case(
                "control: ttl 1 is the inclusive lower bound",
                &mutated(|e| e.ttl = MIN_EPHEMERAL_TTL_SECONDS),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Ok(1_001_000),
            ),
            case(
                "control: ttl 5 is the inclusive upper bound",
                &mutated(|e| e.ttl = MAX_EPHEMERAL_TTL_SECONDS),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                ephemeral_ok,
            ),
            case(
                "control: sender clock +2000 ms is inclusive",
                &mutated(|e| {
                    e.created_at = 1_002;
                    e.ttl = 1;
                }),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Ok(1_003_000),
            ),
            case(
                "control: now = deadline - 1 ms is live",
                &mutated(|e| {
                    e.created_at = 1_000;
                    e.ttl = 1;
                }),
                1_000_999,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Ok(1_001_000),
            ),
            case(
                "control: now = 2^64-1 - 2000 leaves the tolerance sum representable",
                &valid_envelope(),
                u64::MAX - 2_000,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::Expired),
            ),
        ];

        // Refusals: one row per predicate/arm/alternative; each is one isolated mutation of
        // the valid vector (or of its delivery_mode), except the classifier rows, which are
        // refused at mode classification and therefore refuse at both refusal APIs.
        let refusals = [
            case(
                "mode: \"Ephemeral\" casing (catch-all)",
                &with_mode(Value::String("Ephemeral".to_owned())),
                NOW_MS,
                DeliveryMode::Invalid,
                invalid_mode,
                invalid_deadline,
            ),
            case(
                "mode: empty string (catch-all)",
                &with_mode(Value::String(String::new())),
                NOW_MS,
                DeliveryMode::Invalid,
                invalid_mode,
                invalid_deadline,
            ),
            case(
                "mode: \"Durable\" casing (catch-all)",
                &with_mode(Value::String("Durable".to_owned())),
                NOW_MS,
                DeliveryMode::Invalid,
                invalid_mode,
                invalid_deadline,
            ),
            case(
                "mode: trailing space \"ephemeral \" (catch-all)",
                &with_mode(Value::String("ephemeral ".to_owned())),
                NOW_MS,
                DeliveryMode::Invalid,
                invalid_mode,
                invalid_deadline,
            ),
            case(
                "mode: number 1 (catch-all)",
                &with_mode(Value::Number(1.into())),
                NOW_MS,
                DeliveryMode::Invalid,
                invalid_mode,
                invalid_deadline,
            ),
            case(
                "mode: null (catch-all)",
                &with_mode(Value::Null),
                NOW_MS,
                DeliveryMode::Invalid,
                invalid_mode,
                invalid_deadline,
            ),
            case(
                "mode: object {} (catch-all)",
                &with_mode(serde_json::json!({})),
                NOW_MS,
                DeliveryMode::Invalid,
                invalid_mode,
                invalid_deadline,
            ),
            case(
                "mode: array [] (catch-all)",
                &with_mode(Value::Array(Vec::new())),
                NOW_MS,
                DeliveryMode::Invalid,
                invalid_mode,
                invalid_deadline,
            ),
            case(
                "mode: boolean true (catch-all)",
                &with_mode(Value::Bool(true)),
                NOW_MS,
                DeliveryMode::Invalid,
                invalid_mode,
                invalid_deadline,
            ),
            case(
                "deadline Durable arm: absent mode",
                &mutated(|e| {
                    e.ext.ext.remove(DELIVERY_MODE_EXTENSION);
                }),
                NOW_MS,
                DeliveryMode::Durable,
                Ok(()),
                not_ephemeral,
            ),
            case(
                "deadline Durable arm: explicit durable",
                &with_mode(Value::String("durable".to_owned())),
                NOW_MS,
                DeliveryMode::Durable,
                Ok(()),
                not_ephemeral,
            ),
            case(
                "require_durable Ephemeral arm: valid ephemeral",
                &valid_envelope(),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                ephemeral_ok,
            ),
            case(
                "priority normal",
                &mutated(|e| e.priority = Priority::Normal),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::InvalidPriority),
            ),
            case(
                "priority high",
                &mutated(|e| e.priority = Priority::High),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::InvalidPriority),
            ),
            case(
                "priority urgent",
                &mutated(|e| e.priority = Priority::Urgent),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::InvalidPriority),
            ),
            case(
                "ttl 0 (below inclusive lower bound)",
                &mutated(|e| e.ttl = 0),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::InvalidTtl),
            ),
            case(
                "ttl 6 (above inclusive upper bound)",
                &mutated(|e| e.ttl = 6),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::InvalidTtl),
            ),
            case(
                "ttl u32::MAX",
                &mutated(|e| e.ttl = u32::MAX),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::InvalidTtl),
            ),
            raw_case(
                "created_at + ttl overflows i64",
                &mutated(|e| {
                    e.created_at = i64::MAX;
                    e.ttl = 5;
                }),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::CreatedAtTtlOverflow),
            )?,
            case(
                "deadline is negative",
                &mutated(|e| {
                    e.created_at = -2;
                    e.ttl = 1;
                }),
                NOW_MS,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::NegativeDeadline),
            ),
            raw_case(
                "deadline in milliseconds overflows u64",
                &mutated(|e| {
                    e.created_at = i64::MAX / 2;
                    e.ttl = 1;
                }),
                0,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::DeadlineMillisecondsOverflow),
            )?,
            case(
                "now + 2000 ms tolerance overflows u64",
                &valid_envelope(),
                u64::MAX - 1_999,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::ClockToleranceOverflow),
            ),
            case(
                "sender clock +2001 ms is refused",
                &mutated(|e| {
                    e.created_at = 1_002;
                    e.ttl = 1;
                }),
                999_999,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::CreatedAtTooFarInFuture),
            ),
            case(
                "now = deadline is expired (exclusive)",
                &mutated(|e| {
                    e.created_at = 1_000;
                    e.ttl = 1;
                }),
                1_001_000,
                DeliveryMode::Ephemeral,
                at_durable_sink,
                Err(EphemeralModeError::Expired),
            ),
        ];

        for row in controls.iter().chain(refusals.iter()) {
            run(row)?;
        }
        assert_eq!(controls.len(), 8, "control rows");
        assert_eq!(refusals.len(), 24, "refusal rows (one per predicate/arm/alternative)");
        Ok(())
    }
}
