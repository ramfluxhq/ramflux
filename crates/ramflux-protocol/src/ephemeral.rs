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
    use crate::Envelope;
    use crate::{DeliveryClass, Ext, Priority, SignatureAlg, SignedFields};
    use serde_json::Value;

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

    fn assert_deadline_error(envelope: &Envelope, now_ms: u64, expected: EphemeralModeError) {
        assert_eq!(deadline(envelope, now_ms), Err(expected));
    }

    #[test]
    fn ephemeral_mode_and_lifetime_matrix() {
        assert_eq!(GATEWAY_EPHEMERAL_CAPABILITY, "gateway.ephemeral.v1");
        assert_eq!(MIN_EPHEMERAL_TTL_SECONDS, 1);
        assert_eq!(MAX_EPHEMERAL_TTL_SECONDS, 5);
        assert_eq!(EPHEMERAL_FUTURE_TOLERANCE_MS, 2_000);

        // Mode positives: missing and durable select durable; ephemeral selects ephemeral.
        let mut absent = valid_envelope();
        absent.ext.ext.remove(DELIVERY_MODE_EXTENSION);
        assert_eq!(classify_delivery_mode(&absent), DeliveryMode::Durable);
        assert_eq!(require_durable(&absent), Ok(()));

        let mut durable = valid_envelope();
        durable
            .ext
            .ext
            .insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("durable".to_owned()));
        assert_eq!(classify_delivery_mode(&durable), DeliveryMode::Durable);
        assert_eq!(require_durable(&durable), Ok(()));

        let ephemeral = valid_envelope();
        assert_eq!(classify_delivery_mode(&ephemeral), DeliveryMode::Ephemeral);
        assert_eq!(require_durable(&ephemeral), Err(EphemeralModeError::EphemeralAtDurableSink));
        assert_eq!(deadline(&ephemeral, 1_000_000), Ok(1_005_000));

        // Each malformed mode alternative is an isolated negative row.
        let mut mode = valid_envelope();
        mode.ext
            .ext
            .insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("Ephemeral".to_owned()));
        assert_eq!(classify_delivery_mode(&mode), DeliveryMode::Invalid);
        assert_eq!(require_durable(&mode), Err(EphemeralModeError::InvalidDeliveryMode));

        let mut mode = valid_envelope();
        mode.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String(String::new()));
        assert_eq!(classify_delivery_mode(&mode), DeliveryMode::Invalid);

        let mut mode = valid_envelope();
        mode.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::Number(1.into()));
        assert_eq!(classify_delivery_mode(&mode), DeliveryMode::Invalid);

        let mut mode = valid_envelope();
        mode.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::Null);
        assert_eq!(classify_delivery_mode(&mode), DeliveryMode::Invalid);

        let mut mode = valid_envelope();
        mode.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), serde_json::json!({}));
        assert_eq!(classify_delivery_mode(&mode), DeliveryMode::Invalid);

        // Low priority is valid; each other priority has its own negative row.
        assert_eq!(deadline(&valid_envelope(), 1_000_000), Ok(1_005_000));
        for priority in [Priority::Normal, Priority::High, Priority::Urgent] {
            let mut envelope = valid_envelope();
            envelope.priority = priority;
            assert_deadline_error(&envelope, 1_000_000, EphemeralModeError::InvalidPriority);
        }

        // Both inclusive TTL bounds are valid; each out-of-range value is isolated.
        for ttl in [MIN_EPHEMERAL_TTL_SECONDS, MAX_EPHEMERAL_TTL_SECONDS] {
            let mut envelope = valid_envelope();
            envelope.ttl = ttl;
            assert_eq!(deadline(&envelope, 1_000_000), Ok((1_000 + u64::from(ttl)) * 1_000));
        }
        for ttl in [0, 6, u32::MAX] {
            let mut envelope = valid_envelope();
            envelope.ttl = ttl;
            assert_deadline_error(&envelope, 1_000_000, EphemeralModeError::InvalidTtl);
        }

        // The sender-clock lead is inclusive at +2000 ms and rejects +2001 ms.
        let mut future = valid_envelope();
        future.created_at = 1_002;
        future.ttl = 1;
        assert_eq!(deadline(&future, 1_000_000), Ok(1_003_000));

        let mut future = valid_envelope();
        future.created_at = 1_002;
        future.ttl = 1;
        assert_deadline_error(&future, 999_999, EphemeralModeError::CreatedAtTooFarInFuture);

        // The deadline itself is exclusive: one millisecond before is live, equality is expired.
        let mut expiry = valid_envelope();
        expiry.created_at = 1_000;
        expiry.ttl = 1;
        assert_eq!(deadline(&expiry, 1_000_999), Ok(1_001_000));

        let mut expiry = valid_envelope();
        expiry.created_at = 1_000;
        expiry.ttl = 1;
        assert_deadline_error(&expiry, 1_001_000, EphemeralModeError::Expired);

        // Each checked-arithmetic refusal has an isolated valid-vector mutation.
        let mut overflow = valid_envelope();
        overflow.created_at = i64::MAX;
        overflow.ttl = 5;
        assert_deadline_error(&overflow, 0, EphemeralModeError::CreatedAtTtlOverflow);

        let mut overflow = valid_envelope();
        overflow.created_at = i64::MAX / 2;
        overflow.ttl = 1;
        assert_deadline_error(&overflow, 0, EphemeralModeError::DeadlineMillisecondsOverflow);

        let mut negative = valid_envelope();
        negative.created_at = -2;
        negative.ttl = 1;
        assert_deadline_error(&negative, 0, EphemeralModeError::NegativeDeadline);
    }
}
