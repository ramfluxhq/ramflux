// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant SDK receiver lifetime for authenticated ephemeral envelopes.
//!
//! After signature and source authentication, the still-encrypted envelope is
//! handed to the consumer. No client-DB or journal write happens here.

use ramflux_protocol::ephemeral::{
    DeliveryMode, EPHEMERAL_FUTURE_TOLERANCE_MS, MAX_EPHEMERAL_TTL_SECONDS,
    MIN_EPHEMERAL_TTL_SECONDS, classify_delivery_mode,
};
use ramflux_protocol::{Envelope, Priority};

/// Receiver own-clock and early-hold cap, in milliseconds (inclusive +2000).
pub const RECEIVER_OWN_CLOCK_TOLERANCE_MS: u64 = EPHEMERAL_FUTURE_TOLERANCE_MS;

/// During the S6 bridge, `ttl_seconds` is the sender-signed [`Envelope::ttl`].
#[must_use]
pub fn ttl_seconds(envelope: &Envelope) -> u32 {
    envelope.ttl
}

/// Injected receiver clocks. Tests supply both; production never waits on the wall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverClock {
    /// Receiver Unix wall clock, milliseconds.
    pub local_now_ms: u64,
    /// Receiver monotonic milliseconds; used only to cap an early hold.
    pub monotonic_ms: u64,
}

/// Early-hold lease recorded at first receipt. The monotonic deadline never moves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HoldLease {
    pub display_at_ms: u64,
    pub monotonic_deadline_ms: u64,
    pub expires_at_ms: u64,
}

/// Why the receiver drops an authenticated ephemeral envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReceiverDropReason {
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
    #[error("receiver clock plus future tolerance overflows")]
    ClockToleranceOverflow,
    #[error("ephemeral created_at is too far ahead of the receiver clock")]
    OwnClockTooFarInFuture,
    #[error("ephemeral envelope has expired")]
    Expired,
    #[error("monotonic early-hold cap overflowed")]
    HoldDeadlineOverflow,
    #[error("monotonic early-hold cap elapsed before the signed start")]
    HoldCapExceeded,
}

/// Receiver lifetime decision at one injected clock reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverLifetime {
    Drop(ReceiverDropReason),
    Hold(HoldLease),
    Display { expires_at_ms: u64 },
}

/// Authenticated ciphertext handoff: the envelope is returned still encrypted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct ReceiverHandoff<'a> {
    pub lifetime: ReceiverLifetime,
    /// Still-encrypted envelope when the receiver retains or displays it.
    pub ciphertext: Option<&'a Envelope>,
}

/// Admit an already authenticated ephemeral envelope under injected clocks.
///
/// `hold` is `None` on first receipt and the prior [`HoldLease`] on a later poll.
/// The signed interval is never renewed. Exclusive deadline `now_ms < expires_at_ms`.
/// Refusals are [`ReceiverLifetime::Drop`].
pub fn admit_authenticated_ciphertext(
    envelope: &Envelope,
    clock: ReceiverClock,
    hold: Option<HoldLease>,
) -> ReceiverHandoff<'_> {
    match admit_lifetime(envelope, clock, hold) {
        lifetime @ ReceiverLifetime::Drop(_) => ReceiverHandoff { lifetime, ciphertext: None },
        lifetime => ReceiverHandoff { lifetime, ciphertext: Some(envelope) },
    }
}

fn admit_lifetime(
    envelope: &Envelope,
    clock: ReceiverClock,
    hold: Option<HoldLease>,
) -> ReceiverLifetime {
    let expires_at_ms = match signed_expires_at_ms(envelope) {
        Ok(deadline_ms) => deadline_ms,
        Err(reason) => return ReceiverLifetime::Drop(reason),
    };
    let created_at_ms = i128::from(envelope.created_at) * 1_000;
    if hold.is_none()
        && let Err(reason) = receiver_own_clock_allows(created_at_ms, clock.local_now_ms)
    {
        return ReceiverLifetime::Drop(reason);
    }
    if clock.local_now_ms >= expires_at_ms {
        return ReceiverLifetime::Drop(ReceiverDropReason::Expired);
    }
    if let Some(lease) = hold {
        return poll_hold(created_at_ms, clock, lease);
    }
    first_receipt(created_at_ms, clock, expires_at_ms)
}

/// Distinct from hop `deadline()`: drop immediately when the receiver clock is
/// more than 2 s behind `created_at`, and never hold that input.
fn receiver_own_clock_allows(
    created_at_ms: i128,
    local_now_ms: u64,
) -> Result<(), ReceiverDropReason> {
    let latest = local_now_ms
        .checked_add(RECEIVER_OWN_CLOCK_TOLERANCE_MS)
        .ok_or(ReceiverDropReason::ClockToleranceOverflow)?;
    if created_at_ms > i128::from(latest) {
        return Err(ReceiverDropReason::OwnClockTooFarInFuture);
    }
    Ok(())
}

fn signed_expires_at_ms(envelope: &Envelope) -> Result<u64, ReceiverDropReason> {
    match classify_delivery_mode(envelope) {
        DeliveryMode::Ephemeral => {}
        DeliveryMode::Durable => return Err(ReceiverDropReason::NotEphemeral),
        DeliveryMode::Invalid => return Err(ReceiverDropReason::InvalidDeliveryMode),
    }
    if envelope.priority != Priority::Low {
        return Err(ReceiverDropReason::InvalidPriority);
    }
    if !(MIN_EPHEMERAL_TTL_SECONDS..=MAX_EPHEMERAL_TTL_SECONDS).contains(&envelope.ttl) {
        return Err(ReceiverDropReason::InvalidTtl);
    }
    let expires_at = envelope
        .created_at
        .checked_add(i64::from(envelope.ttl))
        .ok_or(ReceiverDropReason::CreatedAtTtlOverflow)?;
    if expires_at < 0 {
        return Err(ReceiverDropReason::NegativeDeadline);
    }
    u64::try_from(expires_at)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or(ReceiverDropReason::DeadlineMillisecondsOverflow)
}

fn first_receipt(
    created_at_ms: i128,
    clock: ReceiverClock,
    expires_at_ms: u64,
) -> ReceiverLifetime {
    if created_at_ms > i128::from(clock.local_now_ms) {
        let Ok(display_at_ms) = u64::try_from(created_at_ms) else {
            return ReceiverLifetime::Drop(ReceiverDropReason::DeadlineMillisecondsOverflow);
        };
        let Some(monotonic_deadline_ms) =
            clock.monotonic_ms.checked_add(RECEIVER_OWN_CLOCK_TOLERANCE_MS)
        else {
            return ReceiverLifetime::Drop(ReceiverDropReason::HoldDeadlineOverflow);
        };
        return ReceiverLifetime::Hold(HoldLease {
            display_at_ms,
            monotonic_deadline_ms,
            expires_at_ms,
        });
    }
    ReceiverLifetime::Display { expires_at_ms }
}

fn poll_hold(created_at_ms: i128, clock: ReceiverClock, lease: HoldLease) -> ReceiverLifetime {
    if in_signed_display_window(created_at_ms, clock.local_now_ms, lease.expires_at_ms) {
        return ReceiverLifetime::Display { expires_at_ms: lease.expires_at_ms };
    }
    if clock.monotonic_ms >= lease.monotonic_deadline_ms {
        return ReceiverLifetime::Drop(ReceiverDropReason::HoldCapExceeded);
    }
    ReceiverLifetime::Hold(lease)
}

fn in_signed_display_window(created_at_ms: i128, now_ms: u64, expires_at_ms: u64) -> bool {
    created_at_ms <= i128::from(now_ms) && now_ms < expires_at_ms
}

#[cfg(test)]
mod tests {
    use super::{
        HoldLease, MAX_EPHEMERAL_TTL_SECONDS, MIN_EPHEMERAL_TTL_SECONDS, ReceiverClock,
        ReceiverDropReason, ReceiverHandoff, ReceiverLifetime, admit_authenticated_ciphertext,
        ttl_seconds,
    };
    use ramflux_protocol::ephemeral::DELIVERY_MODE_EXTENSION;
    use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
    use serde_json::Value;
    use std::collections::BTreeMap;

    const NOW_MS: u64 = 1_000_000;
    const MONOTONIC_MS: u64 = 50_000;
    const CIPHERTEXT: &str = "still-encrypted-ciphertext";

    fn clock(local_now_ms: u64, monotonic_ms: u64) -> ReceiverClock {
        ReceiverClock { local_now_ms, monotonic_ms }
    }

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
            encrypted_payload: CIPHERTEXT.to_owned(),
            payload_hash: "hash".to_owned(),
        }
    }

    fn mutated(change: impl FnOnce(&mut Envelope)) -> Envelope {
        let mut envelope = valid_envelope();
        change(&mut envelope);
        envelope
    }

    fn admit(
        envelope: &Envelope,
        local_now_ms: u64,
        monotonic_ms: u64,
        hold: Option<HoldLease>,
    ) -> ReceiverHandoff<'_> {
        admit_authenticated_ciphertext(envelope, clock(local_now_ms, monotonic_ms), hold)
    }

    fn drop_reason(handoff: &ReceiverHandoff<'_>) -> Option<ReceiverDropReason> {
        match handoff.lifetime {
            ReceiverLifetime::Drop(reason) => Some(reason),
            ReceiverLifetime::Hold(_) | ReceiverLifetime::Display { .. } => None,
        }
    }

    fn display_expires(handoff: &ReceiverHandoff<'_>) -> Option<u64> {
        match handoff.lifetime {
            ReceiverLifetime::Display { expires_at_ms } => Some(expires_at_ms),
            ReceiverLifetime::Drop(_) | ReceiverLifetime::Hold(_) => None,
        }
    }

    fn hold_lease(handoff: &ReceiverHandoff<'_>) -> Option<HoldLease> {
        match handoff.lifetime {
            ReceiverLifetime::Hold(lease) => Some(lease),
            ReceiverLifetime::Drop(_) | ReceiverLifetime::Display { .. } => None,
        }
    }

    fn assert_ciphertext(handoff: &ReceiverHandoff<'_>, envelope: &Envelope) {
        assert_eq!(
            handoff.ciphertext.map(|handed| handed.encrypted_payload.as_str()),
            Some(CIPHERTEXT)
        );
        assert!(handoff.ciphertext.is_some_and(|handed| {
            handed.encrypted_payload == envelope.encrypted_payload
                && core::ptr::eq(handed, envelope)
        }));
    }

    fn ttl_alias_and_bounds() {
        let envelope = valid_envelope();
        assert_eq!(ttl_seconds(&envelope), envelope.ttl);
        assert_eq!(ttl_seconds(&envelope), MAX_EPHEMERAL_TTL_SECONDS);

        let ttl1 = mutated(|e| e.ttl = MIN_EPHEMERAL_TTL_SECONDS);
        let handoff = admit(&ttl1, NOW_MS, MONOTONIC_MS, None);
        assert_eq!(display_expires(&handoff), Some(1_001_000));
        assert_ciphertext(&handoff, &ttl1);

        let ttl5 = mutated(|e| e.ttl = MAX_EPHEMERAL_TTL_SECONDS);
        let handoff = admit(&ttl5, NOW_MS, MONOTONIC_MS, None);
        assert_eq!(display_expires(&handoff), Some(1_005_000));
        assert_ciphertext(&handoff, &ttl5);

        let ttl0 = mutated(|e| e.ttl = 0);
        assert_eq!(
            drop_reason(&admit(&ttl0, NOW_MS, MONOTONIC_MS, None)),
            Some(ReceiverDropReason::InvalidTtl)
        );

        let ttl6 = mutated(|e| e.ttl = 6);
        assert_eq!(
            drop_reason(&admit(&ttl6, NOW_MS, MONOTONIC_MS, None)),
            Some(ReceiverDropReason::InvalidTtl)
        );
    }

    fn own_clock_and_monotonic_hold() {
        let early = mutated(|e| {
            e.created_at = 1_002;
            e.ttl = 1;
        });
        let exact = admit(&early, NOW_MS, MONOTONIC_MS, None);
        let lease = HoldLease {
            display_at_ms: 1_002_000,
            monotonic_deadline_ms: MONOTONIC_MS + 2_000,
            expires_at_ms: 1_003_000,
        };
        assert_eq!(hold_lease(&exact), Some(lease));
        assert_ciphertext(&exact, &early);

        let at_start = admit(&early, 1_002_000, MONOTONIC_MS + 2_000, Some(lease));
        assert_eq!(display_expires(&at_start), Some(1_003_000));

        let still_hold = admit(&early, 1_001_999, MONOTONIC_MS + 1_999, Some(lease));
        assert_eq!(hold_lease(&still_hold), Some(lease));

        let skewed = admit(&early, 999_999, MONOTONIC_MS, None);
        assert_eq!(drop_reason(&skewed), Some(ReceiverDropReason::OwnClockTooFarInFuture));
        assert!(skewed.ciphertext.is_none());

        let rolled = admit(&early, 999_000, MONOTONIC_MS + 1_000, Some(lease));
        assert_eq!(hold_lease(&rolled), Some(lease));

        let cap = admit(&early, 998_000, MONOTONIC_MS + 2_000, Some(lease));
        assert_eq!(drop_reason(&cap), Some(ReceiverDropReason::HoldCapExceeded));
        assert!(cap.ciphertext.is_none());
    }

    fn overflow_display_bridge_handoff() {
        let overflow_sum = mutated(|e| {
            e.created_at = i64::MAX;
            e.ttl = 5;
        });
        assert_eq!(
            drop_reason(&admit(&overflow_sum, NOW_MS, MONOTONIC_MS, None)),
            Some(ReceiverDropReason::CreatedAtTtlOverflow)
        );

        let overflow_ms = mutated(|e| {
            e.created_at = i64::MAX / 2;
            e.ttl = 1;
        });
        assert_eq!(
            drop_reason(&admit(&overflow_ms, 0, MONOTONIC_MS, None)),
            Some(ReceiverDropReason::DeadlineMillisecondsOverflow)
        );

        let clock_overflow = valid_envelope();
        assert_eq!(
            drop_reason(&admit(&clock_overflow, u64::MAX - 1_999, MONOTONIC_MS, None)),
            Some(ReceiverDropReason::ClockToleranceOverflow)
        );

        let envelope = valid_envelope();
        let live = admit(&envelope, NOW_MS, MONOTONIC_MS, None);
        assert_eq!(display_expires(&live), Some(1_005_000));
        assert_ciphertext(&live, &envelope);

        let last_ms = admit(&envelope, 1_004_999, MONOTONIC_MS, None);
        assert_eq!(display_expires(&last_ms), Some(1_005_000));

        let at_d = admit(&envelope, 1_005_000, MONOTONIC_MS, None);
        assert_eq!(drop_reason(&at_d), Some(ReceiverDropReason::Expired));

        let late = admit(&envelope, 1_002_000, MONOTONIC_MS, None);
        assert_eq!(display_expires(&late), Some(1_005_000));

        let mut durable = valid_envelope();
        durable.ext.ext.remove(DELIVERY_MODE_EXTENSION);
        assert_eq!(
            drop_reason(&admit(&durable, NOW_MS, MONOTONIC_MS, None)),
            Some(ReceiverDropReason::NotEphemeral)
        );

        let mut unknown = valid_envelope();
        unknown
            .ext
            .ext
            .insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("Ephemeral".to_owned()));
        assert_eq!(
            drop_reason(&admit(&unknown, NOW_MS, MONOTONIC_MS, None)),
            Some(ReceiverDropReason::InvalidDeliveryMode)
        );
    }

    #[test]
    fn s0_r4_lifetime_bridge() {
        ttl_alias_and_bounds();
        own_clock_and_monotonic_hold();
        overflow_display_bridge_handoff();
    }
}
