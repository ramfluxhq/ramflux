// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Core primitives shared by the Ramflux workspace.

#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const CRATE_NAME: &str = "ramflux-core";

#[must_use]
pub const fn crate_name() -> &'static str {
    CRATE_NAME
}

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CoreError {
    #[error("invalid {kind} id: {value}")]
    InvalidId { kind: &'static str, value: String },
    #[error("system clock is before unix epoch")]
    ClockBeforeUnixEpoch,
    #[error("operation cancelled")]
    Cancelled,
    #[error("retry attempts exhausted after {attempts} attempts")]
    RetryExhausted { attempts: u32 },
    #[error("backpressure budget exhausted: capacity={capacity}, in_flight={in_flight}")]
    BackpressureExhausted { capacity: u64, in_flight: u64 },
    #[error("feature disabled: {0}")]
    FeatureDisabled(FeatureFlag),
}

macro_rules! typed_id {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// # Errors
            /// Returns an error when the id is empty or contains ASCII whitespace.
            pub fn new(value: impl Into<String>) -> CoreResult<Self> {
                let value = value.into();
                if is_valid_id(&value) {
                    Ok(Self(value))
                } else {
                    Err(CoreError::InvalidId { kind: $kind, value })
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = CoreError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = CoreError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

typed_id!(AccountId, "account");
typed_id!(PrincipalId, "principal");
typed_id!(DeviceId, "device");
typed_id!(ConversationId, "conversation");
typed_id!(MessageId, "message");
typed_id!(GroupId, "group");
typed_id!(ObjectId, "object");
typed_id!(ChunkId, "chunk");
typed_id!(EventId, "event");
typed_id!(EnvelopeId, "envelope");
typed_id!(DomainTag, "domain");
typed_id!(FeatureName, "feature");

fn is_valid_id(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_whitespace)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientEventEnvelope {
    pub event_id: EventId,
    pub actor_device_id: Option<DeviceId>,
    pub occurred_at: UnixMillis,
    pub payload_hash: Option<RedactedValue>,
}

impl ClientEventEnvelope {
    #[must_use]
    pub const fn new(
        event_id: EventId,
        actor_device_id: Option<DeviceId>,
        occurred_at: UnixMillis,
        payload_hash: Option<RedactedValue>,
    ) -> Self {
        Self { event_id, actor_device_id, occurred_at, payload_hash }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct UnixMillis(u64);

impl UnixMillis {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

pub trait Clock: Send + Sync {
    /// # Errors
    /// Returns an error when the clock cannot provide a Unix millisecond timestamp.
    fn now_millis(&self) -> CoreResult<UnixMillis>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> CoreResult<UnixMillis> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_error| CoreError::ClockBeforeUnixEpoch)?;
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Ok(UnixMillis::new(millis))
    }
}

#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// # Errors
    /// Returns an error when cancellation has been requested.
    pub fn check(&self) -> CoreResult<()> {
        if self.is_cancelled() { Err(CoreError::Cancelled) } else { Ok(()) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl RetryPolicy {
    #[must_use]
    pub const fn new(max_attempts: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self { max_attempts, base_delay, max_delay }
    }

    #[must_use]
    pub fn delay_for_attempt(self, attempt: u32) -> Option<Duration> {
        if attempt >= self.max_attempts {
            return None;
        }
        let shift = attempt.min(31);
        let factor = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        Some(self.base_delay.saturating_mul(factor).min(self.max_delay))
    }
}

#[derive(Clone, Debug)]
pub struct BackpressureBudget {
    inner: Arc<BackpressureInner>,
}

#[derive(Debug)]
struct BackpressureInner {
    capacity: u64,
    in_flight: AtomicU64,
}

impl BackpressureBudget {
    #[must_use]
    pub fn new(capacity: u64) -> Self {
        Self { inner: Arc::new(BackpressureInner { capacity, in_flight: AtomicU64::new(0) }) }
    }

    /// # Errors
    /// Returns an error when taking one more permit would exceed capacity.
    pub fn try_acquire(&self) -> CoreResult<BackpressurePermit> {
        let mut current = self.inner.in_flight.load(Ordering::Acquire);
        loop {
            if current >= self.inner.capacity {
                return Err(CoreError::BackpressureExhausted {
                    capacity: self.inner.capacity,
                    in_flight: current,
                });
            }
            match self.inner.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(BackpressurePermit { inner: Arc::clone(&self.inner) });
                }
                Err(next) => current = next,
            }
        }
    }

    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.inner.in_flight.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.inner.capacity
    }
}

#[derive(Debug)]
pub struct BackpressurePermit {
    inner: Arc<BackpressureInner>,
}

impl Drop for BackpressurePermit {
    fn drop(&mut self) {
        self.inner.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureFlag {
    Realnet,
    A2ui,
    Mcp,
    ObjectSync,
    Federation,
    TurnSignaling,
}

impl fmt::Display for FeatureFlag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Realnet => "realnet",
            Self::A2ui => "a2ui",
            Self::Mcp => "mcp",
            Self::ObjectSync => "object_sync",
            Self::Federation => "federation",
            Self::TurnSignaling => "turn_signaling",
        };
        formatter.write_str(value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeatureSet {
    enabled: BTreeSet<FeatureFlag>,
}

impl FeatureSet {
    #[must_use]
    pub fn new(enabled: impl IntoIterator<Item = FeatureFlag>) -> Self {
        Self { enabled: enabled.into_iter().collect() }
    }

    #[must_use]
    pub fn is_enabled(&self, flag: FeatureFlag) -> bool {
        self.enabled.contains(&flag)
    }

    /// # Errors
    /// Returns an error when `flag` is not enabled.
    pub fn require(&self, flag: FeatureFlag) -> CoreResult<()> {
        if self.is_enabled(flag) { Ok(()) } else { Err(CoreError::FeatureDisabled(flag)) }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceField {
    pub name: String,
    pub value: RedactedValue,
}

impl TraceField {
    #[must_use]
    pub fn new(name: impl Into<String>, value: RedactedValue) -> Self {
        Self { name: name.into(), value }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RedactedValue {
    Public(String),
    Opaque(String),
    Secret,
}

impl RedactedValue {
    #[must_use]
    pub fn safe_value(&self) -> &str {
        match self {
            Self::Public(value) | Self::Opaque(value) => value,
            Self::Secret => "<redacted>",
        }
    }

    #[must_use]
    pub const fn is_secret(&self) -> bool {
        matches!(self, Self::Secret)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceContext {
    fields: Vec<TraceField>,
}

impl TraceContext {
    #[must_use]
    pub fn new(fields: Vec<TraceField>) -> Self {
        Self { fields }
    }

    #[must_use]
    pub fn fields(&self) -> &[TraceField] {
        &self.fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_event_envelope() -> CoreResult<ClientEventEnvelope> {
        Ok(ClientEventEnvelope::new(
            EventId::new("evt_1")?,
            Some(DeviceId::new("dev_1")?),
            UnixMillis::new(10),
            Some(RedactedValue::Opaque("hash_1".to_owned())),
        ))
    }

    #[test]
    fn typed_ids_reject_empty_or_whitespace() {
        assert!(DeviceId::new("dev_1").is_ok());
        assert!(DeviceId::new("").is_err());
        assert!(DeviceId::new("bad id").is_err());
    }

    #[test]
    fn client_event_envelope_preserves_metadata() -> CoreResult<()> {
        let envelope = valid_event_envelope()?;
        assert_eq!(envelope.event_id.as_str(), "evt_1");
        assert_eq!(envelope.actor_device_id.as_ref().map(DeviceId::as_str), Some("dev_1"));
        assert_eq!(envelope.occurred_at.as_u64(), 10);
        Ok(())
    }

    #[test]
    fn cancellation_token_reports_cancelled() {
        let token = CancellationToken::new();
        assert!(token.check().is_ok());
        token.cancel();
        assert_eq!(token.check(), Err(CoreError::Cancelled));
    }

    #[test]
    fn retry_policy_caps_delay_and_attempts() {
        let policy = RetryPolicy::new(3, Duration::from_millis(10), Duration::from_millis(15));
        assert_eq!(policy.delay_for_attempt(0), Some(Duration::from_millis(10)));
        assert_eq!(policy.delay_for_attempt(1), Some(Duration::from_millis(15)));
        assert_eq!(policy.delay_for_attempt(3), None);
    }

    #[test]
    fn backpressure_permit_releases_on_drop() -> CoreResult<()> {
        let budget = BackpressureBudget::new(1);
        let permit = budget.try_acquire()?;
        assert_eq!(budget.in_flight(), 1);
        assert!(budget.try_acquire().is_err());
        drop(permit);
        assert_eq!(budget.in_flight(), 0);
        assert!(budget.try_acquire().is_ok());
        Ok(())
    }

    #[test]
    fn feature_set_requires_enabled_flags() {
        let features = FeatureSet::new([FeatureFlag::Mcp]);
        assert!(features.require(FeatureFlag::Mcp).is_ok());
        assert_eq!(
            features.require(FeatureFlag::Realnet),
            Err(CoreError::FeatureDisabled(FeatureFlag::Realnet))
        );
    }

    #[test]
    fn trace_context_redacts_secret_values() {
        let context = TraceContext::new(vec![
            TraceField::new("account_id", RedactedValue::Opaque("acct_hash".to_owned())),
            TraceField::new("secret", RedactedValue::Secret),
        ]);
        assert_eq!(context.fields()[0].value.safe_value(), "acct_hash");
        assert_eq!(context.fields()[1].value.safe_value(), "<redacted>");
    }
}
