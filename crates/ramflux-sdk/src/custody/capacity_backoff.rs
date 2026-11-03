// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Share Capacity cooldowns across reconnects and retain server-owned daily reset deadlines.
use super::CustodyNetworkConfig;
use crate::SdkError;
use ramflux_protocol::custody::{CapacityHint, CustodyRefusal};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::time::Instant;

pub(crate) const RETRY_AFTER_SECS: u64 = 300;
pub(crate) const RETRY_AFTER_MS: u64 = RETRY_AFTER_SECS * 1000;
const COOLDOWN: Duration = Duration::from_millis(RETRY_AFTER_MS);
struct Deadline {
    until: Option<Instant>,
    hint: Option<CapacityHint>,
}
impl Deadline {
    fn new(now: Instant, wall: u64, hint: Option<CapacityHint>) -> Self {
        let hint = hint.and_then(|hint| super::capacity_hint::accepted(hint, wall));
        let wait = hint
            .map_or(COOLDOWN.as_secs(), |h| h.resets_at_unix.saturating_sub(wall))
            .max(COOLDOWN.as_secs());
        // Unrepresentable server deadlines remain blocked instead of wrapping or panicking.
        Self { until: now.checked_add(Duration::from_secs(wait)), hint }
    }
    fn active(&self, now: Instant, wall: u64) -> bool {
        self.until.is_none_or(|until| now < until)
            || self.hint.is_some_and(|hint| wall < hint.resets_at_unix)
    }
    fn error(&self, wall: u64) -> SdkError {
        self.hint.filter(|hint| hint.resets_at_unix > wall).map_or_else(
            || CustodyRefusal::Capacity.into(),
            |capacity| SdkError::CustodyCapacity { capacity },
        )
    }
}
#[derive(Default)]
struct Cooldowns(BTreeMap<String, Deadline>);
impl Cooldowns {
    fn check(&mut self, key: &str, now: Instant, wall: u64) -> Result<(), SdkError> {
        self.0.retain(|_, deadline| deadline.active(now, wall));
        self.0.get(key).map_or(Ok(()), |deadline| Err(deadline.error(wall)))
    }
    fn record(&mut self, key: String, now: Instant, wall: u64, hint: Option<CapacityHint>) {
        let hint = hint.and_then(|hint| super::capacity_hint::accepted(hint, wall));
        self.0.retain(|_, deadline| deadline.active(now, wall));
        let entry = self.0.entry(key).or_insert_with(|| Deadline::new(now, wall, hint));
        // Repeated local refusals do not move the original deadline. A new, later server
        // window can extend it; an unhinted refusal cannot erase known daily metadata.
        if let Some(hint) = hint
            && entry.hint.is_none_or(|old| hint.resets_at_unix > old.resets_at_unix)
        {
            let next = Deadline::new(now, wall, Some(hint));
            entry.until = match (entry.until, next.until) {
                (Some(old), Some(new)) => Some(old.max(new)),
                _ => None,
            };
            entry.hint = Some(hint);
        }
    }
}
fn state() -> std::sync::MutexGuard<'static, Cooldowns> {
    static STATE: OnceLock<Mutex<Cooldowns>> = OnceLock::new();
    STATE.get_or_init(Mutex::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
pub(super) fn key(config: &CustodyNetworkConfig) -> String {
    let mut key = blake3::Hasher::new();
    for value in [
        config.account_root.as_os_str().as_encoded_bytes(),
        config.account_id.as_bytes(),
        config.node_id.as_bytes(),
        config.node_public_key.as_bytes(),
        config.gateway_address.to_string().as_bytes(),
    ] {
        key.update(&(value.len() as u64).to_le_bytes());
        key.update(value);
    }
    key.finalize().to_hex().to_string()
}
pub(super) fn check(key: &str) -> Result<(), SdkError> {
    state().check(key, Instant::now(), super::capacity_hint::unix_now())
}
pub(super) fn record_error(key: String, error: &SdkError) {
    if error.custody_refusal() == Some(CustodyRefusal::Capacity) {
        state().record(
            key,
            Instant::now(),
            super::capacity_hint::unix_now(),
            error.capacity_hint(),
        );
    }
}
#[cfg(test)]
pub(super) fn clear_for_test(key: &str) {
    state().0.remove(key);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_protocol::custody::CapacityScope;

    #[tokio::test(start_paused = true)]
    async fn capacity_waits_three_hundred_seconds_without_extending_on_local_retries()
    -> Result<(), SdkError> {
        let mut state = Cooldowns::default();
        let now = Instant::now();
        state.record("alice/node-a".into(), now, 1000, None);
        for seconds in [0, 1, 25, 90, 299] {
            assert!(matches!(
                state.check("alice/node-a", now + Duration::from_secs(seconds), 1000 + seconds),
                Err(SdkError::CustodyNetwork(CustodyRefusal::Capacity))
            ));
            state.record(
                "alice/node-a".into(),
                now + Duration::from_secs(seconds),
                1000 + seconds,
                None,
            );
        }
        state.check("bob/node-a", now, 1000)?;
        state.check("alice/node-b", now, 1000)?;
        state.check("alice/node-a", now + COOLDOWN, 1300)?;
        assert!(state.0.is_empty());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn capacity_hint_never_retries_before_reset_or_floor_despite_clock_changes()
    -> Result<(), SdkError> {
        let mut state = Cooldowns::default();
        let now = Instant::now();
        let hint = CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: 4600 };
        state.record("a".into(), now, 1000, Some(hint));
        for elapsed in [0, 300, 3599] {
            let error = state
                .check("a", now + Duration::from_secs(elapsed), 1000 + elapsed)
                .err()
                .ok_or(SdkError::CustodySetupInvalid)?;
            assert_eq!(error.custody_refusal(), Some(CustodyRefusal::Capacity));
            assert_eq!(error.capacity_hint(), Some(hint));
        }
        // A wall-clock jump forward cannot bypass the captured monotonic reset interval.
        assert!(state.check("a", now + COOLDOWN, 9000).is_err());
        // Nor can a monotonic deadline bypass a wall clock still before the server reset.
        assert!(state.check("a", now + Duration::from_secs(3600), 4599).is_err());
        state.check("a", now + Duration::from_secs(3600), 4600)?;
        let short = CapacityHint { resets_at_unix: 1100, ..hint };
        state.record("short".into(), now, 1000, Some(short));
        assert!(state.check("short", now + Duration::from_secs(100), 1100).is_err());
        state.check("short", now + COOLDOWN, 1300)?;
        state.record(
            "huge".into(),
            now,
            1000,
            Some(CapacityHint { resets_at_unix: u64::MAX, ..hint }),
        );
        state.check("huge", now + COOLDOWN, 1300)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn custody_capacity_far_future_and_past_resets_keep_the_monotonic_floor()
    -> Result<(), SdkError> {
        for reset in [u64::MAX, 1000 + 2 * 86_400 + 1, 999] {
            let now = Instant::now();
            let mut state = Cooldowns::default();
            state.record(
                "bounded".into(),
                now,
                1000,
                Some(CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: reset }),
            );
            let error = state
                .check("bounded", now + Duration::from_secs(299), 1299)
                .err()
                .ok_or(SdkError::CustodySetupInvalid)?;
            assert_eq!(error.capacity_hint(), None);
            state.check("bounded", now + COOLDOWN, 1300)?;
        }
        Ok(())
    }
}
