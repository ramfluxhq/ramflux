// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Share Capacity cooldowns across reconnects and command calls in the same daemon.
use super::CustodyNetworkConfig;
use crate::SdkError;
use ramflux_protocol::custody::CustodyRefusal;
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::time::Instant;

pub(crate) const RETRY_AFTER_MS: u64 = 300_000;
const COOLDOWN: Duration = Duration::from_millis(RETRY_AFTER_MS);
#[derive(Default)]
struct Cooldowns(BTreeMap<String, Instant>);
impl Cooldowns {
    fn check(&mut self, key: &str, now: Instant) -> Result<(), SdkError> {
        self.0.retain(|_, until| *until > now);
        if self.0.contains_key(key) { Err(CustodyRefusal::Capacity.into()) } else { Ok(()) }
    }
    fn record(&mut self, key: String, now: Instant) {
        self.0.retain(|_, until| *until > now);
        // A locally refused retry must not extend the original server refusal's deadline.
        self.0.entry(key).or_insert(now + COOLDOWN);
    }
}
fn state() -> std::sync::MutexGuard<'static, Cooldowns> {
    static STATE: OnceLock<Mutex<Cooldowns>> = OnceLock::new();
    STATE.get_or_init(Mutex::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
pub(super) fn key(config: &CustodyNetworkConfig) -> String {
    // The account and receiving-node pin scope the refusal; independent accounts/nodes remain usable.
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
    state().check(key, Instant::now())
}
pub(super) fn record(key: String) {
    state().record(key, Instant::now());
}

#[cfg(test)]
pub(super) fn clear_for_test(key: &str) {
    state().0.remove(key);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn capacity_waits_three_hundred_seconds_without_extending_on_local_retries()
    -> Result<(), SdkError> {
        let mut state = Cooldowns::default();
        let now = Instant::now();
        state.record("alice/node-a".into(), now);
        for seconds in [0, 1, 25, 90, 299] {
            assert!(matches!(
                state.check("alice/node-a", now + Duration::from_secs(seconds)),
                Err(SdkError::CustodyNetwork(CustodyRefusal::Capacity))
            ));
            state.record("alice/node-a".into(), now + Duration::from_secs(seconds));
        }
        state.check("bob/node-a", now)?;
        state.check("alice/node-b", now)?;
        state.check("alice/node-a", now + COOLDOWN)?;
        assert!(state.0.is_empty());
        Ok(())
    }
}
