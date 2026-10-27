// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded per-source accounting for the public federation HTTP listener.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ramflux_node_core::NodeCoreError;

const DEFAULT_MAX_CONNECTIONS: usize = 8;
const DEFAULT_REQUEST_RATE: u32 = 20;
const DEFAULT_REQUEST_BURST: u32 = 40;
const DEFAULT_TABLE_CAPACITY: usize = 4096;
const DEFAULT_IDLE_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicSourceLimitConfig {
    max_connections: usize,
    request_rate_per_second: u32,
    request_burst: u32,
    table_capacity: usize,
    idle_expiry: Duration,
}

impl PublicSourceLimitConfig {
    pub(crate) fn configured() -> Result<Self, NodeCoreError> {
        Ok(Self {
            max_connections: setting_usize(
                "RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS_PER_SOURCE",
                DEFAULT_MAX_CONNECTIONS,
                4096,
            )?,
            request_rate_per_second: setting_u32(
                "RAMFLUX_FEDERATION_PUBLIC_REQUEST_RATE_PER_SECOND",
                DEFAULT_REQUEST_RATE,
                1_000_000,
            )?,
            request_burst: setting_u32(
                "RAMFLUX_FEDERATION_PUBLIC_REQUEST_BURST",
                DEFAULT_REQUEST_BURST,
                1_000_000,
            )?,
            table_capacity: setting_usize(
                "RAMFLUX_FEDERATION_PUBLIC_SOURCE_TABLE_CAPACITY",
                DEFAULT_TABLE_CAPACITY,
                65_536,
            )?,
            idle_expiry: Duration::from_secs(setting_u64(
                "RAMFLUX_FEDERATION_PUBLIC_SOURCE_IDLE_SECONDS",
                DEFAULT_IDLE_SECONDS,
                86_400,
            )?),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        max_connections: usize,
        request_rate_per_second: u32,
        request_burst: u32,
        table_capacity: usize,
        idle_expiry: Duration,
    ) -> Self {
        Self {
            max_connections,
            request_rate_per_second,
            request_burst,
            table_capacity,
            idle_expiry,
        }
    }
}

fn setting_usize(key: &str, default: usize, maximum: usize) -> Result<usize, NodeCoreError> {
    setting_u64(
        key,
        u64::try_from(default).unwrap_or(1),
        u64::try_from(maximum).unwrap_or(u64::MAX),
    )
    .and_then(|value| {
        usize::try_from(value)
            .map_err(|_| NodeCoreError::ItestHttp(format!("{key} must be 1..{maximum}")))
    })
}

fn setting_u32(key: &str, default: u32, maximum: u32) -> Result<u32, NodeCoreError> {
    setting_u64(key, u64::from(default), u64::from(maximum)).and_then(|value| {
        u32::try_from(value)
            .map_err(|_| NodeCoreError::ItestHttp(format!("{key} must be 1..{maximum}")))
    })
}

fn setting_u64(key: &str, default: u64, maximum: u64) -> Result<u64, NodeCoreError> {
    let Some(value) = ramflux_node_core::environment::var_os(key) else { return Ok(default) };
    let Some(value) = value.to_str() else { return Err(invalid_setting(key, maximum)) };
    parse_setting_u64(key, value, maximum)
}

fn parse_setting_u64(key: &str, value: &str, maximum: u64) -> Result<u64, NodeCoreError> {
    value
        .parse()
        .ok()
        .filter(|value| (1..=maximum).contains(value))
        .ok_or_else(|| invalid_setting(key, maximum))
}

fn invalid_setting(key: &str, maximum: u64) -> NodeCoreError {
    NodeCoreError::ItestHttp(format!("{key} must be 1..{maximum}"))
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SourceKey {
    V4(Ipv4Addr),
    V6Prefix([u8; 8]),
}

impl From<IpAddr> for SourceKey {
    fn from(source: IpAddr) -> Self {
        match source {
            IpAddr::V4(address) => Self::V4(address),
            IpAddr::V6(address) => {
                if let Some(address) = address.to_ipv4_mapped() {
                    Self::V4(address)
                } else {
                    let octets = address.octets();
                    let mut prefix = [0_u8; 8];
                    prefix.copy_from_slice(&octets[..8]);
                    Self::V6Prefix(prefix)
                }
            }
        }
    }
}

#[derive(Debug)]
struct SourceState {
    active_connections: usize,
    tokens: f64,
    token_updated_at: Instant,
    last_seen: Instant,
}

#[derive(Debug, Default)]
struct TrackerState {
    sources: HashMap<SourceKey, SourceState>,
}

#[derive(Debug)]
pub(crate) struct PublicSourceLimits {
    config: PublicSourceLimitConfig,
    state: Mutex<TrackerState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionRefusal {
    SourceLimit,
    TrackingCapacity,
}

impl PublicSourceLimits {
    pub(crate) fn new(config: PublicSourceLimitConfig) -> Arc<Self> {
        Arc::new(Self { config, state: Mutex::new(TrackerState::default()) })
    }

    pub(crate) fn acquire_connection(
        self: &Arc<Self>,
        source: IpAddr,
        now: Instant,
    ) -> Result<SourceConnectionPermit, ConnectionRefusal> {
        let key = SourceKey::from(source);
        let mut state = self.lock_state();
        if let Some(entry) = state.sources.get_mut(&key) {
            if entry.active_connections >= self.config.max_connections {
                return Err(ConnectionRefusal::SourceLimit);
            }
            entry.active_connections += 1;
            entry.last_seen = now;
            return Ok(SourceConnectionPermit { limits: Arc::clone(self), key });
        }
        if state.sources.len() >= self.config.table_capacity {
            let idle_expiry = self.config.idle_expiry;
            state.sources.retain(|_, entry| {
                entry.active_connections != 0
                    || now.saturating_duration_since(entry.last_seen) < idle_expiry
            });
        }
        if state.sources.len() >= self.config.table_capacity {
            return Err(ConnectionRefusal::TrackingCapacity);
        }
        state.sources.insert(
            key,
            SourceState {
                active_connections: 1,
                tokens: f64::from(self.config.request_burst),
                token_updated_at: now,
                last_seen: now,
            },
        );
        Ok(SourceConnectionPermit { limits: Arc::clone(self), key })
    }

    fn allow_request(&self, key: SourceKey, now: Instant) -> bool {
        let mut state = self.lock_state();
        let Some(entry) = state.sources.get_mut(&key) else { return false };
        let elapsed = now.saturating_duration_since(entry.token_updated_at).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * f64::from(self.config.request_rate_per_second))
            .min(f64::from(self.config.request_burst));
        entry.token_updated_at = now;
        entry.last_seen = now;
        if entry.tokens < 1.0 {
            return false;
        }
        entry.tokens -= 1.0;
        true
    }

    fn release_connection(&self, key: SourceKey, now: Instant) {
        let mut state = self.lock_state();
        if let Some(entry) = state.sources.get_mut(&key) {
            entry.active_connections = entry.active_connections.saturating_sub(1);
            entry.last_seen = now;
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, TrackerState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn tracked_sources(&self) -> usize {
        self.lock_state().sources.len()
    }
}

pub(crate) struct SourceConnectionPermit {
    limits: Arc<PublicSourceLimits>,
    key: SourceKey,
}

impl SourceConnectionPermit {
    pub(crate) fn allow_request(&self, now: Instant) -> bool {
        self.limits.allow_request(self.key, now)
    }
}

impl Drop for SourceConnectionPermit {
    fn drop(&mut self) {
        self.limits.release_connection(self.key, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn limits(max_connections: usize, table_capacity: usize) -> Arc<PublicSourceLimits> {
        PublicSourceLimits::new(PublicSourceLimitConfig::for_test(
            max_connections,
            1,
            2,
            table_capacity,
            Duration::from_secs(30),
        ))
    }

    #[test]
    fn numeric_settings_are_positive_and_bounded() {
        assert_eq!(parse_setting_u64("SETTING", "1", 8).ok(), Some(1));
        assert_eq!(parse_setting_u64("SETTING", "8", 8).ok(), Some(8));
        for invalid in ["", "0", "9", "-1", "not-a-number", "${UNRESOLVED}"] {
            assert!(parse_setting_u64("SETTING", invalid, 8).is_err());
        }
    }

    #[test]
    fn one_source_cannot_consume_another_sources_connection_budget() -> Result<(), String> {
        let limits = limits(8, 8);
        let now = Instant::now();
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let held = (0..8)
            .map(|_| limits.acquire_connection(first, now).map_err(|error| format!("{error:?}")))
            .collect::<Result<Vec<_>, _>>()?;
        for _ in 0..32 {
            assert_eq!(
                limits.acquire_connection(first, now).err(),
                Some(ConnectionRefusal::SourceLimit)
            );
        }
        let _other =
            limits.acquire_connection(second, now).map_err(|error| format!("{error:?}"))?;
        drop(held);
        Ok(())
    }

    #[test]
    fn table_stays_bounded_during_spoofed_source_churn_and_reuses_expired_entries()
    -> Result<(), String> {
        let limits = limits(1, 4);
        let now = Instant::now();
        for suffix in 1..=100_u8 {
            let permit =
                limits.acquire_connection(IpAddr::V4(Ipv4Addr::new(198, 51, 100, suffix)), now);
            if suffix <= 4 {
                drop(permit.map_err(|error| format!("{error:?}"))?);
            } else {
                assert_eq!(permit.err(), Some(ConnectionRefusal::TrackingCapacity));
            }
            assert!(limits.tracked_sources() <= 4);
        }
        let later = now + Duration::from_secs(31);
        let replacement = limits
            .acquire_connection(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), later)
            .map_err(|error| format!("{error:?}"))?;
        drop(replacement);
        assert_eq!(limits.tracked_sources(), 1);
        Ok(())
    }

    #[test]
    fn ipv6_sources_are_aggregated_by_prefix_and_rate_buckets_are_source_scoped()
    -> Result<(), String> {
        let limits = limits(1, 8);
        let now = Instant::now();
        let first = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1));
        let same_prefix = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0xffff));
        let other_prefix = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1));
        let first_permit =
            limits.acquire_connection(first, now).map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            limits.acquire_connection(same_prefix, now).err(),
            Some(ConnectionRefusal::SourceLimit)
        );
        let other_permit =
            limits.acquire_connection(other_prefix, now).map_err(|error| format!("{error:?}"))?;
        assert!(first_permit.allow_request(now));
        assert!(first_permit.allow_request(now));
        assert!(!first_permit.allow_request(now));
        assert!(other_permit.allow_request(now));
        assert!(first_permit.allow_request(now + Duration::from_secs(1)));
        Ok(())
    }
}
