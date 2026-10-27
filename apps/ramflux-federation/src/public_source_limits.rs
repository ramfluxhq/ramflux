// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded per-source accounting for the public federation HTTP listener.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ramflux_node_core::NodeCoreError;

const DEFAULT_MAX_CONNECTIONS: usize = 8;
const DEFAULT_AGGREGATE_MAX_CONNECTIONS: usize = 16;
const DEFAULT_CONNECTION_RATE: u32 = 20;
const DEFAULT_CONNECTION_BURST: u32 = 40;
const DEFAULT_REQUEST_RATE: u32 = 20;
const DEFAULT_REQUEST_BURST: u32 = 40;
const DEFAULT_TABLE_CAPACITY: usize = 4096;
const DEFAULT_IDLE_SECONDS: u64 = 300;
const PROXY_WARNING_WINDOW: usize = 100;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicSourceLimitConfig {
    enabled: bool,
    max_connections: usize,
    aggregate_max_connections: usize,
    connection_rate_per_second: u32,
    connection_burst: u32,
    request_rate_per_second: u32,
    request_burst: u32,
    table_capacity: usize,
    idle_expiry: Duration,
}

impl PublicSourceLimitConfig {
    pub(crate) fn configured(global_connection_limit: usize) -> Result<Self, NodeCoreError> {
        let config = Self {
            enabled: on_off_setting("RAMFLUX_FEDERATION_PER_SOURCE_LIMITS", true)?,
            max_connections: setting_usize(
                "RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS_PER_SOURCE",
                DEFAULT_MAX_CONNECTIONS,
                4096,
            )?,
            aggregate_max_connections: setting_usize(
                "RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS_PER_PREFIX",
                DEFAULT_AGGREGATE_MAX_CONNECTIONS,
                4096,
            )?,
            connection_rate_per_second: setting_u32(
                "RAMFLUX_FEDERATION_PUBLIC_CONNECTION_RATE_PER_SECOND",
                DEFAULT_CONNECTION_RATE,
                1_000_000,
            )?,
            connection_burst: setting_u32(
                "RAMFLUX_FEDERATION_PUBLIC_CONNECTION_BURST",
                DEFAULT_CONNECTION_BURST,
                1_000_000,
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
        };
        config.validate(global_connection_limit)
    }

    fn validate(self, global_connection_limit: usize) -> Result<Self, NodeCoreError> {
        if self.enabled && self.table_capacity <= global_connection_limit {
            return Err(NodeCoreError::ItestHttp(format!(
                "RAMFLUX_FEDERATION_PUBLIC_SOURCE_TABLE_CAPACITY must be greater than RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS ({global_connection_limit})"
            )));
        }
        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        max_connections: usize,
        aggregate_max_connections: usize,
        table_capacity: usize,
    ) -> Self {
        Self {
            enabled: true,
            max_connections,
            aggregate_max_connections,
            connection_rate_per_second: 1_000,
            connection_burst: 1_000,
            request_rate_per_second: 1_000,
            request_burst: 1_000,
            table_capacity,
            idle_expiry: Duration::from_secs(30),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_request_rate(mut self, rate: u32, burst: u32) -> Self {
        self.request_rate_per_second = rate;
        self.request_burst = burst;
        self
    }

    #[cfg(test)]
    fn with_connection_rate(mut self, rate: u32, burst: u32) -> Self {
        self.connection_rate_per_second = rate;
        self.connection_burst = burst;
        self
    }

    #[cfg(test)]
    fn with_idle_expiry(mut self, idle_expiry: Duration) -> Self {
        self.idle_expiry = idle_expiry;
        self
    }

    #[cfg(test)]
    pub(crate) fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

fn on_off_setting(key: &str, default: bool) -> Result<bool, NodeCoreError> {
    let Some(value) = ramflux_node_core::environment::var_os(key) else { return Ok(default) };
    match value.to_str() {
        Some("on") => Ok(true),
        Some("off") => Ok(false),
        _ => Err(NodeCoreError::ItestHttp(format!("{key} must be on or off"))),
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

impl SourceKey {
    fn aggregate(self) -> AggregateKey {
        match self {
            Self::V4(address) => {
                let octets = address.octets();
                AggregateKey::V4Prefix([octets[0], octets[1], octets[2]])
            }
            Self::V6Prefix(source) => AggregateKey::V6Prefix([
                source[0], source[1], source[2], source[3], source[4], source[5],
            ]),
        }
    }
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AggregateKey {
    V4Prefix([u8; 3]),
    V6Prefix([u8; 6]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdleClass {
    Refilled,
    Limited,
}

#[derive(Debug)]
struct SourceState {
    active_connections: usize,
    request_tokens: f64,
    request_token_updated_at: Instant,
    connection_tokens: f64,
    connection_token_updated_at: Instant,
    last_seen: Instant,
    idle_class: Option<IdleClass>,
    idle_previous: Option<SourceKey>,
    idle_next: Option<SourceKey>,
}

#[derive(Debug)]
struct AggregateState {
    active_connections: usize,
    tracked_sources: usize,
    connection_tokens: f64,
    connection_token_updated_at: Instant,
}

#[derive(Debug, Default)]
struct IdleList {
    head: Option<SourceKey>,
    tail: Option<SourceKey>,
}

#[derive(Debug, Default)]
struct TrackerState {
    sources: HashMap<SourceKey, SourceState>,
    aggregates: HashMap<AggregateKey, AggregateState>,
    refilled_idle: IdleList,
    limited_idle: IdleList,
}

impl TrackerState {
    fn idle_list_mut(&mut self, class: IdleClass) -> &mut IdleList {
        match class {
            IdleClass::Refilled => &mut self.refilled_idle,
            IdleClass::Limited => &mut self.limited_idle,
        }
    }

    fn remove_idle(&mut self, key: SourceKey) {
        let Some(entry) = self.sources.get(&key) else { return };
        let Some(class) = entry.idle_class else { return };
        let previous = entry.idle_previous;
        let next = entry.idle_next;
        if let Some(previous) = previous {
            if let Some(entry) = self.sources.get_mut(&previous) {
                entry.idle_next = next;
            }
        } else {
            self.idle_list_mut(class).head = next;
        }
        if let Some(next) = next {
            if let Some(entry) = self.sources.get_mut(&next) {
                entry.idle_previous = previous;
            }
        } else {
            self.idle_list_mut(class).tail = previous;
        }
        if let Some(entry) = self.sources.get_mut(&key) {
            entry.idle_class = None;
            entry.idle_previous = None;
            entry.idle_next = None;
        }
    }

    fn push_idle(&mut self, key: SourceKey, class: IdleClass) {
        self.remove_idle(key);
        let previous = self.idle_list_mut(class).tail;
        if let Some(previous) = previous {
            if let Some(entry) = self.sources.get_mut(&previous) {
                entry.idle_next = Some(key);
            }
        } else {
            self.idle_list_mut(class).head = Some(key);
        }
        self.idle_list_mut(class).tail = Some(key);
        if let Some(entry) = self.sources.get_mut(&key) {
            entry.idle_class = Some(class);
            entry.idle_previous = previous;
            entry.idle_next = None;
        }
    }

    fn evict_idle(&mut self, now: Instant, idle_expiry: Duration) -> Option<SourceKey> {
        let refilled = self.refilled_idle.head;
        let limited = self.limited_idle.head;
        let expired = [refilled, limited]
            .into_iter()
            .flatten()
            .filter(|key| {
                self.sources.get(key).is_some_and(|entry| {
                    now.saturating_duration_since(entry.last_seen) >= idle_expiry
                })
            })
            .min_by_key(|key| self.sources.get(key).map(|entry| entry.last_seen));
        let key = expired.or(refilled).or(limited)?;
        self.remove_idle(key);
        self.sources.remove(&key)?;
        let aggregate = key.aggregate();
        let remove_aggregate = self.aggregates.get_mut(&aggregate).is_some_and(|state| {
            state.tracked_sources = state.tracked_sources.saturating_sub(1);
            state.tracked_sources == 0 && state.active_connections == 0
        });
        if remove_aggregate {
            self.aggregates.remove(&aggregate);
        }
        Some(key)
    }
}

#[derive(Debug, Default)]
struct ProxyWindow {
    accepted: usize,
    sources: HashMap<IpAddr, usize>,
    warned: bool,
}

#[derive(Debug)]
pub(crate) struct PublicSourceLimits {
    config: PublicSourceLimitConfig,
    state: Mutex<TrackerState>,
    proxy_window: Mutex<ProxyWindow>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionRefusal {
    SourceLimit,
    AggregateLimit,
    ConnectionRate,
    AggregateConnectionRate,
    TrackingCapacity,
}

impl PublicSourceLimits {
    pub(crate) fn new(config: PublicSourceLimitConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Mutex::new(TrackerState::default()),
            proxy_window: Mutex::new(ProxyWindow::default()),
        })
    }

    pub(crate) fn observe_accepted_source(&self, source: IpAddr) -> bool {
        let mut window =
            self.proxy_window.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if window.warned {
            return false;
        }
        window.accepted += 1;
        *window.sources.entry(source).or_default() += 1;
        if window.accepted < PROXY_WARNING_WINDOW {
            return false;
        }
        let collapsed = window.sources.iter().any(|(source, count)| {
            is_private_or_loopback(*source) && *count * 10 > window.accepted * 9
        });
        window.accepted = 0;
        window.sources.clear();
        if collapsed {
            window.warned = true;
        }
        collapsed
    }

    pub(crate) fn acquire_connection(
        self: &Arc<Self>,
        source: IpAddr,
        now: Instant,
    ) -> Result<SourceConnectionPermit, ConnectionRefusal> {
        if !self.config.enabled {
            return Ok(SourceConnectionPermit { limits: Arc::clone(self), key: None });
        }
        let key = SourceKey::from(source);
        let aggregate = key.aggregate();
        let mut state = self.lock_state();
        if !state.sources.contains_key(&key) {
            if state.sources.len() >= self.config.table_capacity
                && state.evict_idle(now, self.config.idle_expiry).is_none()
            {
                return Err(ConnectionRefusal::TrackingCapacity);
            }
            state.sources.insert(
                key,
                SourceState {
                    active_connections: 0,
                    request_tokens: f64::from(self.config.request_burst),
                    request_token_updated_at: now,
                    connection_tokens: f64::from(self.config.connection_burst),
                    connection_token_updated_at: now,
                    last_seen: now,
                    idle_class: None,
                    idle_previous: None,
                    idle_next: None,
                },
            );
            let aggregate_state = state.aggregates.entry(aggregate).or_insert(AggregateState {
                active_connections: 0,
                tracked_sources: 0,
                connection_tokens: f64::from(self.config.connection_burst),
                connection_token_updated_at: now,
            });
            aggregate_state.tracked_sources += 1;
            state.push_idle(key, IdleClass::Refilled);
        }

        let (source_connections, source_rate_limited) = {
            let entry = state.sources.get_mut(&key).ok_or(ConnectionRefusal::TrackingCapacity)?;
            refill(
                &mut entry.connection_tokens,
                &mut entry.connection_token_updated_at,
                now,
                self.config.connection_rate_per_second,
                self.config.connection_burst,
            );
            entry.last_seen = now;
            let limited = entry.connection_tokens < 1.0;
            if !limited {
                entry.connection_tokens -= 1.0;
            }
            (entry.active_connections, limited)
        };
        if source_rate_limited {
            if source_connections == 0 {
                state.push_idle(key, IdleClass::Limited);
            }
            return Err(ConnectionRefusal::ConnectionRate);
        }
        let aggregate_connections = {
            let aggregate_state =
                state.aggregates.get_mut(&aggregate).ok_or(ConnectionRefusal::TrackingCapacity)?;
            refill(
                &mut aggregate_state.connection_tokens,
                &mut aggregate_state.connection_token_updated_at,
                now,
                self.config.connection_rate_per_second,
                self.config.connection_burst,
            );
            if aggregate_state.connection_tokens < 1.0 {
                return Err(ConnectionRefusal::AggregateConnectionRate);
            }
            aggregate_state.connection_tokens -= 1.0;
            aggregate_state.active_connections
        };
        if source_connections >= self.config.max_connections {
            return Err(ConnectionRefusal::SourceLimit);
        }
        if aggregate_connections >= self.config.aggregate_max_connections {
            if source_connections == 0 {
                state.push_idle(key, IdleClass::Limited);
            }
            return Err(ConnectionRefusal::AggregateLimit);
        }
        state
            .sources
            .get_mut(&key)
            .ok_or(ConnectionRefusal::TrackingCapacity)?
            .active_connections += 1;
        if source_connections == 0 {
            state.remove_idle(key);
        }
        let aggregate_state =
            state.aggregates.get_mut(&aggregate).ok_or(ConnectionRefusal::TrackingCapacity)?;
        aggregate_state.active_connections += 1;
        Ok(SourceConnectionPermit { limits: Arc::clone(self), key: Some(key) })
    }

    fn allow_request(&self, key: SourceKey, now: Instant) -> bool {
        let mut state = self.lock_state();
        let Some(entry) = state.sources.get_mut(&key) else { return false };
        refill(
            &mut entry.request_tokens,
            &mut entry.request_token_updated_at,
            now,
            self.config.request_rate_per_second,
            self.config.request_burst,
        );
        entry.last_seen = now;
        if entry.request_tokens < 1.0 {
            return false;
        }
        entry.request_tokens -= 1.0;
        true
    }

    fn release_connection(&self, key: SourceKey, now: Instant) {
        let mut state = self.lock_state();
        let aggregate = key.aggregate();
        if let Some(aggregate_state) = state.aggregates.get_mut(&aggregate) {
            aggregate_state.active_connections =
                aggregate_state.active_connections.saturating_sub(1);
        }
        let Some(entry) = state.sources.get_mut(&key) else { return };
        entry.active_connections = entry.active_connections.saturating_sub(1);
        if entry.active_connections != 0 {
            return;
        }
        refill(
            &mut entry.request_tokens,
            &mut entry.request_token_updated_at,
            now,
            self.config.request_rate_per_second,
            self.config.request_burst,
        );
        refill(
            &mut entry.connection_tokens,
            &mut entry.connection_token_updated_at,
            now,
            self.config.connection_rate_per_second,
            self.config.connection_burst,
        );
        let refilled = entry.request_tokens >= f64::from(self.config.request_burst)
            && entry.connection_tokens >= f64::from(self.config.connection_burst);
        state.push_idle(key, if refilled { IdleClass::Refilled } else { IdleClass::Limited });
    }

    fn lock_state(&self) -> MutexGuard<'_, TrackerState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn tracked_sources(&self) -> usize {
        self.lock_state().sources.len()
    }

    #[cfg(test)]
    fn tracks_source(&self, source: IpAddr) -> bool {
        self.lock_state().sources.contains_key(&SourceKey::from(source))
    }

    #[cfg(test)]
    fn source_last_seen(&self, source: IpAddr) -> Option<Instant> {
        self.lock_state().sources.get(&SourceKey::from(source)).map(|entry| entry.last_seen)
    }
}

fn refill(tokens: &mut f64, updated_at: &mut Instant, now: Instant, rate: u32, burst: u32) {
    let elapsed = now.saturating_duration_since(*updated_at).as_secs_f64();
    *tokens = (*tokens + elapsed * f64::from(rate)).min(f64::from(burst));
    *updated_at = now;
}

fn is_private_or_loopback(source: IpAddr) -> bool {
    match source {
        IpAddr::V4(source) => source.is_private() || source.is_loopback() || source.is_link_local(),
        IpAddr::V6(source) => {
            source.is_unique_local() || source.is_loopback() || source.is_unicast_link_local()
        }
    }
}

pub(crate) struct SourceConnectionPermit {
    limits: Arc<PublicSourceLimits>,
    key: Option<SourceKey>,
}

impl SourceConnectionPermit {
    pub(crate) fn allow_request(&self, now: Instant) -> bool {
        self.key.is_none_or(|key| self.limits.allow_request(key, now))
    }
}

impl Drop for SourceConnectionPermit {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            self.limits.release_connection(key, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn numeric_settings_are_positive_and_bounded() {
        assert_eq!(parse_setting_u64("SETTING", "1", 8).ok(), Some(1));
        assert_eq!(parse_setting_u64("SETTING", "8", 8).ok(), Some(8));
        for invalid in ["", "0", "9", "-1", "not-a-number", "${UNRESOLVED}"] {
            assert!(parse_setting_u64("SETTING", invalid, 8).is_err());
        }
        assert!(PublicSourceLimitConfig::for_test(1, 1, 64).validate(64).is_err());
        assert!(PublicSourceLimitConfig::for_test(1, 1, 65).validate(64).is_ok());
        assert!(PublicSourceLimitConfig::for_test(1, 1, 1).disabled().validate(64).is_ok());
    }

    #[test]
    fn full_idle_table_evicts_lru_in_constant_time_and_never_locks_out_new_sources()
    -> Result<(), String> {
        let limits = PublicSourceLimits::new(
            PublicSourceLimitConfig::for_test(8, 16, 4096)
                .with_connection_rate(10_000, 10_000)
                .with_idle_expiry(Duration::from_secs(300)),
        );
        let now = Instant::now();
        for subnet in 0..4096_u16 {
            let address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, subnet, 0, 0, 0, 1));
            drop(limits.acquire_connection(address, now).map_err(|error| format!("{error:?}"))?);
        }
        for suffix in 1..=179_u16 {
            let address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, suffix, 0, 0, 0, 1));
            drop(
                limits
                    .acquire_connection(address, now + Duration::from_secs(1))
                    .map_err(|error| format!("{error:?}"))?,
            );
            assert_eq!(limits.tracked_sources(), 4096);
        }
        Ok(())
    }

    #[test]
    fn idle_lru_evicts_the_oldest_source_and_close_does_not_refresh_last_seen() -> Result<(), String>
    {
        let limits = PublicSourceLimits::new(
            PublicSourceLimitConfig::for_test(1, 2, 2).with_connection_rate(1, 1_000),
        );
        let now = Instant::now();
        let first = ip4(192, 0, 2, 1);
        let second = ip4(192, 0, 3, 1);
        let third = ip4(192, 0, 4, 1);

        drop(limits.acquire_connection(first, now).map_err(|error| format!("{error:?}"))?);
        drop(
            limits
                .acquire_connection(second, now + Duration::from_millis(1))
                .map_err(|error| format!("{error:?}"))?,
        );
        let permit = limits
            .acquire_connection(first, now + Duration::from_millis(2))
            .map_err(|error| format!("{error:?}"))?;
        let key = SourceKey::from(first);
        std::mem::forget(permit);
        limits.release_connection(key, now + Duration::from_millis(10));
        assert_eq!(limits.source_last_seen(first), Some(now + Duration::from_millis(2)));

        drop(
            limits
                .acquire_connection(third, now + Duration::from_millis(21))
                .map_err(|error| format!("{error:?}"))?,
        );
        assert!(limits.tracks_source(first));
        assert!(!limits.tracks_source(second));
        assert!(limits.tracks_source(third));
        Ok(())
    }

    #[test]
    fn aggregate_prefix_caps_leave_global_capacity_for_other_networks() -> Result<(), String> {
        let limits = PublicSourceLimits::new(PublicSourceLimitConfig::for_test(8, 16, 128));
        let now = Instant::now();
        let mut held = Vec::new();
        for subnet in 0..8_u16 {
            let source = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, subnet, 0, 0, 0, 1));
            for _ in 0..8 {
                match limits.acquire_connection(source, now) {
                    Ok(permit) => held.push(permit),
                    Err(error) => assert_eq!(error, ConnectionRefusal::AggregateLimit),
                }
            }
        }
        assert_eq!(held.len(), 16);
        held.push(
            limits
                .acquire_connection(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1)), now)
                .map_err(|error| format!("{error:?}"))?,
        );
        Ok(())
    }

    #[test]
    fn source_and_aggregate_connection_open_rates_refill() -> Result<(), String> {
        let limits = PublicSourceLimits::new(
            PublicSourceLimitConfig::for_test(8, 2, 16).with_connection_rate(1, 2),
        );
        let now = Instant::now();
        drop(
            limits
                .acquire_connection(ip4(192, 0, 2, 1), now)
                .map_err(|error| format!("{error:?}"))?,
        );
        drop(
            limits
                .acquire_connection(ip4(192, 0, 2, 1), now)
                .map_err(|error| format!("{error:?}"))?,
        );
        assert_eq!(
            limits.acquire_connection(ip4(192, 0, 2, 1), now).err(),
            Some(ConnectionRefusal::ConnectionRate)
        );
        assert!(limits.acquire_connection(ip4(192, 0, 2, 1), now + Duration::from_secs(1)).is_ok());

        let aggregate_limits = PublicSourceLimits::new(PublicSourceLimitConfig::for_test(8, 2, 16));
        let one = aggregate_limits
            .acquire_connection(ip4(198, 51, 100, 1), now)
            .map_err(|error| format!("{error:?}"))?;
        let two = aggregate_limits
            .acquire_connection(ip4(198, 51, 100, 2), now)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            aggregate_limits.acquire_connection(ip4(198, 51, 100, 3), now).err(),
            Some(ConnectionRefusal::AggregateLimit)
        );
        drop((one, two));

        let ipv4_aggregate_rate = PublicSourceLimits::new(
            PublicSourceLimitConfig::for_test(8, 16, 16).with_connection_rate(1, 2),
        );
        drop(
            ipv4_aggregate_rate
                .acquire_connection(ip4(198, 51, 100, 1), now)
                .map_err(|error| format!("{error:?}"))?,
        );
        drop(
            ipv4_aggregate_rate
                .acquire_connection(ip4(198, 51, 100, 2), now)
                .map_err(|error| format!("{error:?}"))?,
        );
        assert_eq!(
            ipv4_aggregate_rate.acquire_connection(ip4(198, 51, 100, 3), now).err(),
            Some(ConnectionRefusal::AggregateConnectionRate)
        );
        assert!(ipv4_aggregate_rate.acquire_connection(ip4(198, 51, 101, 1), now).is_ok());

        let aggregate_rate = PublicSourceLimits::new(
            PublicSourceLimitConfig::for_test(8, 16, 16).with_connection_rate(1, 2),
        );
        for subnet in 0..2_u16 {
            let source = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 7, subnet, 0, 0, 0, 1));
            drop(
                aggregate_rate
                    .acquire_connection(source, now)
                    .map_err(|error| format!("{error:?}"))?,
            );
        }
        let same_prefix = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 7, 2, 0, 0, 0, 1));
        assert_eq!(
            aggregate_rate.acquire_connection(same_prefix, now).err(),
            Some(ConnectionRefusal::AggregateConnectionRate)
        );
        assert!(
            aggregate_rate
                .acquire_connection(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 8, 0, 0, 0, 0, 1)),
                    now,
                )
                .is_ok()
        );
        assert!(
            aggregate_rate.acquire_connection(same_prefix, now + Duration::from_secs(1)).is_ok()
        );
        Ok(())
    }

    #[test]
    fn request_buckets_are_source_scoped_and_switch_can_disable_limits() -> Result<(), String> {
        let limits = PublicSourceLimits::new(
            PublicSourceLimitConfig::for_test(1, 1, 8).with_request_rate(1, 2),
        );
        let now = Instant::now();
        let permit = limits
            .acquire_connection(ip4(192, 0, 2, 1), now)
            .map_err(|error| format!("{error:?}"))?;
        assert!(permit.allow_request(now));
        assert!(permit.allow_request(now));
        assert!(!permit.allow_request(now));
        assert!(permit.allow_request(now + Duration::from_secs(1)));

        let disabled = PublicSourceLimits::new(
            PublicSourceLimitConfig::for_test(1, 1, 1).with_connection_rate(1, 1).disabled(),
        );
        let permits = (0..64)
            .map(|_| disabled.acquire_connection(ip4(127, 0, 0, 1), now))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("{error:?}"))?;
        assert!(permits.iter().all(|permit| permit.allow_request(now)));
        Ok(())
    }

    #[test]
    fn proxy_warning_detects_collapsed_private_source_once() {
        let limits = PublicSourceLimits::new(PublicSourceLimitConfig::for_test(8, 16, 128));
        for _ in 0..99 {
            assert!(!limits.observe_accepted_source(ip4(10, 0, 2, 2)));
        }
        assert!(limits.observe_accepted_source(ip4(10, 0, 2, 2)));
        for _ in 0..100 {
            assert!(!limits.observe_accepted_source(ip4(10, 0, 2, 2)));
        }

        let boundary = PublicSourceLimits::new(PublicSourceLimitConfig::for_test(8, 16, 128));
        for _ in 0..90 {
            assert!(!boundary.observe_accepted_source(ip4(10, 0, 2, 2)));
        }
        for suffix in 1..=10 {
            assert!(!boundary.observe_accepted_source(ip4(203, 0, 113, suffix)));
        }
    }
}
