// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-local prefix admission; live holders are never imported from durable state.
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Bound the whole unauthenticated custody exchange, independently of idle activity.
/// # Errors
/// Rejects malformed timeout configuration and values outside 100 through 30000 ms.
pub fn custody_auth_timeout() -> Result<Duration, crate::NodeCoreError> {
    let value = std::env::var("RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS").ok();
    let millis = value
        .as_deref()
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| {
            crate::NodeCoreError::ItestHttp("invalid custody authentication timeout".into())
        })?
        .unwrap_or(10_000);
    if !(100..=30_000).contains(&millis) {
        return Err(crate::NodeCoreError::ItestHttp(
            "custody authentication timeout outside 100..30000 ms".into(),
        ));
    }
    Ok(Duration::from_millis(millis))
}
/// Simultaneous IP and network-prefix budgets, normalizing IPv4-mapped IPv6.
#[must_use]
pub fn custody_source_prefixes(source: IpAddr) -> Vec<String> {
    match source {
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => custody_source_prefixes(IpAddr::V4(
            ip.to_ipv4_mapped().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
        )),
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            vec![ip.to_string(), format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])]
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            vec![
                ip.to_string(),
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]),
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]),
            ]
        }
    }
}
struct Bucket {
    started: Instant,
    touched: u64,
    count: u32,
    active: usize,
}
pub(crate) enum BudgetAdmission {
    Admitted,
    Evicted(String),
}
#[derive(Default)]
pub(crate) struct CustodySourceBudget {
    buckets: BTreeMap<String, Bucket>,
    sequence: u64,
}
impl CustodySourceBudget {
    fn room(&mut self) {
        if self.buckets.len() >= 8192
            && let Some(oldest) = self
                .buckets
                .iter()
                .filter(|(key, b)| key.as_str() != "global" && b.active == 0)
                .min_by_key(|(_, b)| b.touched)
                .map(|(k, _)| k.clone())
        {
            self.buckets.remove(&oldest);
        }
    }
    fn charge(&mut self, key: &str, limit: u32, tick: Instant, active_limit: usize) -> bool {
        if !self.buckets.contains_key(key) {
            self.room();
        }
        let bucket = self.buckets.entry(key.into()).or_insert(Bucket {
            started: tick,
            touched: 0,
            count: 0,
            active: 0,
        });
        if tick.saturating_duration_since(bucket.started) >= Duration::from_secs(60) {
            bucket.started = tick;
            bucket.count = 0;
        }
        self.sequence = self.sequence.saturating_add(1);
        bucket.touched = self.sequence;
        if bucket.count >= limit || bucket.active >= active_limit {
            return false;
        }
        bucket.count += 1;
        true
    }
    pub(crate) fn admit(&mut self, source: IpAddr, tick: Instant) -> Option<BudgetAdmission> {
        let prefixes = custody_source_prefixes(source);
        let available = |key: &str, limit: u32| {
            self.buckets.get(key).is_none_or(|bucket| {
                tick.saturating_duration_since(bucket.started) >= Duration::from_secs(60)
                    || bucket.count < limit
            })
        };
        // Refused prefixes cannot churn the source LRU or consume another quota.
        if !prefixes.iter().enumerate().rev().all(|(n, key)| available(key, [32, 128, 256][n])) {
            return None;
        }
        let share = prefixes.last()?;
        let count = |bucket: &Bucket| {
            if tick.saturating_duration_since(bucket.started) >= Duration::from_secs(60) {
                0
            } else {
                bucket.count
            }
        };
        let global: u32 = self
            .buckets
            .iter()
            .filter(|(key, _)| key.ends_with("/24") || key.ends_with("/48"))
            .map(|(_, bucket)| count(bucket))
            .sum();
        let incoming = self.buckets.get(share).map_or(0, count);
        let mut evicted = None;
        if global >= 1024 {
            let heaviest = self
                .buckets
                .iter()
                .filter(|(key, _)| key.ends_with("/24") || key.ends_with("/48"))
                .map(|(key, bucket)| (key.clone(), count(bucket), bucket.touched))
                .filter(|(_, count, _)| *count > incoming)
                .max_by_key(|(_, count, touched)| (*count, std::cmp::Reverse(*touched)));
            let (key, _, _) = heaviest?;
            if let Some(bucket) = self.buckets.get_mut(&key) {
                bucket.count = bucket.count.saturating_sub(1);
            }
            evicted = Some(key);
        }
        for (n, key) in prefixes.iter().enumerate() {
            if !self.charge(key, [32, 128, 256][n], tick, usize::MAX) {
                return None;
            }
        }
        Some(evicted.map_or(BudgetAdmission::Admitted, BudgetAdmission::Evicted))
    }
}
struct ActiveHolder {
    keys: Vec<String>,
    share: String,
    connection: Option<usize>,
    admitted: u64,
    revoked: Arc<AtomicBool>,
    authenticated: Arc<AtomicBool>,
}
struct State {
    sources: CustodySourceBudget,
    connections: BTreeMap<usize, usize>,
    holders: BTreeMap<u64, ActiveHolder>,
    sequence: u64,
}
/// Shared listener admission. An owned permit releases on EOF, cancellation or timeout.
pub struct CustodyIngressLimiter {
    limit: usize,
    state: Mutex<State>,
}
pub struct CustodyIngressPermit {
    limiter: Arc<CustodyIngressLimiter>,
    holder: u64,
    revoked: Arc<AtomicBool>,
    authenticated: Arc<AtomicBool>,
}
impl CustodyIngressLimiter {
    #[must_use]
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            state: Mutex::new(State {
                sources: CustodySourceBudget::default(),
                connections: BTreeMap::new(),
                holders: BTreeMap::new(),
                sequence: 0,
            }),
        })
    }
    /// Reserve at most four streams per QUIC connection and four/eight/sixteen per IP/prefix.
    /// Admission timestamps expire after sixty seconds; disconnect immediately releases holders.
    #[must_use]
    pub fn acquire(
        self: &Arc<Self>,
        source: IpAddr,
        connection: Option<usize>,
        tick: Instant,
    ) -> Option<CustodyIngressPermit> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if connection.is_some_and(|id| state.connections.get(&id).copied().unwrap_or(0) >= 4) {
            return None;
        }
        let keys = custody_source_prefixes(source);
        if keys
            .iter()
            .enumerate()
            .any(|(n, k)| state.sources.buckets.get(k).is_some_and(|b| b.active >= [4, 8, 16][n]))
        {
            return None;
        }
        let share = keys.last()?.clone();
        let evicted_holder = if state.holders.len() >= self.limit {
            let mut counts = BTreeMap::<&str, usize>::new();
            for holder in state
                .holders
                .values()
                .filter(|holder| !holder.authenticated.load(Ordering::Acquire))
            {
                *counts.entry(&holder.share).or_default() += 1;
            }
            let incoming = counts.get(share.as_str()).copied().unwrap_or(0);
            let heavy = counts
                .into_iter()
                .filter(|(_, count)| *count > incoming)
                .max_by_key(|(_, count)| *count)
                .map(|(prefix, _)| prefix)?;
            state
                .holders
                .iter()
                .filter(|(_, holder)| {
                    holder.share == heavy && !holder.authenticated.load(Ordering::Acquire)
                })
                .min_by_key(|(_, holder)| holder.admitted)
                .map(|(id, _)| *id)
        } else {
            None
        };
        state.sources.admit(source, tick)?;
        if let Some(holder) = evicted_holder {
            Self::remove_holder(&mut state, holder, true);
        }
        for key in &keys {
            if let Some(bucket) = state.sources.buckets.get_mut(key) {
                bucket.active += 1;
            }
        }
        if let Some(id) = connection {
            *state.connections.entry(id).or_default() += 1;
        }
        state.sequence = state.sequence.saturating_add(1);
        let holder = state.sequence;
        let revoked = Arc::new(AtomicBool::new(false));
        let authenticated = Arc::new(AtomicBool::new(false));
        state.holders.insert(
            holder,
            ActiveHolder {
                keys,
                share,
                connection,
                admitted: holder,
                revoked: Arc::clone(&revoked),
                authenticated: Arc::clone(&authenticated),
            },
        );
        Some(CustodyIngressPermit { limiter: Arc::clone(self), holder, revoked, authenticated })
    }
    fn remove_holder(state: &mut State, holder: u64, revoke: bool) {
        let Some(holder) = state.holders.remove(&holder) else { return };
        if revoke {
            holder.revoked.store(true, Ordering::Release);
        }
        for key in &holder.keys {
            if let Some(bucket) = state.sources.buckets.get_mut(key) {
                bucket.active = bucket.active.saturating_sub(1);
            }
        }
        if let Some(id) = holder.connection
            && let Some(count) = state.connections.get_mut(&id)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.connections.remove(&id);
            }
        }
    }
}
impl CustodyIngressPermit {
    /// Whether fair-share admission revoked this unauthenticated holder.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
    /// Protect this holder from unauthenticated fair-share eviction after proof succeeds.
    pub fn mark_authenticated(&self) {
        self.authenticated.store(true, Ordering::Release);
    }
}
impl Drop for CustodyIngressPermit {
    fn drop(&mut self) {
        let mut state =
            self.limiter.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        CustodyIngressLimiter::remove_holder(&mut state, self.holder, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prefix_and_quic_limits_release_without_importing_holders()
    -> Result<(), Box<dyn std::error::Error>> {
        let tick = Instant::now();
        let limiter = CustodyIngressLimiter::new(32);
        let held: Vec<_> = (1..=4)
            .filter_map(|n| {
                limiter.acquire(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, n)), Some(1), tick)
            })
            .collect();
        assert_eq!(held.len(), 4);
        assert!(limiter.acquire("198.51.100.1".parse()?, Some(1), tick).is_none());
        assert!(limiter.acquire("198.51.100.1".parse()?, Some(2), tick).is_some());
        drop(held);
        assert!(limiter.acquire("192.0.2.1".parse()?, Some(1), tick).is_some());
        assert_eq!(
            custody_source_prefixes("::ffff:192.0.2.1".parse()?),
            custody_source_prefixes("192.0.2.1".parse()?)
        );
        Ok(())
    }
    #[test]
    fn source_tables_evict_idle_entries_and_aggregate_ipv6()
    -> Result<(), Box<dyn std::error::Error>> {
        let tick = Instant::now();
        let mut budget = CustodySourceBudget::default();
        let admitted = (1..=64)
            .filter(|n| {
                (0..64)
                    .filter(|_| {
                        budget
                            .admit(
                                IpAddr::V6(std::net::Ipv6Addr::new(
                                    0x2001, 0xdb8, 1, 2, 0, 0, 0, *n,
                                )),
                                tick,
                            )
                            .is_some()
                    })
                    .count()
                    > 0
            })
            .count();
        assert!(admitted < 64);
        assert!(budget.admit("203.0.113.1".parse()?, tick + Duration::from_secs(61)).is_some());
        for n in 0..9000 {
            assert!(budget.charge(&format!("test-{n}"), 1, tick, usize::MAX));
        }
        assert!(budget.buckets.len() <= 8192);
        Ok(())
    }
    #[test]
    fn full_pools_revoke_oldest_holder_from_heaviest_prefix_for_a_fresh_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        for (limit, prefixes) in [(32, 4_u8), (64, 8_u8)] {
            let tick = Instant::now();
            let limiter = CustodyIngressLimiter::new(limit);
            let mut held = Vec::new();
            for net in 0..prefixes {
                for host in 1..=2 {
                    for _ in 0..4 {
                        held.push(
                            limiter
                                .acquire(
                                    IpAddr::V4(std::net::Ipv4Addr::new(203, 0, net, host)),
                                    None,
                                    tick,
                                )
                                .ok_or("attacker holder")?,
                        );
                    }
                }
            }
            let honest = limiter
                .acquire("198.51.100.7".parse()?, None, tick)
                .ok_or("fresh prefix refused")?;
            assert!(!honest.is_revoked());
            assert_eq!(held.iter().filter(|permit| permit.is_revoked()).count(), 1);
        }
        Ok(())
    }
    #[test]
    fn fair_share_never_revokes_an_authenticated_holder() -> Result<(), Box<dyn std::error::Error>>
    {
        let tick = Instant::now();
        let limiter = CustodyIngressLimiter::new(4);
        let held: Vec<_> = (1..=4)
            .map(|host| {
                limiter
                    .acquire(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, host)), None, tick)
                    .ok_or("holder")
            })
            .collect::<Result<_, _>>()?;
        held[0].mark_authenticated();
        let honest =
            limiter.acquire("198.51.100.7".parse()?, None, tick).ok_or("fresh prefix refused")?;
        assert!(!honest.is_revoked());
        assert!(!held[0].is_revoked());
        assert_eq!(held[1..].iter().filter(|permit| permit.is_revoked()).count(), 1);
        Ok(())
    }
}
