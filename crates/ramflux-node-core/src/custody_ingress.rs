// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Hard-capped listener pools; arrivals never revoke existing holders.
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
mod settings;
pub use settings::{
    CustodyPoolSettings, custody_auth_timeout, custody_authenticated_session_limit,
};
const DEFAULT_AUTHENTICATED_SESSIONS_PER_PRINCIPAL: usize = 4;
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
    count: u32,
}
#[derive(Default)]
pub(crate) struct CustodySourceBudget {
    buckets: BTreeMap<String, Bucket>,
}
impl CustodySourceBudget {
    pub(crate) fn admit(&mut self, source: IpAddr, tick: Instant) -> Option<()> {
        self.buckets
            .retain(|_, b| tick.saturating_duration_since(b.started) < Duration::from_secs(60));
        let keys = custody_source_prefixes(source);
        if keys
            .iter()
            .enumerate()
            .any(|(n, k)| self.buckets.get(k).is_some_and(|b| b.count >= [16, 32, 32][n]))
        {
            return None;
        }
        let share = keys.last()?;
        let incoming = self.buckets.get(share).map_or(0, |b| b.count);
        // Reserve the second challenge when admitting a new prefix. Neither reservation nor
        // live challenges can be retired by another prefix. Refuse new work at the hard bound.
        let reserved: u32 = self
            .buckets
            .iter()
            .filter(|(k, _)| k.ends_with("/24") || k.ends_with("/48"))
            .map(|(_, b)| b.count.max(2))
            .sum();
        let extra = if incoming == 0 { 2 } else { u32::from(incoming != 1) };
        if reserved + extra > 1024
            || self.buckets.len() + keys.iter().filter(|k| !self.buckets.contains_key(*k)).count()
                > 8192
        {
            return None;
        }
        for key in keys {
            let b = self.buckets.entry(key).or_insert(Bucket { started: tick, count: 0 });
            b.count += 1;
        }
        Some(())
    }
}
struct ActiveHolder {
    keys: Vec<String>,
    share: String,
    connection: Option<usize>,
    principal: Option<String>,
    deadline: Instant,
    revoked: Arc<AtomicBool>,
    revocation: Arc<Notify>,
}
#[derive(Default)]
struct State {
    connections: BTreeMap<usize, usize>,
    holders: BTreeMap<u64, ActiveHolder>,
    sequence: u64,
    handshakes: usize,
    authenticated: usize,
}
/// Owned permits keep both pools within their ceilings until disconnect or expiry.
pub struct CustodyIngressLimiter {
    handshake_limit: usize,
    authenticated_limit: usize,
    authenticated_per_principal: usize,
    auth_timeout: Duration,
    state: Mutex<State>,
}
pub struct CustodyIngressPermit {
    limiter: Arc<CustodyIngressLimiter>,
    holder: u64,
    revoked: Arc<AtomicBool>,
    revocation: Arc<Notify>,
    deadline: Instant,
}
impl CustodyIngressLimiter {
    #[must_use]
    pub fn new(limit: usize) -> Arc<Self> {
        Self::with_pools(
            limit,
            limit,
            DEFAULT_AUTHENTICATED_SESSIONS_PER_PRINCIPAL,
            Duration::from_secs(10),
        )
    }
    #[must_use]
    pub fn with_authenticated_limit(limit: usize, principal: usize) -> Arc<Self> {
        Self::with_pools(limit, limit, principal, Duration::from_secs(10))
    }
    #[must_use]
    pub fn with_pools(
        handshakes: usize,
        authenticated: usize,
        principal: usize,
        timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            handshake_limit: handshakes,
            authenticated_limit: authenticated,
            authenticated_per_principal: principal,
            auth_timeout: timeout,
            state: Mutex::new(State::default()),
        })
    }
    fn prune(state: &mut State, tick: Instant) {
        let expired: Vec<_> =
            state.holders.iter().filter(|(_, h)| h.deadline <= tick).map(|(id, _)| *id).collect();
        for id in expired {
            Self::remove_holder(state, id);
        }
    }
    /// Reserve H on entry to the custody protocol, at most four handshakes per IP and prefix.
    /// Listener-wide source limits include both pools. IPv4-mapped addresses use IPv4 shares.
    #[must_use]
    pub fn acquire(
        self: &Arc<Self>,
        source: IpAddr,
        connection: Option<usize>,
        tick: Instant,
    ) -> Option<CustodyIngressPermit> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::prune(&mut state, tick);
        if state.handshakes >= self.handshake_limit
            || connection.is_some_and(|id| state.connections.get(&id).copied().unwrap_or(0) >= 4)
        {
            return None;
        }
        let keys = custody_source_prefixes(source);
        if keys.iter().enumerate().any(|(n, key)| {
            let total = state.holders.values().filter(|holder| holder.keys.contains(key)).count();
            let handshakes = state
                .holders
                .values()
                .filter(|holder| holder.principal.is_none() && holder.keys.contains(key))
                .count();
            total >= [4, 8, 16][n] || handshakes >= 4
        }) {
            return None;
        }
        let share = keys.last()?.clone();
        if let Some(id) = connection {
            *state.connections.entry(id).or_default() += 1;
        }
        state.sequence = state.sequence.checked_add(1)?;
        let holder = state.sequence;
        let revoked = Arc::new(AtomicBool::new(false));
        let revocation = Arc::new(Notify::new());
        let deadline = tick + self.auth_timeout;
        state.holders.insert(
            holder,
            ActiveHolder {
                keys,
                share,
                connection,
                principal: None,
                deadline,
                revoked: Arc::clone(&revoked),
                revocation: Arc::clone(&revocation),
            },
        );
        state.handshakes += 1;
        Some(CustodyIngressPermit {
            limiter: Arc::clone(self),
            holder,
            revoked,
            revocation,
            deadline,
        })
    }
    fn remove_holder(state: &mut State, id: u64) {
        let Some(h) = state.holders.remove(&id) else { return };
        h.revoked.store(true, Ordering::Release);
        h.revocation.notify_one();
        if h.principal.is_some() {
            state.authenticated -= 1;
        } else {
            state.handshakes -= 1;
        }
        if let Some(id) = h.connection
            && let Some(n) = state.connections.get_mut(&id)
        {
            *n -= 1;
            if *n == 0 {
                state.connections.remove(&id);
            }
        }
    }
}
impl CustodyIngressPermit {
    #[must_use]
    pub fn auth_deadline(&self) -> Instant {
        self.deadline
    }
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
    /// Fence a holder before disconnect cleanup; queued work cannot recreate its grant.
    pub fn revoke(&self) {
        let mut s = self.limiter.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        CustodyIngressLimiter::remove_holder(&mut s, self.holder);
    }
    /// Move H to A, checking both ceilings and ownership under one critical section.
    #[must_use]
    pub fn mark_authenticated(&self, principal: &str) -> bool {
        self.grant(principal, || ()).is_some()
    }
    /// Execute a session grant under the same lock as the H-to-A transition and revocation.
    /// The callback must not re-enter this limiter.
    pub fn grant<T>(&self, principal: &str, grant: impl FnOnce() -> T) -> Option<T> {
        self.try_grant(principal, || Ok::<T, std::convert::Infallible>(grant())).map(|r| match r {
            Ok(value) => value,
            Err(never) => match never {},
        })
    }
    /// Grant only a successful operation; failed validation leaves the holder in H.
    /// Returns `None` when the holder is revoked, expired or has no authenticated capacity.
    /// # Errors
    /// Propagates the callback error without moving the holder between pools.
    pub fn try_grant<T, E>(
        &self,
        principal: &str,
        grant: impl FnOnce() -> Result<T, E>,
    ) -> Option<Result<T, E>> {
        let mut s = self.limiter.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        CustodyIngressLimiter::prune(&mut s, Instant::now());
        let h = s.holders.get(&self.holder)?;
        if self.is_revoked() || principal.is_empty() || principal.len() > 512 {
            return None;
        }
        if let Some(current) = &h.principal {
            return (current == principal).then(grant);
        }
        if s.authenticated >= self.limiter.authenticated_limit
            || s.holders.values().filter(|h| h.principal.as_deref() == Some(principal)).count()
                >= self.limiter.authenticated_per_principal
            || s.holders
                .values()
                .filter(|other| other.principal.is_some() && other.share == h.share)
                .count()
                >= 16
        {
            return None;
        }
        let result = grant();
        if result.is_err() {
            return Some(result);
        }
        let h = s.holders.get_mut(&self.holder)?;
        h.principal = Some(principal.to_owned());
        h.deadline = Instant::now() + Duration::from_mins(15);
        s.handshakes -= 1;
        s.authenticated += 1;
        Some(result)
    }
    pub async fn revoked(&self) {
        loop {
            if self.is_revoked() {
                return;
            }
            self.revocation.notified().await;
        }
    }
}
impl Drop for CustodyIngressPermit {
    fn drop(&mut self) {
        self.revoke();
    }
}
#[cfg(test)]
mod tests;
