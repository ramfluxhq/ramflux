// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-authentication listener bounds and optional authenticated node capacity; no eviction.
use crate::custody_budget_log::{CustodyAdmissionRefusal, node_retry, refuse};
use ramflux_protocol::custody::{CustodyRefusal, RetryHint, RetryScope};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
mod settings;
pub use settings::{CustodyIssuanceSettings, CustodyPoolSettings, custody_auth_timeout};
mod source_budget;
pub(crate) use source_budget::CustodySourceBudget;
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

struct ActiveHolder {
    keys: Vec<String>,
    connection: Option<usize>,
    principal: Option<String>,
    granting: bool,
    deadline: Instant,
    revoked: Arc<AtomicBool>,
    revocation: Arc<Notify>,
}
#[derive(Default)]
struct PreAuthBudget {
    count: usize,
    deadlines: BTreeSet<(Instant, u64)>,
}
impl PreAuthBudget {
    fn insert(&mut self, deadline: Instant, holder: u64) {
        self.count += 1;
        self.deadlines.insert((deadline, holder));
    }
    fn remove(&mut self, deadline: Instant, holder: u64) {
        self.count -= 1;
        self.deadlines.remove(&(deadline, holder));
    }
}
#[derive(Default)]
struct State {
    connections: BTreeMap<usize, PreAuthBudget>,
    sources: BTreeMap<String, PreAuthBudget>,
    preauth_deadlines: BTreeSet<(Instant, u64)>,
    deadlines: BTreeSet<(Instant, u64)>,
    holders: crate::custody_population_map::PopulationMap<u64, ActiveHolder>,
    sequence: u64,
    handshakes: usize,
    authenticated: usize,
    #[cfg(test)]
    grant_lock_holds: Vec<Duration>,
}
/// Owned permits bound pre-authentication work; authenticated capacity is optional.
pub struct CustodyIngressLimiter {
    handshake_limit: usize,
    authenticated_limit: Option<usize>,
    preauth_per_source: usize,
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
    pub fn new(handshakes: usize) -> Arc<Self> {
        Self::with_pools(handshakes, None, 4, Duration::from_secs(10))
    }
    #[must_use]
    pub fn with_authenticated_limit(handshakes: usize, authenticated: usize) -> Arc<Self> {
        Self::with_pools(handshakes, Some(authenticated), 4, Duration::from_secs(10))
    }
    #[must_use]
    pub fn with_pools(
        handshakes: usize,
        authenticated: Option<usize>,
        preauth_per_source: usize,
        timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            handshake_limit: handshakes,
            authenticated_limit: authenticated,
            preauth_per_source,
            auth_timeout: timeout,
            state: Mutex::new(State::default()),
        })
    }
    #[cfg(test)]
    pub(crate) fn operation_count(&self, reset: bool) -> usize {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).holders.visits(reset)
    }
    #[cfg(test)]
    pub(crate) fn grant_lock_hold_times(&self) -> Vec<Duration> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .grant_lock_holds
            .clone()
    }
    fn prune(state: &mut State, tick: Instant) {
        while let Some((deadline, holder)) = state.deadlines.first().copied() {
            if deadline > tick {
                break;
            }
            state.deadlines.pop_first();
            Self::remove_holder(state, holder);
        }
    }
    fn remaining(
        &self,
        scope: RetryScope,
        first: Option<&(Instant, u64)>,
        tick: Instant,
    ) -> RetryHint {
        let deadline = first.map_or(tick + self.auth_timeout, |(deadline, _)| *deadline);
        RetryHint::new(
            scope,
            u32::try_from(deadline.saturating_duration_since(tick).as_millis()).unwrap_or(u32::MAX),
        )
    }
    /// Reserve pre-authentication capacity only; authenticated holders do not consume it.
    /// # Errors
    /// Returns the refused budget's server retry hint without displacing any holder.
    pub fn acquire(
        self: &Arc<Self>,
        source: IpAddr,
        connection: Option<usize>,
        tick: Instant,
    ) -> Result<CustodyIngressPermit, CustodyAdmissionRefusal> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::prune(&mut state, tick);
        if state.handshakes >= self.handshake_limit {
            return Err(refuse(
                "handshake",
                state.handshakes,
                self.handshake_limit,
                CustodyRefusal::Busy,
                Some(self.remaining(
                    RetryScope::NodeCapacity,
                    state.preauth_deadlines.first(),
                    tick,
                )),
            ));
        }
        if let Some(budget) = connection.and_then(|id| state.connections.get(&id))
            && budget.count >= 4
        {
            return Err(refuse(
                "connection_stream",
                budget.count,
                4,
                CustodyRefusal::Busy,
                Some(self.remaining(RetryScope::PreAuthSource, budget.deadlines.first(), tick)),
            ));
        }
        let keys = custody_source_prefixes(source);
        for key in &keys {
            if let Some(budget) = state.sources.get(key)
                && budget.count >= self.preauth_per_source
            {
                return Err(refuse(
                    "listener_source_handshake",
                    budget.count,
                    self.preauth_per_source,
                    CustodyRefusal::Busy,
                    Some(self.remaining(RetryScope::PreAuthSource, budget.deadlines.first(), tick)),
                ));
            }
        }
        state.sequence = state.sequence.checked_add(1).ok_or_else(|| {
            tracing::warn!(
                budget = "holder_sequence",
                count = state.sequence,
                limit = u64::MAX,
                refusal = "Busy",
                "custody admission refused"
            );
            CustodyAdmissionRefusal { code: CustodyRefusal::Busy, retry: Some(node_retry()) }
        })?;
        let holder = state.sequence;
        let revoked = Arc::new(AtomicBool::new(false));
        let revocation = Arc::new(Notify::new());
        let deadline = tick + self.auth_timeout;
        if let Some(id) = connection {
            state.connections.entry(id).or_default().insert(deadline, holder);
        }
        for key in &keys {
            state.sources.entry(key.clone()).or_default().insert(deadline, holder);
        }
        state.preauth_deadlines.insert((deadline, holder));
        state.deadlines.insert((deadline, holder));
        state.holders.insert(
            holder,
            ActiveHolder {
                keys,
                connection,
                principal: None,
                granting: false,
                deadline,
                revoked: Arc::clone(&revoked),
                revocation: Arc::clone(&revocation),
            },
        );
        state.handshakes += 1;
        Ok(CustodyIngressPermit {
            limiter: Arc::clone(self),
            holder,
            revoked,
            revocation,
            deadline,
        })
    }
    fn untrack_preauth(state: &mut State, id: u64, h: &ActiveHolder) {
        state.handshakes -= 1;
        state.preauth_deadlines.remove(&(h.deadline, id));
        for key in &h.keys {
            if let Some(budget) = state.sources.get_mut(key) {
                budget.remove(h.deadline, id);
                if budget.count == 0 {
                    state.sources.remove(key);
                }
            }
        }
        if let Some(connection) = h.connection
            && let Some(budget) = state.connections.get_mut(&connection)
        {
            budget.remove(h.deadline, id);
            if budget.count == 0 {
                state.connections.remove(&connection);
            }
        }
    }
    fn remove_holder(state: &mut State, id: u64) {
        let Some(h) = state.holders.remove(&id) else { return };
        state.deadlines.remove(&(h.deadline, id));
        h.revoked.store(true, Ordering::Release);
        h.revocation.notify_one();
        if h.principal.is_some() {
            state.authenticated -= 1;
        } else {
            Self::untrack_preauth(state, id, &h);
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
        let mut state =
            self.limiter.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        CustodyIngressLimiter::remove_holder(&mut state, self.holder);
    }
    /// # Errors
    /// Returns a typed refusal for a missing holder or finite authenticated node capacity.
    pub fn mark_authenticated(&self, principal: &str) -> Result<(), CustodyAdmissionRefusal> {
        self.grant(principal, || ())
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

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
pub(crate) mod hint_tests;

mod grant;
#[cfg(test)]
mod grant_tests;
