// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node-wide, authenticated principal lookup admission with bounded source/account LRU tables.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
/// Constructed by a gateway from its authenticated session and actual socket peer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrincipalLookupRequest {
    pub principal_id: String,
    pub session_id: String,
    pub requester_device_id: String,
    pub target_delivery_id: String,
    pub gateway_id: String,
    pub source: IpAddr,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Window {
    started: u64,
    touched: u64,
    count: u32,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Buckets {
    windows: BTreeMap<String, Window>,
    order: BTreeSet<(u64, String)>,
    sequence: u64,
}
impl Buckets {
    fn charge(&mut self, key: String, limit: u32, capacity: usize, now: u64) -> bool {
        let mut window = if let Some(w) = self.windows.remove(&key) {
            self.order.remove(&(w.touched, key.clone()));
            w
        } else {
            if self.windows.len() >= capacity
                && let Some((_, oldest)) = self.order.pop_first()
            {
                self.windows.remove(&oldest);
            }
            Window { started: now, touched: 0, count: 0 }
        };
        if now.saturating_sub(window.started) >= 60 {
            window.started = now;
            window.count = 0;
        }
        self.sequence = self.sequence.wrapping_add(1);
        window.touched = self.sequence;
        let admitted = window.count < limit;
        if admitted {
            window.count += 1;
        }
        self.order.insert((window.touched, key.clone()));
        self.windows.insert(key, window);
        admitted
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PrincipalLookupLimiter {
    sources: Buckets,
    accounts: Buckets,
}
impl PrincipalLookupLimiter {
    pub(crate) fn admit(&mut self, account: &str, source: IpAddr, now: u64) -> bool {
        self.sources.charge(source_key(source), 120, 4096, now)
            && self.accounts.charge(account.to_owned(), 60, 4096, now)
    }
}
fn source_key(source: IpAddr) -> String {
    match source {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || {
                let s = ip.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            },
            |ip| ip.to_string(),
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_and_source_limits_are_independent_and_expire_without_clock_rewind()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut limiter = PrincipalLookupLimiter::default();
        let source = "127.0.0.1".parse()?;
        for _ in 0..60 {
            assert!(limiter.admit("alice", source, 100));
        }
        assert!(!limiter.admit("alice", source, 100));
        assert!(limiter.admit("bob", source, 100));
        for _ in 0..58 {
            assert!(limiter.admit("bob", source, 100));
        }
        assert!(!limiter.admit("carol", source, 100));
        assert!(!limiter.admit("alice", source, 1));
        assert!(limiter.admit("alice", source, 160));
        Ok(())
    }
    #[test]
    fn lookup_lru_tables_and_ipv6_prefix_quotas_remain_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut buckets = Buckets::default();
        for n in 0..10000 {
            assert!(buckets.charge(n.to_string(), 1, 32, 100));
            assert!(buckets.windows.len() <= 32);
            assert_eq!(buckets.windows.len(), buckets.order.len());
        }
        assert_eq!(source_key("::ffff:127.0.0.1".parse()?), source_key("127.0.0.1".parse()?));
        assert_eq!(
            source_key("2001:db8:1:2::1".parse()?),
            source_key("2001:db8:1:2::ffff".parse()?)
        );
        Ok(())
    }
}
