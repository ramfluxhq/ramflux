// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A small authenticated preflight cache is never a registration or peer-provided live state.
use crate::{AttestedHome, NodeCoreError};
use ramflux_protocol::home_migration::Refusal;
use std::collections::BTreeMap;
const MAX_ENTRIES: usize = 16;
const MAX_BYTES: usize = 8 * 1024 * 1024;
#[derive(Default)]
pub(crate) struct PreflightCache {
    entries: BTreeMap<(String, String), Entry>,
    rates: BTreeMap<String, Rate>,
}
struct Entry {
    home: AttestedHome,
    bytes: usize,
}
struct Rate {
    window_start: u64,
    requests: u8,
    token_time: u64,
    tokens: u8,
}
fn failure(reason: Refusal) -> NodeCoreError {
    NodeCoreError::HomeMigration(reason)
}
impl PreflightCache {
    pub fn charge(&mut self, anchor: &str, now: u64) -> Result<(), NodeCoreError> {
        self.rates.retain(|_, rate| now < rate.window_start.saturating_add(3600));
        if !self.rates.contains_key(anchor) && self.rates.len() >= 1024 {
            return Err(failure(Refusal::CapacityRefused));
        }
        let rate = self.rates.entry(anchor.into()).or_insert(Rate {
            window_start: now,
            requests: 0,
            token_time: now,
            tokens: 2,
        });
        let refill = now.saturating_sub(rate.token_time) / 600;
        if refill != 0 {
            let added =
                u8::try_from(refill.min(2)).map_err(|_| failure(Refusal::CapacityRefused))?;
            rate.tokens = rate.tokens.saturating_add(added).min(2);
            rate.token_time = rate.token_time.saturating_add(refill.saturating_mul(600));
        }
        if rate.requests >= 6 || rate.tokens == 0 {
            return Err(failure(Refusal::RateLimited));
        }
        rate.tokens -= 1;
        rate.requests += 1;
        Ok(())
    }
    pub fn insert(&mut self, home: AttestedHome, now: u64) -> Result<(), NodeCoreError> {
        self.entries.retain(|_, entry| now <= entry.home.attestation.body.expires_at);
        let size = ramflux_protocol::canonical_json_bytes(&home)
            .map_err(|e| NodeCoreError::Redb(e.to_string()))?
            .len();
        let a = &home.attestation.body;
        let key = (a.account_anchor.clone(), a.nonce.clone());
        let previous = self.entries.get(&key).map_or(0, |entry| entry.bytes);
        let bytes = self.entries.values().map(|entry| entry.bytes).sum::<usize>() - previous;
        if (!self.entries.contains_key(&key) && self.entries.len() >= MAX_ENTRIES)
            || size > MAX_BYTES.saturating_sub(bytes)
        {
            return Err(failure(Refusal::CapacityRefused));
        }
        self.entries.insert(key, Entry { home, bytes: size });
        Ok(())
    }
    pub fn get(&self, anchor: &str, nonce: &str, now: u64) -> Result<AttestedHome, NodeCoreError> {
        self.entries
            .get(&(anchor.into(), nonce.into()))
            .filter(|entry| now <= entry.home.attestation.body.expires_at)
            .map(|entry| entry.home.clone())
            .ok_or_else(|| failure(Refusal::EvidenceRequired))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_refill_never_banks_more_than_the_two_request_burst() -> Result<(), NodeCoreError> {
        let mut cache = PreflightCache::default();
        cache.charge("owner", 100)?;
        cache.charge("owner", 100)?;
        assert!(matches!(
            cache.charge("owner", 100),
            Err(NodeCoreError::HomeMigration(Refusal::RateLimited))
        ));
        cache.charge("owner", 3100)?;
        cache.charge("owner", 3100)?;
        assert!(matches!(
            cache.charge("owner", 3100),
            Err(NodeCoreError::HomeMigration(Refusal::RateLimited))
        ));
        Ok(())
    }
    #[test]
    fn authenticated_root_hour_budget_remains_independent_of_burst_refills()
    -> Result<(), NodeCoreError> {
        let mut cache = PreflightCache::default();
        for time in [100, 100, 700, 1300, 1900, 2500] {
            cache.charge("owner", time)?;
        }
        assert!(matches!(
            cache.charge("owner", 3100),
            Err(NodeCoreError::HomeMigration(Refusal::RateLimited))
        ));
        cache.charge("owner", 3700)?;
        Ok(())
    }
}
