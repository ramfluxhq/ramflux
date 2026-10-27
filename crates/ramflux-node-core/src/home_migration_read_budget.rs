// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated read quotas are transient and bounded independently of custody registry allocation.
use crate::{MigrationNode, NodeCoreError};
use ramflux_protocol::home_migration::Refusal;
use std::collections::{BTreeMap, VecDeque};
#[derive(Default)]
pub(crate) struct ReadBudget(BTreeMap<String, Bucket>);
struct Bucket {
    token_time: u64,
    tokens: u8,
    accepted: VecDeque<u64>,
}
impl MigrationNode {
    pub(crate) fn charge_migration_read(
        &self,
        requester: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.read_budget
            .lock()
            .map_err(|e| NodeCoreError::Redb(e.to_string()))?
            .charge(requester, now)
    }
}
impl ReadBudget {
    fn charge(&mut self, requester: &str, now: u64) -> Result<(), NodeCoreError> {
        self.0.retain(|_, b| b.accepted.back().is_some_and(|last| now < last.saturating_add(60)));
        if !self.0.contains_key(requester) && self.0.len() >= 1024 {
            return Err(refuse());
        }
        let b = self.0.entry(requester.into()).or_insert(Bucket {
            token_time: now,
            tokens: 10,
            accepted: VecDeque::new(),
        });
        while b.accepted.front().is_some_and(|first| now >= first.saturating_add(60)) {
            b.accepted.pop_front();
        }
        let elapsed = now.saturating_sub(b.token_time);
        if elapsed != 0 {
            let added = u8::try_from(elapsed.min(10)).map_err(|_| refuse())?;
            b.tokens = b.tokens.saturating_add(added).min(10);
            b.token_time = now;
        }
        if b.tokens == 0 || b.accepted.len() >= 60 {
            return Err(refuse());
        }
        b.tokens -= 1;
        b.accepted.push_back(now);
        Ok(())
    }
}
fn refuse() -> NodeCoreError {
    NodeCoreError::HomeMigration(Refusal::RateLimited)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_read_burst_and_sliding_minute_limits_are_independent() -> Result<(), NodeCoreError> {
        let mut budget = ReadBudget::default();
        for _ in 0..10 {
            budget.charge("owner", 100)?;
        }
        assert!(budget.charge("owner", 100).is_err());
        for now in 101..151 {
            budget.charge("owner", now)?;
        }
        assert!(budget.charge("owner", 151).is_err());
        budget.charge("another-owner", 151)?;
        budget.charge("owner", 160)?;
        Ok(())
    }
}
