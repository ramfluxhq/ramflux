// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded router challenge-issuance windows, independent of authenticated sessions.
use super::{CustodyIssuanceSettings, custody_source_prefixes};
use crate::custody_budget_log::{CustodyAdmissionRefusal, refuse};
use ramflux_protocol::custody::{CustodyRefusal, RetryHint, RetryScope};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(60);
const BUCKET_LIMIT: usize = 8192;
pub(super) struct Bucket {
    pub(super) started: Instant,
    pub(super) count: u32,
}
pub(crate) struct CustodySourceBudget {
    pub(super) buckets: BTreeMap<String, Bucket>,
    settings: CustodyIssuanceSettings,
}
impl Default for CustodySourceBudget {
    fn default() -> Self {
        Self::with_settings(CustodyIssuanceSettings::default())
    }
}
impl CustodySourceBudget {
    pub(crate) fn with_settings(settings: CustodyIssuanceSettings) -> Self {
        Self { buckets: BTreeMap::new(), settings }
    }
    fn retry(scope: RetryScope, started: Instant, tick: Instant) -> RetryHint {
        let remaining = WINDOW.saturating_sub(tick.saturating_duration_since(started));
        RetryHint::new(scope, u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX))
    }
    pub(crate) fn admit(
        &mut self,
        source: IpAddr,
        tick: Instant,
    ) -> Result<(), CustodyAdmissionRefusal> {
        self.buckets.retain(|_, b| tick.saturating_duration_since(b.started) < WINDOW);
        let keys = custody_source_prefixes(source);
        for (n, key) in keys.iter().enumerate() {
            let bucket = self.buckets.get(key);
            let count = bucket.map_or(0, |b| b.count as usize);
            let limit = if n == 0 { self.settings.ip } else { self.settings.prefix };
            if count >= limit {
                let started = bucket.map_or(tick, |b| b.started);
                return Err(refuse(
                    if n == 0 { "source_ip_rate" } else { "source_prefix_rate" },
                    count,
                    limit,
                    CustodyRefusal::Busy,
                    Some(Self::retry(RetryScope::PreAuthSource, started, tick)),
                ));
            }
        }
        let share = keys.last().ok_or(CustodyRefusal::InvalidInput)?;
        let incoming = self.buckets.get(share).map_or(0, |b| b.count as usize);
        // Keep the existing two-challenge reservation, limited by a one-slot operator budget.
        let reservation = self.settings.node.min(2);
        let reserved: usize = self
            .buckets
            .iter()
            .filter(|(k, _)| k.ends_with("/24") || k.ends_with("/48"))
            .map(|(_, b)| (b.count as usize).max(reservation))
            .sum();
        let extra = if incoming == 0 { reservation } else { usize::from(incoming >= reservation) };
        let oldest = self.buckets.values().map(|bucket| bucket.started).min().unwrap_or(tick);
        if reserved + extra > self.settings.node {
            return Err(refuse(
                "source_global_rate",
                reserved,
                self.settings.node,
                CustodyRefusal::Busy,
                Some(Self::retry(RetryScope::NodeCapacity, oldest, tick)),
            ));
        }
        let incoming_keys = keys.iter().filter(|key| !self.buckets.contains_key(*key)).count();
        if self.buckets.len() + incoming_keys > BUCKET_LIMIT {
            return Err(refuse(
                "source_bucket",
                self.buckets.len(),
                BUCKET_LIMIT,
                CustodyRefusal::Busy,
                Some(Self::retry(RetryScope::NodeCapacity, oldest, tick)),
            ));
        }
        for key in keys {
            self.buckets.entry(key).or_insert(Bucket { started: tick, count: 0 }).count += 1;
        }
        Ok(())
    }
}
