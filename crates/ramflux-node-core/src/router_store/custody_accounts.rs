// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic per-account authority rows and durable bounded new-principal admission receipts.
use crate::{
    IdentityRegistry, NodeCoreError, RouterRedbStore, custody_authority::CustodyAccountState,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_accounts_v3");
const BUDGETS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("custody_publication_budgets_v1");
const MAX_ACCOUNTS: u64 = 65_536;
fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
fn capacity() -> NodeCoreError {
    NodeCoreError::Capacity { resource: "new custody principals" }
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Budget {
    day: u64,
    daily: u64,
    minute: u64,
    burst: u64,
    total: u64,
}
impl Budget {
    fn charge(
        &mut self,
        now: u64,
        daily_limit: u64,
        minute_limit: u64,
        global: bool,
    ) -> Result<(), NodeCoreError> {
        let day = now / 86_400;
        let minute = now / 60;
        // Clock rollback cannot reset the durable window or grant a fresh budget.
        if day < self.day || minute < self.minute {
            return Err(capacity());
        }
        if day > self.day {
            self.day = day;
            self.daily = 0;
        }
        if minute > self.minute {
            self.minute = minute;
            self.burst = 0;
        }
        if self.daily >= daily_limit
            || self.burst >= minute_limit
            || (global && self.total >= MAX_ACCOUNTS)
        {
            return Err(capacity());
        }
        self.daily += 1;
        self.burst += 1;
        self.total += 1;
        Ok(())
    }
}
impl RouterRedbStore {
    fn custody_budget_keys(&self, source: IpAddr) -> Vec<(String, u64, u64, bool)> {
        const FAIR_PREFIXES: u64 = 32;
        let fair_daily = self.custody_new_principals_per_day.div_ceil(FAIR_PREFIXES).max(1);
        let mut keys = vec![(
            "global".to_owned(),
            self.custody_new_principals_per_day,
            self.custody_new_principals_per_minute,
            true,
        )];
        keys.extend(crate::custody_source_prefixes(source).into_iter().skip(1).enumerate().map(
            |(n, key)| {
                let prior_daily = if n == 0 { 8 } else { 32 };
                (key, prior_daily.min(fair_daily), self.custody_new_principals_per_minute, false)
            },
        ));
        keys
    }
    pub(crate) fn check_custody_new_principal_budget(
        &self,
        source: IpAddr,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_read().map_err(error)?;
        let table = match tx.open_table(BUDGETS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
            Err(e) => return Err(error(e)),
        };
        for (key, daily_limit, minute_limit, global) in self.custody_budget_keys(source) {
            let mut budget: Budget = table
                .get(key.as_str())
                .map_err(error)?
                .map(|v| serde_json::from_slice(v.value()).map_err(error))
                .transpose()?
                .unwrap_or_default();
            budget.charge(now, daily_limit, minute_limit, global)?;
        }
        Ok(())
    }

    pub(crate) fn record_custody_account(
        &self,
        anchor: &str,
        state: &CustodyAccountState,
        is_new: bool,
        source: IpAddr,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let bytes = serde_json::to_vec(state).map_err(error)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(NodeCoreError::Capacity { resource: "custody account authority bytes" });
        }
        self.prune_custody_history(now)?;
        let tx = self.db.begin_write().map_err(error)?;
        {
            let mut accounts = tx.open_table(ACCOUNTS).map_err(error)?;
            if is_new {
                let mut budgets = tx.open_table(BUDGETS).map_err(error)?;
                for (key, daily_limit, minute_limit, global) in self.custody_budget_keys(source) {
                    let mut budget: Budget = budgets
                        .get(key.as_str())
                        .map_err(error)?
                        .map(|v| serde_json::from_slice(v.value()).map_err(error))
                        .transpose()?
                        .unwrap_or_default();
                    budget.charge(now, daily_limit, minute_limit, global)?;
                    let encoded = serde_json::to_vec(&budget).map_err(error)?;
                    budgets.insert(key.as_str(), encoded.as_slice()).map_err(error)?;
                }
                // Configured admissions create at most two prefix rows each, retained for two days.
                // No unexpired receipt is evicted to make room for another publisher.
                let expired: Vec<String> = budgets
                    .iter()
                    .map_err(error)?
                    .map(|entry| {
                        let (key, value) = entry.map_err(error)?;
                        let budget: Budget =
                            serde_json::from_slice(value.value()).map_err(error)?;
                        Ok((key.value().to_owned(), budget.day))
                    })
                    .collect::<Result<Vec<_>, NodeCoreError>>()?
                    .into_iter()
                    .filter(|(key, day)| key != "global" && day.saturating_add(2) <= now / 86_400)
                    .map(|(key, _)| key)
                    .collect();
                for key in expired {
                    budgets.remove(key.as_str()).map_err(error)?;
                }
            }
            if let Some(previous) = accounts.get(anchor).map_err(error)? {
                let previous: CustodyAccountState =
                    serde_json::from_slice(previous.value()).map_err(error)?;
                super::custody_history::retain(
                    &tx,
                    &previous.publication,
                    &state.publication,
                    now,
                )?;
            }
            accounts.insert(anchor, bytes.as_slice()).map_err(error)?;
        }
        tx.commit().map_err(error)?;
        self.custody_publication_writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    /// Number of committed per-account custody updates in this store process.
    #[must_use]
    pub fn custody_publication_write_count(&self) -> u64 {
        self.custody_publication_writes.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub(crate) fn load_custody_accounts(
        &self,
        registry: &mut IdentityRegistry,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_read().map_err(error)?;
        let accounts = match tx.open_table(ACCOUNTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
            Err(e) => return Err(error(e)),
        };
        for entry in accounts.iter().map_err(error)? {
            let (anchor, bytes) = entry.map_err(error)?;
            let state: CustodyAccountState =
                serde_json::from_slice(bytes.value()).map_err(error)?;
            registry.apply_custody_account(anchor.value().into(), state)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_budget_retains_daily_floor_on_restart_and_clock_rollback()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut budget = Budget::default();
        for _ in 0..8 {
            budget.charge(86_400, 8, 8, false)?;
        }
        let mut restored: Budget = serde_json::from_slice(&serde_json::to_vec(&budget)?)?;
        assert!(restored.charge(86_401, 8, 8, false).is_err());
        assert!(restored.charge(1, 8, 8, false).is_err());
        restored.charge(172_800, 8, 8, false)?;
        Ok(())
    }
    #[test]
    fn custody_budget_configuration_refuses_invalid_or_out_of_range_values() {
        assert_eq!(super::super::custody_budget_value("BUDGET", None, 16, 1, 32).ok(), Some(16));
        assert_eq!(
            super::super::custody_budget_value("BUDGET", Some("32"), 16, 1, 32).ok(),
            Some(32)
        );
        for invalid in ["", "0", "33", "many"] {
            assert!(
                super::super::custody_budget_value("BUDGET", Some(invalid), 16, 1, 32).is_err(),
                "accepted {invalid}"
            );
        }
    }
}
