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
            tracing::warn!(
                scope = if global { "global" } else { "prefix" },
                budget = "publication_clock",
                count = self.minute,
                limit = minute,
                refusal = "Capacity",
                "custody admission refused"
            );
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
        for (budget, count, limit) in [
            ("publication_daily", self.daily, daily_limit),
            ("publication_minute", self.burst, minute_limit),
            ("publication_total", self.total, if global { MAX_ACCOUNTS } else { u64::MAX }),
        ] {
            if count >= limit {
                tracing::warn!(
                    scope = if global { "global" } else { "prefix" },
                    budget,
                    count,
                    limit,
                    refusal = "Capacity",
                    "custody admission refused"
                );
                return Err(capacity());
            }
        }
        self.daily += 1;
        self.burst += 1;
        self.total += 1;
        Ok(())
    }
}
/// Read-only operator view of one durable admission window.
#[derive(Debug, Serialize)]
pub struct CustodyPublicationBudgetRow {
    pub scope: &'static str,
    pub prefix: Option<String>,
    pub budget: &'static str,
    pub count: u64,
    pub limit: u64,
    /// Unix seconds in UTC; `None` denotes the non-expiring global account ceiling.
    pub reset_at: Option<u64>,
}

impl RouterRedbStore {
    fn custody_budget_keys(&self, source: IpAddr) -> Vec<(String, u64, u64, bool)> {
        let mut keys = vec![(
            "global".to_owned(),
            self.custody_new_principals_per_day,
            self.custody_new_principals_per_minute,
            true,
        )];
        keys.extend(crate::custody_source_prefixes(source).into_iter().skip(1).enumerate().map(
            |(n, key)| {
                let daily = self.custody_prefix_daily_limit(n != 0);
                (key, daily, self.custody_new_principals_per_minute, false)
            },
        ));
        keys
    }
    fn custody_prefix_daily_limit(&self, wider: bool) -> u64 {
        super::custody_budget_policy::prefix_daily_limit(
            self.custody_new_principals_per_day,
            self.custody_new_principals_per_prefix_per_day,
            wider,
        )
    }

    /// Inspect durable publication receipts without charging, resetting, or pruning them.
    /// Counts refer to the retained window; a past reset time means its count has expired.
    /// Prefix identifiers are node-keyed truncated hashes, never addresses.
    ///
    /// # Errors
    /// Returns an error if durable receipts cannot be read or decoded.
    pub fn custody_publication_budgets(
        &self,
    ) -> Result<Vec<CustodyPublicationBudgetRow>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(error)?;
        let table = match tx.open_table(BUDGETS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(error(e)),
        };
        let mut rows = Vec::new();
        for entry in table.iter().map_err(error)? {
            let (key, value) = entry.map_err(error)?;
            let key = key.value();
            let receipt: Budget = serde_json::from_slice(value.value()).map_err(error)?;
            let global = key == "global";
            let scope = if global { "global" } else { "prefix" };
            let prefix =
                (!global).then(|| crate::source_ip_hash(key).chars().take(16).collect::<String>());
            let daily_limit = if global {
                self.custody_new_principals_per_day
            } else {
                self.custody_prefix_daily_limit(key.ends_with("/48"))
            };
            for (budget, count, limit, reset_at) in [
                (
                    "publication_daily",
                    receipt.daily,
                    daily_limit,
                    Some(receipt.day.saturating_add(1).saturating_mul(86_400)),
                ),
                (
                    "publication_minute",
                    receipt.burst,
                    self.custody_new_principals_per_minute,
                    Some(receipt.minute.saturating_add(1).saturating_mul(60)),
                ),
            ] {
                rows.push(CustodyPublicationBudgetRow {
                    scope,
                    prefix: prefix.clone(),
                    budget,
                    count,
                    limit,
                    reset_at,
                });
            }
            if global {
                rows.push(CustodyPublicationBudgetRow {
                    scope,
                    prefix,
                    budget: "publication_total",
                    count: receipt.total,
                    limit: MAX_ACCOUNTS,
                    reset_at: None,
                });
            }
        }
        Ok(rows)
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
            crate::custody_budget_log::refuse(
                "authority_bytes",
                bytes.len(),
                16 * 1024 * 1024,
                ramflux_protocol::custody::CustodyRefusal::Capacity,
            );
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
    fn configured_prefix_limits_cover_ipv4_and_ipv6_source_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "rf-custody-policy-{}.redb",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        {
            let mut store = RouterRedbStore::open_without_wal(&path)?;
            for source in ["192.0.2.9", "2001:db8:1:2::9"] {
                let keys = store.custody_budget_keys(source.parse()?);
                assert_eq!(keys[1].1, 8);
                if keys.len() == 3 {
                    assert_eq!(keys[2].1, 8);
                }
            }
            store.custody_new_principals_per_day = 1024;
            store.custody_new_principals_per_prefix_per_day = Some(128);
            let v4 = store.custody_budget_keys("192.0.2.9".parse()?);
            assert_eq!(v4[1].1, 128);
            let v6 = store.custody_budget_keys("2001:db8:1:2::9".parse()?);
            assert_eq!(v6[1].1, 128);
            assert_eq!(v6[2].1, 512);
        }
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn inspection_preserves_durable_rows_and_redacts_prefixes_after_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "rf-custody-inspection-{}.redb",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let encoded =
            serde_json::to_vec(&Budget { day: 1, daily: 8, minute: 1441, burst: 2, total: 8 })?;
        {
            let store = RouterRedbStore::open_without_wal(&path)?;
            assert!(store.custody_publication_budgets()?.is_empty());
            let tx = store.db.begin_write()?;
            {
                let mut table = tx.open_table(BUDGETS)?;
                table.insert("global", encoded.as_slice())?;
                table.insert("192.0.2.0/24", encoded.as_slice())?;
            }
            tx.commit()?;
        }
        {
            let store = RouterRedbStore::open_without_wal(&path)?;
            let rows = store.custody_publication_budgets()?;
            assert_eq!(rows.len(), 5);
            let daily = rows
                .iter()
                .find(|r| r.scope == "prefix" && r.budget == "publication_daily")
                .ok_or("prefix row missing")?;
            assert_eq!((daily.count, daily.limit, daily.reset_at), (8, 8, Some(172_800)));
            assert_eq!(daily.prefix.as_ref().map(String::len), Some(16));
            assert!(!serde_json::to_string(&rows)?.contains("192.0.2"));
            let tx = store.db.begin_read()?;
            let table = tx.open_table(BUDGETS)?;
            assert_eq!(table.get("192.0.2.0/24")?.ok_or("row missing")?.value(), encoded);
            assert_eq!(store.custody_publication_write_count(), 0);
        }
        std::fs::remove_file(path)?;
        Ok(())
    }

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
    fn durable_publication_capacity_reports_current_window_and_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::custody_budget_log::tests::assert_warning;
        if crate::custody_budget_log::tests::run_isolated()? {
            return Ok(());
        }
        let mut daily = Budget { day: 1, daily: 8, minute: 1440, burst: 0, total: 8 };
        assert_warning("publication_daily", 8, 8, || {
            assert!(daily.charge(86_400, 8, 16, false).is_err());
        });
        let mut minute = Budget { day: 1, daily: 2, minute: 1440, burst: 2, total: 2 };
        assert_warning("publication_minute", 2, 2, || {
            assert!(minute.charge(86_400, 100, 2, true).is_err());
        });
        let mut total = Budget { day: 1, total: MAX_ACCOUNTS, minute: 1440, ..Budget::default() };
        assert_warning("publication_total", 65_536, 65_536, || {
            assert!(total.charge(86_400, 100, 16, true).is_err());
        });
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
