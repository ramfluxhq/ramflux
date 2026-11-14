// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit prefix quotas and the backwards-compatible unset fair-share policy.
use crate::NodeCoreError;

const PREFIX_ENV: &str = "RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_PREFIX_PER_DAY";

pub(super) fn prefix_budget_env(global: u64) -> Result<Option<u64>, NodeCoreError> {
    let value = match std::env::var(PREFIX_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(NodeCoreError::InvalidConfiguration(format!(
                "{PREFIX_ENV} must be valid UTF-8"
            )));
        }
    };
    prefix_budget_value(value.as_deref(), global)
}

fn prefix_budget_value(value: Option<&str>, global: u64) -> Result<Option<u64>, NodeCoreError> {
    value
        .map(|value| {
            super::custody_budget_value(PREFIX_ENV, Some(value), 8, 1, 4096)
                .map(|configured| configured.min(global))
        })
        .transpose()
}

pub(super) fn prefix_daily_limit(global: u64, configured: Option<u64>, wider: bool) -> u64 {
    if let Some(configured) = configured {
        let limit = if wider { configured.saturating_mul(4).max(32) } else { configured };
        limit.min(global)
    } else {
        let fair_daily = global.div_ceil(32).max(1);
        (if wider { 32 } else { 8 }).min(fair_daily)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_retains_narrow_and_wide_fair_share() -> Result<(), NodeCoreError> {
        assert_eq!(prefix_budget_value(None, 256)?, None);
        assert_eq!(prefix_daily_limit(256, None, false), 8);
        assert_eq!(prefix_daily_limit(256, None, true), 8);
        assert_eq!(prefix_daily_limit(32, None, false), 1);
        assert_eq!(prefix_daily_limit(1024, None, true), 32);
        Ok(())
    }

    #[test]
    fn explicit_prefix_scales_wider_prefix_and_never_exceeds_global() -> Result<(), NodeCoreError> {
        let configured = prefix_budget_value(Some("128"), 1024)?;
        assert_eq!(prefix_daily_limit(1024, configured, false), 128);
        assert_eq!(prefix_daily_limit(1024, configured, true), 512);
        let clamped = prefix_budget_value(Some("4096"), 256)?;
        assert_eq!(clamped, Some(256));
        assert_eq!(prefix_daily_limit(256, clamped, false), 256);
        assert_eq!(prefix_daily_limit(256, clamped, true), 256);
        assert_eq!(prefix_daily_limit(256, Some(1), true), 32);
        Ok(())
    }

    #[test]
    fn invalid_prefix_environment_prevents_store_startup() -> Result<(), Box<dyn std::error::Error>>
    {
        const CHILD: &str = "RAMFLUX_PREFIX_CONFIG_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let path = ramflux_test_support::TestPath::new()
                .expect("test: allocate fixture directory")
                .child(format!("rf-invalid-prefix-{}.redb", std::process::id()));
            assert!(matches!(
                crate::RouterRedbStore::open_without_wal(&path),
                Err(NodeCoreError::InvalidConfiguration(_))
            ));
            std::fs::remove_file(path)?;
            return Ok(());
        }
        for invalid in ["0", "4097", "many", ""] {
            let output = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "router_store::custody_budget_policy::tests::invalid_prefix_environment_prevents_store_startup"])
                .env(CHILD, "1").env(PREFIX_ENV, invalid).output()?;
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
        }
        Ok(())
    }

    #[test]
    fn invalid_prefix_values_fail_the_startup_parser() {
        for invalid in ["", "0", "4097", "-1", "many", " 16", "18446744073709551616"] {
            assert!(prefix_budget_value(Some(invalid), 1024).is_err(), "accepted {invalid}");
        }
    }
}
