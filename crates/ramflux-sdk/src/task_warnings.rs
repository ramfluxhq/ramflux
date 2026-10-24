// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, process-local warning admission; no mutex is held while logging or awaiting work.
use crate::SdkError;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
const WINDOW: Duration = Duration::from_secs(3600);
const MAX_ROWS: usize = 4096;
#[derive(Default)]
struct WarningBudget(BTreeMap<String, Instant>);
impl WarningBudget {
    fn admit(&mut self, row: &str, now: Instant) -> bool {
        self.0.retain(|_, at| now.saturating_duration_since(*at) < WINDOW);
        if self.0.contains_key(row) || self.0.len() >= MAX_ROWS {
            return false;
        }
        self.0.insert(row.to_owned(), now);
        true
    }
}
pub(crate) fn warn(row: &str, error: &SdkError, message: &str) {
    static BUDGET: OnceLock<Mutex<WarningBudget>> = OnceLock::new();
    let admitted = BUDGET
        .get_or_init(Mutex::default)
        .lock()
        .is_ok_and(|mut budget| budget.admit(row, Instant::now()));
    if admitted {
        tracing::warn!(row, %error, "{message}");
    }
}
pub(crate) fn row_key(row: &serde_json::Value) -> String {
    crate::client::task::key(
        "lifecycle",
        &serde_json::json!([row["conversation_id"].as_str(), row["task_id"].as_str()]).to_string(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r8_repeated_row_failures_warn_once_an_hour_without_unbounded_key_retention() {
        let now = Instant::now();
        let mut budget = WarningBudget::default();
        assert!(budget.admit("bad-task", now));
        assert!(!budget.admit("bad-task", now + Duration::from_secs(3599)));
        assert!(budget.admit("another-task", now));
        assert!(budget.admit("bad-task", now + WINDOW));
        for n in 0..MAX_ROWS {
            budget.admit(&format!("row-{n}"), now + WINDOW);
        }
        assert!(!budget.admit("overflow", now + WINDOW));
        assert!(!budget.admit("bad-task", now + WINDOW + Duration::from_secs(1)));
        assert!(budget.admit("overflow", now + WINDOW * 2));
    }
}
