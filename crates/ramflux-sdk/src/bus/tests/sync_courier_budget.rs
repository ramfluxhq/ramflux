// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lower-priority admission must not poll network work below its minimum budget.

use super::*;

#[tokio::test(start_paused = true)]
async fn insufficient_cycle_time_defers_lower_priority_work_without_polling() {
    let polled = std::cell::Cell::new(false);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(999);
    let count = courier_count(deadline, "fixture", async {
        polled.set(true);
        Ok(1)
    })
    .await;
    assert_eq!(count, 0);
    assert!(!polled.get());
}
