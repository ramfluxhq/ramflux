// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native sibling tombstones erase generated copies and fence late arrivals across reopen.
use crate::client::native_test_support::{TestResult, sibling_erasure, watchdog};

#[tokio::test(flavor = "current_thread")]
async fn sibling_history_tombstone_erases_a_live_own_copy_and_its_footprint() -> TestResult {
    watchdog::within(sibling_erasure::exercise(false, 1)).await?
}

#[tokio::test(flavor = "current_thread")]
async fn sibling_history_tombstone_prevents_a_late_own_copy_from_reviving_content() -> TestResult {
    watchdog::within(sibling_erasure::exercise(true, 1)).await?
}

#[tokio::test(flavor = "current_thread")]
async fn sibling_history_tombstone_erases_each_live_copy_of_the_same_original() -> TestResult {
    watchdog::within(sibling_erasure::exercise(false, 2)).await?
}
