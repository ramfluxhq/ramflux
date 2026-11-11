// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded subprocess cleanup for the CLI e2e harness (M2).
#![cfg(unix)]

#[path = "e2e/mod.rs"]
mod e2e;

use std::time::Duration;

const BUDGET: Duration = Duration::from_secs(8);

#[test]
fn hung_cli_command_returns_within_budget_and_reaps() -> e2e::Result<()> {
    e2e::prove_hung_command_reaped_within(BUDGET)
}

#[test]
fn failed_ceremony_returns_within_budget_and_reaps() -> e2e::Result<()> {
    e2e::prove_failed_ceremony_reaped_within(BUDGET)
}

#[test]
fn unresponsive_daemon_drop_returns_within_budget_and_reaps() -> e2e::Result<()> {
    e2e::prove_unresponsive_daemon_drop_within(BUDGET)
}
