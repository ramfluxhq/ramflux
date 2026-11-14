// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native replacements for the retired group JSON authorization and bootstrap regressions.
#[path = "legacy_bootstrap_retry_tests.rs"]
mod bootstrap_retry;
#[path = "native_group_auth_tests.rs"]
mod native;
