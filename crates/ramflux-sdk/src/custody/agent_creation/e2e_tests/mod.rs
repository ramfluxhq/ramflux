// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-crate end-to-end tests of agent creation (AGENT-IDENTITY-01 step C4). Each file holds one
//! scenario group. Shared support, what is real and what is a fixture: `../test_support.rs`.
//! Every test waits through a bounded deadline, and no test sleeps for expiry: time is passed as
//! an explicit `now`.
mod authorization_binding;
mod primary_phone;
pub(crate) mod rebind;
mod refusal_timeout;
