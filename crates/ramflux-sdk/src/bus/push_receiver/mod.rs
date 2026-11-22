// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session-push receive executor. `connection_manager::background_children` runs it
//! (anchored catch-up plus intake) for every session that advertises session push.
#![allow(dead_code)]

pub(crate) mod ack_batch;
#[cfg(test)]
mod ack_batch_tests;
pub(crate) mod apply;
pub(crate) mod authority;
pub(crate) mod executor;
#[cfg(test)]
mod fence_tests;
pub(crate) mod hooks;
pub(crate) mod inventory;
pub(crate) mod managed_ack;
pub(crate) use managed_ack::{MANAGED_ACK_CODE, managed_public_ack};
#[cfg(test)]
mod apply_tests;
pub(crate) mod apply_w1;
#[cfg(test)]
mod apply_w1_failure_tests;
#[cfg(test)]
mod apply_w1_real_own_copy;
#[cfg(test)]
mod apply_w1_sweep_tests;
#[cfg(test)]
mod apply_w1_tests;
pub(crate) mod compat;
#[cfg(test)]
pub(crate) mod erase_support;
#[cfg(test)]
mod guard_tests;
pub(crate) mod intake;
pub(crate) mod keepalive;
#[cfg(test)]
mod keepalive_tests;
pub(crate) mod reorder;
#[cfg(test)]
mod reorder_tests;
pub(crate) mod sweep;
#[cfg(test)]
mod sweep_tests;
