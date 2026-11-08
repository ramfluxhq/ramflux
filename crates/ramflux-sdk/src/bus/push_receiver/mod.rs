// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant session-push receive executor. P20 wires `ApplyPage` into the actor.
#![allow(dead_code)]

pub(crate) mod ack_batch;
#[cfg(test)]
mod ack_batch_tests;
pub(crate) mod apply;
pub(crate) mod authority;
pub(crate) mod executor;
pub(crate) mod hooks;
pub(crate) mod inventory;
pub(crate) mod managed_ack;
pub(crate) use managed_ack::{MANAGED_ACK_CODE, managed_public_ack};
#[cfg(test)]
mod apply_tests;
pub(crate) mod apply_w1;
#[cfg(test)]
mod apply_w1_tests;
#[cfg(test)]
mod guard_tests;
