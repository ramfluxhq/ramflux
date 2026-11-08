// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant session-push receive executor. P20 wires `ApplyPage` into the actor.
#![allow(dead_code)]

pub(crate) mod apply;
#[cfg(test)]
mod apply_tests;
pub(crate) mod apply_w1;
#[cfg(test)]
mod apply_w1_tests;
