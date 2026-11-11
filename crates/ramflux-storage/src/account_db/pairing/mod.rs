// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant pairing journal. Tables exist after normal open; no coordinator is wired.
pub(crate) mod admission;
pub(crate) mod journal;
pub(crate) mod privacy;
pub(crate) mod recovery;
pub(crate) mod schema;
#[cfg(test)]
mod tests;

pub(crate) use privacy::{merge_floor, sanitize_backup, skip_merge};
pub(crate) use schema::install;
