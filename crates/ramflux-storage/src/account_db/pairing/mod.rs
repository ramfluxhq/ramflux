// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant pairing journal. Tables exist after normal open; no coordinator is wired.
pub(crate) mod admission;
pub(crate) mod full_reference;
pub(crate) mod journal;
pub(crate) mod own_sync;
pub(crate) mod privacy;
pub(crate) mod recovery;
pub(crate) mod schema;
pub(crate) mod tail;
#[cfg(test)]
pub(in crate::account_db) mod tests;

pub(crate) use privacy::{merge_floor, sanitize_backup, skip_merge};
pub(crate) use schema::install;
