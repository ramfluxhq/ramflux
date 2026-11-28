// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The group host (MLS-SPEC r1.1 2, MLS-MIGRATION-PLAN G3): the node side of MLS groups on the
//! router database. The host sees pseudonyms, cleartext entry headers and MLS ciphertext, never
//! an account, a device or a roster; it stores no session id, source address or arrival time. The
//! gateway (G4) authenticates sessions and passes `now_ms` and the session's `group_id`; every
//! function here is one transaction on the `lg_*` tables.

pub mod attach;
pub mod blobs;
pub(crate) mod check;
pub mod entries;
pub mod host;
pub mod issue;
pub mod join;
mod key_file;
pub mod refusal;
pub mod retention;
pub mod roll;
pub mod route;
pub mod rows;
pub mod wakes;
