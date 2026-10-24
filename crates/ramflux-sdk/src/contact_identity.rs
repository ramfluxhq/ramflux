// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact root provenance and public confirmation data; no independent verification flag.
use serde::{Deserialize, Serialize};
/// The authority used for a contact's current root.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactRootSource {
    Lookup,
    Card,
    Verified,
}
/// Root values the user must compare before confirming a provisional replacement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContactRootChange {
    pub principal_id: String,
    pub previous_root_commitment: String,
    pub proposed_root_commitment: String,
}
