// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Permanent source-authority refusals shared by router admission and federation spool retries.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeAuthorityReason {
    Revoked,
    AuthorityMismatch,
    StaleEpoch,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeAuthorityRefusal {
    pub reason_code: EnvelopeAuthorityReason,
}
