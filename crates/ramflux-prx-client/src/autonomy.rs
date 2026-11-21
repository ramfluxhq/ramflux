// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The three autonomy levels PRX accepts. Any other value is refused by PRX and fails closed here.

use serde::{Deserialize, Serialize};

/// Autonomy level of an agent or of Main, as spelled on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Autonomy {
    Readonly,
    Supervised,
    Full,
}
