// SPDX-License-Identifier: BSD-3-Clause
//! Host-visible lifecycle and verified approval facts.
//! These values are not part of the signed snapshot hash.

use serde::{Deserialize, Serialize};

/// How the host should treat the current tree.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardLifecycle {
    #[default]
    Open,
    Closed,
    Retired,
    Superseded,
}

impl CardLifecycle {
    /// Typed refusal for a host action. Open cards have none.
    #[must_use]
    pub const fn refusal(&self) -> Option<&'static str> {
        match self {
            Self::Open => None,
            Self::Closed => Some("card_closed"),
            Self::Retired => Some("card_retired"),
            Self::Superseded => Some("card_superseded"),
        }
    }
}

pub(crate) fn lifecycle_is_open(value: &CardLifecycle) -> bool {
    matches!(value, CardLifecycle::Open)
}

/// JSON bool omitted when false.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OmittedFalse(bool);

impl From<bool> for OmittedFalse {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

pub(crate) fn omitted_false(value: &OmittedFalse) -> bool {
    !value.0
}

/// One verified scope row. `name` is a fixed label, never card prose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalScope {
    pub name: String,
    pub value: String,
}

/// Facts taken from a verified approval row. Author component text is not copied here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalFacts {
    pub requester: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    pub scope: Vec<ApprovalScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
}
