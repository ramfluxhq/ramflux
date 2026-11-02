// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Replay references retain only a projection ID, its deletion state and private digests.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageReplayReference {
    Target { message_id: String, deleted: bool, binding: Option<String>, scope: Option<String> },
    Ambiguous,
}
impl MessageReplayReference {
    #[must_use]
    pub fn message_id(&self) -> Option<&str> {
        match self {
            Self::Target { message_id, .. } => Some(message_id),
            Self::Ambiguous => None,
        }
    }
    #[must_use]
    pub fn binding(&self) -> Option<&str> {
        match self {
            Self::Target { binding, .. } => binding.as_deref(),
            Self::Ambiguous => None,
        }
    }
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        match self {
            Self::Target { scope, .. } => scope.as_deref(),
            Self::Ambiguous => None,
        }
    }
}
