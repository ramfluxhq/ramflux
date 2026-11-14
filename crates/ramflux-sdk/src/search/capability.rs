// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generation-zero decisions require no account, database, startup or mutation receipt.
use super::{SearchError, SearchIndexStatus};
use crate::SdkError;
use ramflux_storage::local_search::SearchActivation;

#[must_use]
pub fn is_method(method: &str) -> bool {
    matches!(
        method,
        "search.query"
            | "search.cursor.close"
            | "search.cancel"
            | "search.index.status"
            | "search.index.rebuild"
            | "search.index.rebuild.cancel"
    )
}
/// Shared pre-account guard used by local-bus and binding dispatch.
/// # Errors
/// Query and rebuild return a fixed capability refusal while dormant.
pub fn guard(method: &str) -> Result<Option<serde_json::Value>, SdkError> {
    if !is_method(method) {
        return Ok(None);
    }
    match SearchActivation::configured() {
        Ok(_) => Ok(None),
        Err(SearchError::NotActivated) => match method {
            "search.index.status" => Ok(Some(serde_json::to_value(SearchIndexStatus::disabled())?)),
            "search.cancel" | "search.cursor.close" | "search.index.rebuild.cancel" => {
                Ok(Some(serde_json::json!({"released":true})))
            }
            _ => Err(SearchError::NotActivated.into()),
        },
        Err(error) => Err(error.into()),
    }
}
