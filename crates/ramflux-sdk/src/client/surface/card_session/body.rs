// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded local session bodies. Host events are not a new wire decoder.
use super::super::invalid;
use crate::SdkError;
use serde::Deserialize;
use serde_json::Value;

pub(super) const MAX_BODY: usize = 16 * 1024;

pub(super) fn parse<T: for<'de> Deserialize<'de>>(body: &Value, max: usize) -> Result<T, SdkError> {
    let bytes = serde_json::to_vec(body)?;
    if bytes.len() > max {
        return Err(invalid("card_session_limit"));
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid("card_session_refused"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionBody {
    pub session: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PresentBody {
    pub session: u64,
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default)]
    pub dark: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OpenBody {
    pub surface_ref: String,
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default)]
    pub dark: Option<bool>,
}

pub(super) fn presentation(locale: Option<&str>, dark: Option<bool>) -> (&str, bool) {
    (locale.unwrap_or("en"), dark.unwrap_or(false))
}
