// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded account and attachment display metadata at the typed request boundary.

use serde::{Deserialize, Deserializer};

fn optional<'de, D: Deserializer<'de>>(
    deserializer: D,
    validate: fn(&str) -> Result<(), &'static str>,
) -> Result<Option<String>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(value) = &value {
        validate(value).map_err(serde::de::Error::custom)?;
    }
    Ok(value)
}

pub(super) fn validate_label(value: &str) -> Result<(), &'static str> {
    if value.chars().count() > 64 { Err("label exceeds 64 characters") } else { Ok(()) }
}

fn validate_name(value: &str) -> Result<(), &'static str> {
    if value.len() > 255 || value.chars().any(|c| c == '/' || c == '\\' || c.is_control()) {
        Err("name must be at most 255 bytes without path separators or control characters")
    } else {
        Ok(())
    }
}

fn validate_mime(value: &str) -> Result<(), &'static str> {
    let parsed = value.parse::<::mime::Mime>();
    if value.len() > 1024
        || value.trim_end().ends_with(';')
        || !parsed.is_ok_and(|mime| {
            !mime.subtype().as_str().is_empty()
                && mime.type_() != ::mime::STAR
                && mime.subtype() != ::mime::STAR
        })
    {
        Err("mime must be a valid media type of at most 1024 bytes")
    } else {
        Ok(())
    }
}

pub(super) fn label<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    optional(d, validate_label)
}
pub(super) fn name<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    optional(d, validate_name)
}
pub(super) fn mime<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    optional(d, validate_mime)
}

#[cfg(test)]
mod tests;
