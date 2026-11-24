// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared bounds for untrusted media hints, independent of container and codec.
use super::validation::ValidationError;

/// Validate paired, optional media dimensions. Absence means unknown.
/// # Errors
/// Rejects partial dimensions, zero, or either dimension above 32768 pixels.
pub fn validate_dimensions(width: Option<u32>, height: Option<u32>) -> Result<(), ValidationError> {
    match (width, height) {
        (None, None) => Ok(()),
        (Some(w), Some(h)) if (1..=32768).contains(&w) && (1..=32768).contains(&h) => Ok(()),
        _ => Err(ValidationError::Content),
    }
}
