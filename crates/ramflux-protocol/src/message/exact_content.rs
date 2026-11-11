// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Borrow exact content slices for edit digests; never decode and re-encode content.
use super::{
    validation::{self, ScanOutcome, ValidationError},
    wire,
};

/// Original Message body or the exact replacement field of an accepted Edit.
/// # Errors
/// Refuses unsupported, malformed, or unrelated stored Inner bytes.
pub fn message_in_force(inner: &[u8]) -> Result<&[u8], ValidationError> {
    let scanned = validation::scan_inner(inner)?;
    if scanned.outcome != ScanOutcome::Supported {
        return Err(ValidationError::Unsupported);
    }
    match scanned.kind {
        1 => Ok(scanned.body),
        3 => {
            let mut fields = scanned.body;
            let mut replacement = None;
            while !fields.is_empty() {
                let field = wire::field(&mut fields)?;
                if field.tag == 4 && replacement.replace(field.bytes).is_some() {
                    return Err(ValidationError::NonCanonical);
                }
            }
            replacement.ok_or(ValidationError::Content)
        }
        _ => Err(ValidationError::Content),
    }
}
