// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Renderer bounds plus finite wire-operation and JSON nesting budgets.

use super::{SurfaceLimit, SurfaceReject};
use serde_json::Value;

pub const MAX_SURFACE_BLOCKS: usize = 64;
pub const MAX_SURFACE_ACTIONS: usize = 16;
pub const MAX_SURFACE_TEXT_CHARS: usize = 16_384;
pub const MAX_SURFACE_DATA_BYTES: usize = 65_536;
pub const MAX_SURFACE_TEXT_DELTA_BYTES: usize = 4_096;
/// At most one block-sized batch per atomic patch.
pub const MAX_SURFACE_PATCH_OPS: usize = MAX_SURFACE_BLOCKS;
/// Retired final stream IDs are kept to prevent replay through remove/reinsert.
pub const MAX_SURFACE_FINALIZED_BLOCKS: usize = MAX_SURFACE_BLOCKS;
/// Leaves room for the event envelope within the standard JSON decoder recursion budget.
pub const MAX_SURFACE_DATA_DEPTH: usize = 64;

pub(super) const fn exceeded(limit: SurfaceLimit) -> SurfaceReject {
    SurfaceReject::LimitExceeded { limit }
}

pub(super) fn text(value: &str) -> Result<(), SurfaceReject> {
    if value.chars().take(MAX_SURFACE_TEXT_CHARS + 1).count() > MAX_SURFACE_TEXT_CHARS {
        Err(exceeded(SurfaceLimit::TextCharacters))
    } else {
        Ok(())
    }
}
pub(super) fn identifier(value: &str) -> Result<(), SurfaceReject> {
    if value.is_empty() {
        return Err(SurfaceReject::InvalidIdentifier);
    }
    text(value)
}

pub(super) fn json(value: &Value) -> Result<Vec<u8>, SurfaceReject> {
    let mut pending = vec![(value, 0_usize)];
    let mut minimum_bytes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_SURFACE_DATA_DEPTH {
            return Err(exceeded(SurfaceLimit::NestingDepth));
        }
        let lower_bound = match value {
            Value::String(value) => {
                text(value)?;
                value.len().saturating_add(2)
            }
            Value::Array(values) => 2_usize.saturating_add(values.len().saturating_sub(1)),
            Value::Object(values) => {
                let mut bytes = 2_usize.saturating_add(values.len().saturating_sub(1));
                for key in values.keys() {
                    text(key)?;
                    bytes = bytes.saturating_add(key.len()).saturating_add(3);
                }
                bytes
            }
            _ => 1,
        };
        minimum_bytes = minimum_bytes.saturating_add(lower_bound);
        if minimum_bytes > MAX_SURFACE_DATA_BYTES {
            return Err(exceeded(SurfaceLimit::DataBytes));
        }
        match value {
            Value::Array(values) => {
                if pending.len().saturating_add(values.len()) > MAX_SURFACE_DATA_BYTES {
                    return Err(exceeded(SurfaceLimit::DataBytes));
                }
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if pending.len().saturating_add(values.len()) > MAX_SURFACE_DATA_BYTES {
                    return Err(exceeded(SurfaceLimit::DataBytes));
                }
                for (key, value) in values {
                    text(key)?;
                    pending.push((value, depth + 1));
                }
            }
            _ => {}
        }
    }
    let bytes = crate::canonical_json_bytes(value).map_err(|_| SurfaceReject::Encoding)?;
    if bytes.len() > MAX_SURFACE_DATA_BYTES {
        return Err(exceeded(SurfaceLimit::DataBytes));
    }
    Ok(bytes)
}
