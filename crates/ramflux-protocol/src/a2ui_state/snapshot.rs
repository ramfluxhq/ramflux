// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounds and identity interpretation for the existing createSurface snapshot fields.
use super::{SurfaceLimit, SurfaceReject, limits};
use crate::CreateSurfaceCommand;
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) fn component_id(v: &Value) -> Result<&str, SurfaceReject> {
    v.get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or(SurfaceReject::InvalidIdentifier)
}
pub(super) fn action_id(v: &Value) -> Result<&str, SurfaceReject> {
    let name = v.get("name").and_then(Value::as_str);
    let id = v.get("id").and_then(Value::as_str);
    if name.zip(id).is_some_and(|(name, id)| name != id) {
        return Err(SurfaceReject::InvalidIdentifier);
    }
    v.as_str().or(name).or(id).filter(|id| !id.is_empty()).ok_or(SurfaceReject::InvalidIdentifier)
}
pub(super) fn validated_hash(content: &CreateSurfaceCommand) -> Result<String, SurfaceReject> {
    #[cfg(test)]
    super::work::snapshot();
    if content.components.len() > super::MAX_SURFACE_BLOCKS {
        return Err(limits::exceeded(SurfaceLimit::Blocks));
    }
    if content.allowed_actions.len() > super::MAX_SURFACE_ACTIONS {
        return Err(limits::exceeded(SurfaceLimit::Actions));
    }
    limits::identifier(&content.surface_id)?;
    if content.fallback_text.trim().is_empty() {
        return Err(SurfaceReject::MissingFallback);
    }
    let mut ids = BTreeSet::new();
    for component in &content.components {
        if !ids.insert(component_id(component)?) {
            return Err(SurfaceReject::DuplicateBlock);
        }
    }
    ids.clear();
    for action in &content.allowed_actions {
        if !ids.insert(action_id(action)?) {
            return Err(SurfaceReject::DuplicateAction);
        }
    }
    // Exactly the typed hash input, including actions, fallback strings and JSON syntax.
    // One bounded traversal and one canonical encoding after the complete atomic update.
    let value = serde_json::to_value(content).map_err(|_| SurfaceReject::Encoding)?;
    let bytes = limits::json(&value)?;
    Ok(crate::surfaces::surface_hash_from_canonical(&bytes))
}
