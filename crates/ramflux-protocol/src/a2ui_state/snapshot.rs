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
pub(super) fn validate(content: &CreateSurfaceCommand) -> Result<(), SurfaceReject> {
    if content.components.len() > super::MAX_SURFACE_BLOCKS {
        return Err(limits::exceeded(SurfaceLimit::Blocks));
    }
    if content.allowed_actions.len() > super::MAX_SURFACE_ACTIONS {
        return Err(limits::exceeded(SurfaceLimit::Actions));
    }
    limits::identifier(&content.surface_id)?;
    limits::text(&content.fallback_text)?;
    if content.fallback_text.trim().is_empty() {
        return Err(SurfaceReject::MissingFallback);
    }
    if let Some(text) = &content.fallback_markdown {
        limits::text(text)?;
    }
    limits::text(&content.catalog)?;
    limits::text(&content.catalog_version)?;
    let mut ids = BTreeSet::new();
    let mut bytes = 0;
    for component in &content.components {
        let id = component_id(component)?;
        if !ids.insert(id) {
            return Err(SurfaceReject::DuplicateBlock);
        }
        bytes += limits::json(component)?.len();
        if bytes > super::MAX_SURFACE_DATA_BYTES {
            return Err(limits::exceeded(SurfaceLimit::DataBytes));
        }
    }
    bytes += limits::json(&Value::Object(content.data_model.clone()))?.len();
    if bytes > super::MAX_SURFACE_DATA_BYTES {
        return Err(limits::exceeded(SurfaceLimit::DataBytes));
    }
    ids.clear();
    for action in &content.allowed_actions {
        let id = action_id(action)?;
        if !ids.insert(id) {
            return Err(SurfaceReject::DuplicateAction);
        }
        limits::json(action)?;
    }
    Ok(())
}
