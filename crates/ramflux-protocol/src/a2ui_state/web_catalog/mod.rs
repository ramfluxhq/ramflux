// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant declarative catalog. This validator grants no renderer or action capability.
//! Binding resolution/expansion and action ownership must be added before activation.
mod schema;
use super::SurfaceReject;
use crate::CreateSurfaceCommand;

pub const CATALOG: &str = "rf-web/v1";
pub const VERSION: &str = "1";
/// Shipping/advertisement stays disabled until consumer and sandbox admission.
pub const ENABLED: bool = false;
pub const SCHEMA: &str = include_str!("../../../catalogs/rf-web-v1.schema.json");

pub(super) fn validate(content: &CreateSurfaceCommand) -> Result<(), SurfaceReject> {
    if content.catalog != CATALOG {
        return Ok(());
    }
    let value = serde_json::to_value(content).map_err(|_| SurfaceReject::Encoding)?;
    schema::validate(&value)
}

// Original raw snapshot validation must precede lossy DTO defaults/skip serialization.
pub(super) fn validate_received(
    raw: &serde_json::Value,
    content: &CreateSurfaceCommand,
) -> Result<(), SurfaceReject> {
    schema::validate(raw)?;
    let typed = serde_json::to_value(content).map_err(|_| SurfaceReject::Encoding)?;
    for (key, value) in raw.as_object().ok_or(SurfaceReject::Encoding)? {
        if typed.get(key) != Some(value) {
            return Err(SurfaceReject::WebCatalog {
                path: format!("/{key}"),
                rule: "nonCanonicalField".into(),
            });
        }
    }
    Ok(())
}
pub(super) fn validate_raw(raw: &serde_json::Value) -> Result<(), SurfaceReject> {
    schema::validate(raw)
}
