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
