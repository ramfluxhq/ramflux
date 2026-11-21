// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A2I control DTO and the single Surface v3 protocol contract.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct A2iControlEvent {
    pub event_id: String,
    pub event_type: String,
    pub source_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_principal_commitment: Option<String>,
    pub target_device_id: String,
    pub control_domain: String,
    pub action: String,
    pub subject_base64: String,
    pub created_at: i64,
    pub acknowledged: bool,
}

pub use ramflux_protocol::a2ui::{SurfaceAction, SurfaceEvent, SurfaceState};
