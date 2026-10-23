// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Versioned conversation projection of existing A2UI commands, using their existing hash.
//! Create consumes version 1; every subsequent mutation consumes the next version. Decisions
//! validate without changing content. `DeleteSurface` is terminal close. All updates are atomic.
//! Signatures, author permissions, encryption, routing and persistence are the carrier's job.
mod limits;
mod snapshot;
mod state;
mod types;
pub use limits::{
    MAX_SURFACE_ACTIONS, MAX_SURFACE_BLOCKS, MAX_SURFACE_DATA_BYTES, MAX_SURFACE_DATA_DEPTH,
    MAX_SURFACE_FINALIZED_BLOCKS, MAX_SURFACE_PATCH_OPS, MAX_SURFACE_TEXT_CHARS,
    MAX_SURFACE_TEXT_DELTA_BYTES,
};
pub use state::SurfaceState;
pub use types::*;

/// Uses the protocol's existing BLAKE3/base64url hash primitive with an argument-specific domain.
/// # Errors
/// Rejects non-I-JSON values and values exceeding the surface data limits.
pub fn surface_args_hash(values: &serde_json::Value) -> Result<String, SurfaceReject> {
    Ok(crate::hash_base64url("ramflux.a2ui.action_args.v1", &limits::json(values)?))
}
