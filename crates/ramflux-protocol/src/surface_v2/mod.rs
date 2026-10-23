// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Declarative conversation surfaces with atomic, ordered updates and bound human decisions.
//!
//! Start from [`SurfaceState::default`] and apply a create at version 1. Each later event,
//! including a stream chunk or close, consumes exactly the next version. Replaying a chunk
//! therefore cannot append twice. Actions validate the current version and content hash without
//! mutating the surface. Signatures, conversation routing and persistence belong to callers.
//!
//! The new hash contract uses protocol JCS, independently of the legacy A2UI hash API.

mod content;
mod hash;
mod limits;
mod state;
mod types;

pub use content::SurfaceContent;
pub use hash::{SURFACE_ARGS_HASH_DOMAIN, SURFACE_HASH_DOMAIN, surface_args_hash, surface_hash};
pub use limits::{
    MAX_SURFACE_ACTIONS, MAX_SURFACE_BLOCKS, MAX_SURFACE_DATA_BYTES, MAX_SURFACE_DATA_DEPTH,
    MAX_SURFACE_FINALIZED_BLOCKS, MAX_SURFACE_PATCH_OPS, MAX_SURFACE_TEXT_CHARS,
    MAX_SURFACE_TEXT_DELTA_BYTES,
};
pub use state::SurfaceState;
pub use types::*;
