// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant generated application schema. Native authority checks remain with their owners.
// Generated protobuf/serde implementations follow upstream generator conventions.
#[allow(clippy::all, clippy::pedantic)]
mod generated;
pub use generated::*;
mod protojson;
pub use protojson::from_protojson;

/// Exact descriptor shared by protobuf, `ProtoJSON` and binding generators.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!("descriptor.bin");

#[cfg(test)]
mod tests;
