// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant generated application schema. Native authority checks remain with their owners.
//!
//! Prost decoding is not canonical: it accepts reordered tags and overlong
//! varints (for example `08 81 00` encodes layer 1). Before hashing, signing or
//! executing peer input, P03 must reject noncanonical bytes with its descriptor
//! scanner. Decode/re-encode cannot establish original-byte canonicality.
// Generated protobuf/serde implementations follow upstream generator conventions.
#[allow(clippy::all, clippy::pedantic)]
mod generated;
pub use generated::*;
mod canonical;
pub mod client_class;
pub mod exact_content;
pub mod history_chain;
pub mod identity;
pub mod original_header;
pub mod private_revision;
pub use client_class::{
    ClientDeliveryClass, ProviderPush, client_class_from_delivery, client_class_from_notification,
    provider_push,
};
pub mod dm_scope;
pub mod outer;
mod protojson;
pub mod registry;
mod scanner;
pub mod self_sync;
pub mod unsupported;
pub mod validation;
mod wire;
pub use protojson::from_protojson;

/// Native local-bus Typing updates; never a durable journal topic or cursor.
pub const TRANSIENT_TOPIC: &str = "message.transient";

/// Exact descriptor shared by protobuf, `ProtoJSON` and binding generators.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!("descriptor.bin");

#[cfg(test)]
mod tests;

#[cfg(test)]
mod registry_tests;

#[cfg(test)]
mod boundary_tests;
