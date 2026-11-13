// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WASM contract for generated request/update types. No WASM runtime is linked.

use super::{AdapterSurface, adapter_binding_vector};
use crate::SdkError;

pub use super::{
    AdapterError, ErrorDetails, GeneratedErrorCode, decode_message_request, decode_message_update,
    encode_message_request, encode_message_update, round_trip_request, round_trip_update,
};

/// JSON names exported by the WASM adapter, derived from the descriptor.
///
/// # Errors
/// Returns an error when the descriptor cannot be loaded.
pub fn exported_fields(message: &str) -> Result<Vec<String>, SdkError> {
    Ok(adapter_binding_vector(AdapterSurface::Wasm, message)?
        .fields
        .into_iter()
        .map(|field| field.json_name)
        .collect())
}
