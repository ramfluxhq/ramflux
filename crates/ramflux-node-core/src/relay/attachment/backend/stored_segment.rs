// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Private persistence mirror: public segment descriptions cannot be deserialized.
use super::BackendSegment;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[derive(Serialize, Deserialize)]
struct Stored {
    object: [u8; 32],
    manifest: [u8; 32],
    generation: u64,
    index: u32,
    length: u64,
    chunk: u32,
    digest: [u8; 32],
}
pub(super) fn serialize<S: Serializer>(
    spec: &BackendSegment,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Stored {
        object: spec.object,
        manifest: spec.manifest,
        generation: spec.generation,
        index: spec.index,
        length: spec.length,
        chunk: spec.chunk,
        digest: spec.digest,
    }
    .serialize(serializer)
}
pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BackendSegment, D::Error> {
    let value = Stored::deserialize(deserializer)?;
    let spec = BackendSegment {
        object: value.object,
        manifest: value.manifest,
        generation: value.generation,
        index: value.index,
        length: value.length,
        chunk: value.chunk,
        digest: value.digest,
    };
    spec.validate().map_err(serde::de::Error::custom)?;
    Ok(spec)
}
