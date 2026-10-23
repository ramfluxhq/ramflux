// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authoritative, domain-separated JCS/SHA-256 surface and decision-argument hashes.

use super::{SurfaceContent, SurfaceReject, limits};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SURFACE_HASH_DOMAIN: &[u8] = b"ramflux.surface.v1\n";
pub const SURFACE_ARGS_HASH_DOMAIN: &[u8] = b"ramflux.surface.args.v1\n";

/// Hashes exactly the validated content field set, excluding version and stream lifecycle state.
#[must_use]
pub fn surface_hash(content: &SurfaceContent) -> String {
    digest(SURFACE_HASH_DOMAIN, content.canonical_bytes())
}

/// Hashes human decision values using their own domain and the same protocol JCS encoding.
/// # Errors
/// Rejects JSON that exceeds the text, data byte or nesting bounds.
pub fn surface_args_hash(values: &Value) -> Result<String, SurfaceReject> {
    Ok(digest(SURFACE_ARGS_HASH_DOMAIN, &limits::json(values)?))
}
fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    format!("sha256:{:x}", hash.finalize())
}
