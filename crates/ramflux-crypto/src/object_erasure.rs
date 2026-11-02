// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Portable object erasure identities. Components use unsigned 64-bit big-endian lengths.

use crate::Blake3DomainHasher;

/// Commits to a verified ciphertext identity without retaining its access material.
#[must_use]
pub fn object_erasure_commitment(root: &str, wire_id: &str, manifest: &str) -> String {
    commitment("ramflux.object.erasure.fence.v1", &[root, wire_id, manifest])
}

/// Opaque lookup index used to return an erased outcome after removing a wire identifier.
#[must_use]
pub fn object_erasure_lookup(root: &str, selector: &str) -> String {
    commitment("ramflux.object.erasure.lookup.v1", &[root, selector])
}

fn commitment(domain: &str, components: &[&str]) -> String {
    let mut hasher = Blake3DomainHasher::new(domain);
    for component in components {
        hasher.update(&(component.len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
    hasher.finalize_base64url()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mutation: remove the length prefix or omit any one identity component.
    #[test]
    fn erasure_commitment_binds_root_wire_manifest_and_component_boundaries() {
        let original = object_erasure_commitment("root", "wire", "manifest");
        for changed in [
            object_erasure_commitment("other", "wire", "manifest"),
            object_erasure_commitment("root", "other", "manifest"),
            object_erasure_commitment("root", "wire", "other"),
            object_erasure_commitment("roo", "twire", "manifest"),
        ] {
            assert_ne!(original, changed);
        }
        assert_ne!(original, object_erasure_lookup("root", "wire"));
    }
}
