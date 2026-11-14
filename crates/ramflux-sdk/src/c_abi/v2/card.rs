// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Optional renderer metadata; rendering and authority retain separate lifecycles.

pub(super) fn metadata() -> serde_json::Value {
    #[cfg(feature = "card-runtime")]
    {
        serde_json::json!({
            "abi_major":ramflux_card::HOST_ABI,
            "catalog_sha256":ramflux_card::catalog_digest(),
            "trust_manifest_blake3":blake3::hash(TRUST_PACKAGE).to_hex().to_string(),
        })
    }
    #[cfg(not(feature = "card-runtime"))]
    serde_json::Value::Null
}

const TRUST_PACKAGE: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/include/card/trust.json"));

pub(super) fn trust_package() -> Result<serde_json::Value, crate::SdkError> {
    Ok(serde_json::from_slice(TRUST_PACKAGE)?)
}
