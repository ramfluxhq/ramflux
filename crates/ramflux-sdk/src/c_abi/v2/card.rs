// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Optional renderer metadata; rendering and authority retain separate lifecycles.

pub(super) fn metadata() -> serde_json::Value {
    #[cfg(feature = "card-runtime")]
    {
        serde_json::json!({
            "abi_major":ramflux_card::HOST_ABI,
            "catalog_sha256":ramflux_card::catalog_digest(),
        })
    }
    #[cfg(not(feature = "card-runtime"))]
    serde_json::Value::Null
}
