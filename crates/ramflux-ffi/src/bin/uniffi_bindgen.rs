// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bindings generator pinned to the same UniFFI version as the scaffolding.
//!
//! `cargo run -p ramflux-ffi --features bindgen-cli --bin uniffi-bindgen -- generate
//! --library <built library> --language swift|kotlin --out-dir <dir>`

fn main() {
    uniffi::uniffi_bindgen_main();
}
