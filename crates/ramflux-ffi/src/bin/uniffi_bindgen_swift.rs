// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Swift bindings generator (library mode) pinned to the scaffolding's UniFFI version.
//!
//! `uniffi-bindgen-swift <library> <out-dir> --swift-sources | --headers |
//! --modulemap [--xcframework] [--modulemap-filename <name>]`

fn main() {
    uniffi::uniffi_bindgen_swift();
}
