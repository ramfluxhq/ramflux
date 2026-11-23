// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed outer signal that a durable envelope must not mint a message wake.
//!
//! Absence means the send is visible. A call grant still mints `call_wake`.

use serde_json::Value;

/// Extension key. The value is the constant [`NONE`] or the key is absent.
pub const KEY: &str = "wake_eligibility";

/// The sender says this envelope is not a user-visible alert.
pub const NONE: &str = "none";

/// True when the signed envelope opts out of a message wake.
#[must_use]
pub fn suppressed(ext: &crate::Ext) -> bool {
    ext.ext.get(KEY).and_then(Value::as_str) == Some(NONE)
}

/// Record the opt-out. The caller signs the envelope after this insert.
pub fn mark_silent(ext: &mut crate::Ext) {
    ext.ext.insert(KEY.to_owned(), Value::String(NONE.to_owned()));
}
