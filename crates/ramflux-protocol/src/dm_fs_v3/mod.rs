// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant native DM bootstrap components, separate from application message grammars.
//! Validation here establishes canonical framing, not signatures or current authority.
mod codec;
pub use codec::{DecodeError, Field, Fields, Scanned, WireType, scan, valid_custody_id};

#[cfg(test)]
mod codec_tests;
