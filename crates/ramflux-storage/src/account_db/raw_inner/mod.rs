// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded exact-byte storage for Unsupported messages and private known-content evidence.

pub mod evidence;
pub mod quota;
pub mod schema;
mod writer;

pub use evidence::KnownContentEvidence;
pub use quota::{RawInnerQuota, RawInnerQuotaScope};
pub use writer::{RawInnerCopy, RawInnerCopyKind, RawInnerCopyWrite};

#[cfg(test)]
mod tests;
