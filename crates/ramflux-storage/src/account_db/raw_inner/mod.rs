// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded exact-byte storage for Unsupported messages, private known-content evidence,
//! and supported own-message attestation (its own quota, same erasure linkage).

pub mod evidence;
pub mod quota;
mod reparse;
pub use reparse::RawInnerReparseRow;
pub mod schema;
mod writer;

pub use evidence::KnownContentEvidence;
pub use quota::{RawInnerQuota, RawInnerQuotaScope};
pub(crate) use writer::raw_copy_deleted;
pub use writer::{RawInnerCopy, RawInnerCopyKind, RawInnerCopyWrite};

#[cfg(test)]
mod tests;
