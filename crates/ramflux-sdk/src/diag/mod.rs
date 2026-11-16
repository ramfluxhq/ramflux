// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Diagnostics that report locations, never cell or file contents.

mod files;
mod residue;

pub use residue::{ResidueDiagnostic, ResidueDirectory, diagnose_plaintext_residue};
