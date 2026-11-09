// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant pairing install-store. Unwired: files are codecs only.
pub mod install_gate;
pub mod install_store;
pub use install_gate::{Admission, ReopenGate, reopen};
pub use install_store::{Install, decode, encode, write_installed, write_pending};
