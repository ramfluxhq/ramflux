// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Browser host for a linked secondary device.
//!
//! The crate has two layers. The modules declared first are platform-neutral: they hold every
//! rule of the web wire contract, the tab carrier, the leader hand-off and the storage policy as
//! plain state machines, so they compile and are tested on the native host. The `browser` module
//! is the only code that touches a browser API and it compiles on `target_family = "wasm"` only.
//!
//! A browser build is a linked secondary device. It has no account creation, recovery, home
//! migration or device approval entry point; `role` turns any attempt to add one into a
//! compile error.

pub mod carrier;
pub mod close;
pub mod error;
pub mod leader;
pub mod link;
pub mod role;
pub mod session;
pub mod store_policy;
pub mod vault_format;
pub mod wire;

#[cfg(target_family = "wasm")]
pub mod browser;

pub use error::WebError;
