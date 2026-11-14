// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A2UI 1.0 messages carried by the signed Surface v3 transport.
mod action;
mod expression;
mod format_string;
mod link;
mod pointer;
mod rpc;
pub use rpc::*;
mod schema;
mod state;
mod wire;
pub use action::*;
pub use pointer::JsonPointer;
pub use state::*;
pub use wire::*;
#[cfg(test)]
mod tests;
