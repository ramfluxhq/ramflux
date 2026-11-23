// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A2UI 1.0 messages carried by the signed Surface v3 transport.
mod action;
mod expression;
mod format_string;
mod graph;
mod icon_path;
mod link;
pub use link::validate_url;
mod locale;
mod locale_format;
pub use locale::DisplayLocale;
mod pointer;
mod resolve;
mod resource;
pub use resolve::*;
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

#[cfg(test)]
mod upstream_tests;
