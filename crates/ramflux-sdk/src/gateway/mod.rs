// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub mod access;
pub mod engine;
pub(crate) mod transport_opener;
pub(crate) use access::GatewayPushAccess;
pub use access::{GatewayCallFuture, GatewaySessionAccess};
pub(crate) mod frame_dispatch;
pub mod helpers;
pub(crate) mod host_frames;
pub mod protocol;
pub(crate) mod push_point;
pub(crate) mod push_resume;
pub mod push_route;
pub(crate) mod push_submit;
pub(crate) mod session_push;

pub use engine::*;
pub(crate) use helpers::*;
pub use protocol::*;
pub use push_route::*;

mod custody;
#[cfg(test)]
#[path = "submit_tests.rs"]
mod submit_tests;
pub use custody::GatewayCustodyConfig;
