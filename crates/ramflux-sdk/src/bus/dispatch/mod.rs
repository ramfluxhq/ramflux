// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub mod a2i_a2ui;
pub mod account;
pub mod call_bot;
pub mod contact;
mod contact_resolution;
pub mod daemon;
pub(crate) mod deferred_attachment;
pub mod device;
pub mod grant_mcp;
pub mod group;
pub mod message;
pub mod node;
pub mod object;
pub(crate) mod surface;

pub(crate) use a2i_a2ui::*;
pub(crate) use account::*;
pub(crate) use call_bot::*;
pub(crate) use contact::*;
pub(crate) use daemon::*;
pub(crate) use device::*;
pub(crate) use grant_mcp::*;
pub(crate) use group::*;
pub(crate) use message::*;
pub(crate) use object::*;

pub(crate) mod surface_transport;
pub(crate) mod task;
pub(crate) mod task_approval;
mod task_approval_transport;
mod task_group;
pub(crate) mod task_transport;
mod identity_authority;
