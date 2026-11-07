// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Non-persisted ephemeral routing state owned by `RouterCore`.

mod capability;

pub use capability::{
    EPHEMERAL_CAPABILITY_BOUND, EPHEMERAL_REASSERTION_ITEM_BOUND, EphemeralReassertionError,
    EphemeralRouteGate,
};
pub(crate) use capability::{EphemeralCapabilityState, new_router_boot_id};
