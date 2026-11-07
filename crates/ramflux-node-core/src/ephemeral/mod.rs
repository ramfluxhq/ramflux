// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Non-persisted ephemeral routing state owned by `RouterCore`.

mod capability;

pub(crate) use capability::EphemeralCapabilityState;
pub use capability::{EPHEMERAL_CAPABILITY_BOUND, EphemeralRouteGate};
