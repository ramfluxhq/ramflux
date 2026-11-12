// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Everything that touches a browser API. Compiled on `target_family = "wasm"` only, and run
//! only inside the dedicated worker of the leader page.

pub mod api;
pub mod driver;
pub mod js;
pub mod locks;
pub mod ports;
pub mod socket;
pub mod storage;
pub mod vault;
