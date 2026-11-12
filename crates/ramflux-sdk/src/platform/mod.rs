// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host seams for the local bus. Unix keeps today's calls. No other carrier is implemented here.

#[cfg(unix)]
pub(crate) mod fs;
#[cfg(unix)]
pub(crate) mod listener;
/// Host network-change reports and per-network path memory; neutral on every target.
pub(crate) mod network;
