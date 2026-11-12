// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host seams for the local bus. Unix keeps today's calls. No other carrier is implemented here.

#[cfg(unix)]
pub(crate) mod fs;
#[cfg(unix)]
pub(crate) mod listener;
/// Platform-neutral in-process host lifecycle (phones). Shared by the iOS and Android cores.
pub mod lifecycle;
/// Android host seams: private storage, backup rules, lifecycle, network and push policy.
/// Also built for host tests; nothing here is reachable on another platform.
#[cfg(any(target_os = "android", test))]
pub mod android;
