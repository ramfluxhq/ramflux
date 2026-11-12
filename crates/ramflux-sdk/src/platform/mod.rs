// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host seams for the local bus. Unix keeps today's calls. The in-process carrier and the
//! embedded supervisor are for hosts with no helper process; nothing starts them by default.

#[cfg(unix)]
pub(crate) mod fs;
#[cfg(unix)]
pub(crate) mod listener;
/// Platform-neutral in-process host lifecycle (phones). Shared by the iOS and Android cores.
pub mod lifecycle;
/// In-process local-bus carrier used by the embedded supervisor.
#[cfg(unix)]
pub(crate) mod in_process;
/// In-process supervisor (phones). Shared by the iOS and Android cores.
#[cfg(unix)]
pub mod embedded;
/// App-container data protection and backup exclusion.
#[cfg(target_os = "ios")]
pub(crate) mod apple_container;
/// Destination-family bind, staggered connect and the QUIC/TCP race (design 4.2, 4.3).
pub mod connect_policy;
/// Android host seams: private storage, backup rules, lifecycle, network and push policy.
/// Also built for Unix host tests; nothing here is reachable on another platform.
#[cfg(any(target_os = "android", all(test, unix)))]
pub mod android;
/// Host network-change reports and per-network path memory; neutral on every target.
pub(crate) mod network;
/// Process-wide gateway session defaults a phone host may install; unset by default.
pub(crate) mod session_defaults;
