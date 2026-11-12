// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host seams for the local bus. Unix keeps today's calls. Windows uses a per-user named pipe.

#[cfg(unix)]
pub(crate) mod fs;
#[cfg(unix)]
pub(crate) mod listener;

#[cfg(windows)]
pub(crate) mod pipe;
#[cfg(windows)]
pub(crate) use pipe::listener;
