// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Windows local-bus carrier: a per-user named pipe.
//!
//! The pipe's access list is hygiene against other standard users and sandboxed processes.
//! Administrators and SYSTEM can always reach a user's data.

pub(crate) mod listener;
mod name;
pub(crate) mod win32;

#[cfg(test)]
mod tests;
