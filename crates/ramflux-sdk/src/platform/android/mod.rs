// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Android host seams for the in-process supervisor.
//!
//! The application process is the supervisor on Android: nothing here listens on a socket.
//! The host application passes its private directory, forwards its lifecycle and
//! connectivity callbacks, and may or may not have a push provider. Every module is plain
//! Rust over host-supplied values, so the same code is exercised by host tests.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

pub mod backup;
pub mod host;
pub mod lifecycle;
pub mod network;
pub mod network_security;
pub mod push;
pub mod storage;
