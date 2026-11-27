// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Large-group host (LARGE-GROUP-01 P1): pseudonymous group log, posting-token issuance and key
//! delivery checks for one node. Requests carry no session identity; the host never receives one.

mod debug;
mod entries;
mod host;
mod issue;
mod key_file;
mod rows;
mod store;

pub use host::{LargeGroupHost, LgReply};
