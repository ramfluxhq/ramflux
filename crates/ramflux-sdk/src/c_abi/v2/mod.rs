// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Version 2: bounded asynchronous requests through the process supervisor.
//! See docs/design/c-abi-v2.md for ownership, cancellation and wire contracts.

#[cfg(panic = "abort")]
compile_error!("C ABI v2 requires panic=unwind; build with --profile ffi-release");

mod buffer;
mod card;
mod custody;
#[cfg(test)]
mod custody_tests;
mod exports;
mod input;
mod input_config;
mod method_policy;
mod native_error;
mod projection;
#[cfg(test)]
mod review_tests;
mod runtime;
mod state;
#[cfg(test)]
mod tests;

pub use custody::{RamfluxV2CustodyOperation, RamfluxV2CustodyProvider, RamfluxV2CustodyRequest};
pub use exports::ramflux_v2_client_open_with_custody;
pub use exports::{
    RamfluxV2Status, ramflux_v2_buffer_free, ramflux_v2_card_trust_package,
    ramflux_v2_client_close, ramflux_v2_client_open, ramflux_v2_client_release,
    ramflux_v2_conversation_project, ramflux_v2_event_poll, ramflux_v2_event_reset,
    ramflux_v2_execute, ramflux_v2_negotiate, ramflux_v2_operation_cancel,
    ramflux_v2_operation_poll, ramflux_v2_operation_release, ramflux_v2_receipt_present,
};
use exports::{error_code, failure};
