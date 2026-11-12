// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! C ABI major 2: a synchronous facade over the in-process supervisor.
//!
//! Major 1 (the parent module) owns a private runtime and a private `RamfluxClient`. Major 2
//! owns neither. Every request is a local-bus frame handed to the one supervisor of the data
//! root, so a C host, the UniFFI bindings and the desktop socket execute the same code.
//!
//! Rules of this boundary, mirrored in `include/ramflux_sdk_v2.h`:
//!
//! - **Versioned structs.** Every struct the host passes starts with `struct_size`. A size
//!   below the 2.0 layout is `InvalidArgument`; a size above what this core knows is
//!   `UnsupportedVersion`, never a silently ignored field.
//! - **Ownership.** Inputs are borrowed for the duration of the call and copied. Every
//!   `RamfluxBuffer*` written to an out-parameter is owned by the host and released with the
//!   major-1 `ramflux_buffer_free`. Handles are released with their own `_free` function.
//! - **Errors.** The return value is a major-1 `RamfluxErrorCode` discriminant. The optional
//!   error buffer carries diagnostic JSON; hosts match the number and the `effect` field only.
//! - **No unwinding.** Every export runs under `catch_unwind` and reports `PanicAborted`.
//! - **Waiting.** The calling thread waits outside the supervisor thread with a bounded
//!   deadline. A waiter that gives up after its frame was handed to the supervisor reports
//!   `effect = "unknown"`: the request may have run. The shim never retries and never mints
//!   an operation id.
//! - **Account creation.** A ceremony on its own connection, never an `execute` request:
//!   begin, show the phrase once, ask three positions, confirm once.
//! - **Events.** Polling only, on a bounded queue. Overflow ends the subscription with a
//!   terminal `lagged` record that names the last delivered sequence.
//!
//! Major-1 symbols keep their signatures and their backend. Nothing here is advertised by
//! `ramflux_sdk_abi_version_major`, which stays 1 until the major-1 backend is retired.

mod ceremony;
mod driver;
mod error;
mod exports;
mod exports_account;
mod host;
mod subscription;
mod types;

#[cfg(test)]
mod tests;

pub use exports::*;
pub use exports_account::*;
pub use host::CoreHost;
pub use types::{
    RAMFLUX_V2_ABI_MAJOR, RAMFLUX_V2_ABI_MINOR, RamfluxV2AccountCreation, RamfluxV2Cancel,
    RamfluxV2Config, RamfluxV2Core, RamfluxV2CreateConfirm, RamfluxV2CreateOptions,
    RamfluxV2Request, RamfluxV2SubscribeOptions, RamfluxV2Subscription, RamfluxV2Version,
};

/// The hand-kept C header for this module. A test keeps it in step with the exports.
pub const HEADER: &str = include_str!("../../../include/ramflux_sdk_v2.h");
