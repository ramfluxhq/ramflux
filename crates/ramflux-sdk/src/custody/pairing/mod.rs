// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant pairing install-store and SDK coordinator. Default-off.
mod coordinator;
pub mod install_gate;
pub mod install_store;
mod transport;
pub use coordinator::{
    PairingActor, PairingIdentity, handle_bus, install_actor, pairing_enabled,
    validate_head_advance,
};
pub use install_gate::{Admission, ReopenGate, reopen};
pub use install_store::{Install, decode, encode, write_installed, write_pending};
pub use transport::{
    HttpRelay, PairingConfig, PairingNative, PairingTransport, PreparedCreate, PreparedIssue,
    ProofPairingNative,
};

#[cfg(test)]
mod prove_tests;
#[cfg(test)]
mod tests;
