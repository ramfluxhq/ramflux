// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant committed SAS adapter. Unwired: grants no authority and does not change live behaviour.
mod cleanup;
mod sas;
#[cfg(test)]
mod tests;

pub use cleanup::PairingSecrets;
#[cfg(test)]
pub use cleanup::{last_wiped_pairing_bytes, take_pairing_secret_cleanups};
pub use sas::{
    EstablishedSas, PairingRole, PendingSas, SAS_EMOJI, SasEmoji, commit, emoji_from_indices,
};
