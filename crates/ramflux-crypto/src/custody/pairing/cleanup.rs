// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned pairing secret buffers. Drop zeroizes; explicit [`PairingSecrets::cleanup`]
//! is required on every public success and error exit so tests can observe the call.
//! HKDF/HMAC/X25519/AEAD library copies, stack residues and panic=abort are not
//! claimed erased; a stronger guarantee needs a separately audited primitive.

use std::cell::Cell;
use zeroize::{Zeroize, ZeroizeOnDrop};

thread_local! {
    static CLEANUPS: Cell<u64> = const { Cell::new(0) };
}

/// Number of explicit pairing-secret cleanup calls since the last take on this thread.
#[must_use]
pub fn take_pairing_secret_cleanups() -> u64 {
    CLEANUPS.with(Cell::take)
}

/// Ephemeral SAS secret, DH output, HKDF keys and salt. Channel plaintext is not stored.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingSecrets {
    pub(super) sas_secret: [u8; 32],
    pub(super) shared: [u8; 32],
    pub(super) confirm_i: [u8; 32],
    pub(super) confirm_r: [u8; 32],
    pub(super) channel_i: [u8; 32],
    pub(super) channel_r: [u8; 32],
    pub(super) salt: [u8; 32],
}

impl PairingSecrets {
    pub(super) fn pending(sas_secret: [u8; 32], salt: [u8; 32]) -> Self {
        Self {
            sas_secret,
            shared: [0; 32],
            confirm_i: [0; 32],
            confirm_r: [0; 32],
            channel_i: [0; 32],
            channel_r: [0; 32],
            salt,
        }
    }

    /// Wipe owned bytes and record the explicit cleanup. Drop still zeroizes if this is skipped.
    pub fn cleanup(&mut self) {
        self.zeroize();
        CLEANUPS.with(|count| count.set(count.get() + 1));
    }

    #[must_use]
    pub(super) fn is_wiped(&self) -> bool {
        self.sas_secret.iter().chain(self.shared.iter()).all(|byte| *byte == 0)
            && self.confirm_i.iter().chain(self.confirm_r.iter()).all(|byte| *byte == 0)
            && self.channel_i.iter().chain(self.channel_r.iter()).all(|byte| *byte == 0)
    }
}
