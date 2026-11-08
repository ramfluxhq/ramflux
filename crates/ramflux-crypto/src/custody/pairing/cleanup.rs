// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned pairing secret buffers. Drop zeroizes; explicit [`PairingSecrets::cleanup`]
//! is required on every public success and error exit so tests can observe the call.
//! HKDF/HMAC/X25519/AEAD library copies, stack residues and panic=abort are not
//! claimed erased; a stronger guarantee needs a separately audited primitive.

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
mod observer {
    use std::cell::{Cell, RefCell};
    thread_local! {
        static CLEANUPS: Cell<u64> = const { Cell::new(0) };
        static LAST: RefCell<[u8; 224]> = const { RefCell::new([0; 224]) };
    }
    pub fn take() -> u64 {
        CLEANUPS.with(Cell::take)
    }
    pub fn last_bytes() -> [u8; 224] {
        LAST.with(|bytes| *bytes.borrow())
    }
    pub fn record(bytes: [u8; 224]) {
        CLEANUPS.with(|count| count.set(count.get() + 1));
        LAST.with(|slot| *slot.borrow_mut() = bytes);
    }
}

/// Number of explicit pairing-secret cleanup calls since the last take on this thread.
#[cfg(test)]
#[must_use]
pub fn take_pairing_secret_cleanups() -> u64 {
    observer::take()
}

/// Bytes observed in pairing secret storage after the last explicit cleanup on this thread.
#[cfg(test)]
#[must_use]
pub fn last_wiped_pairing_bytes() -> [u8; 224] {
    observer::last_bytes()
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
        #[cfg(test)]
        observer::record(self.observed_bytes());
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn is_wiped(&self) -> bool {
        self.all_zero()
    }

    #[cfg(test)]
    fn all_zero(&self) -> bool {
        self.sas_secret.iter().chain(self.shared.iter()).all(|byte| *byte == 0)
            && self.confirm_i.iter().chain(self.confirm_r.iter()).all(|byte| *byte == 0)
            && self.channel_i.iter().chain(self.channel_r.iter()).all(|byte| *byte == 0)
            && self.salt.iter().all(|byte| *byte == 0)
    }

    #[cfg(test)]
    pub(super) fn observed_bytes(&self) -> [u8; 224] {
        let mut bytes = [0_u8; 224];
        let parts = [
            self.sas_secret,
            self.shared,
            self.confirm_i,
            self.confirm_r,
            self.channel_i,
            self.channel_r,
            self.salt,
        ];
        for (slot, part) in bytes.chunks_mut(32).zip(parts) {
            slot.copy_from_slice(&part);
        }
        bytes
    }
}

/// Owned HPKE Auth secret. Ephemeral KEM DH and AES context stay inside the hpke crate.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkeSecrets {
    sk: [u8; 32],
}

impl HpkeSecrets {
    pub(super) fn new(sk: [u8; 32]) -> Self {
        Self { sk }
    }

    /// Wipe the owned HPKE secret and record the explicit cleanup. Drop still zeroizes if this is skipped.
    pub fn cleanup(&mut self) {
        self.zeroize();
        #[cfg(test)]
        observer::record(self.observed_bytes());
    }

    #[cfg(test)]
    fn observed_bytes(&self) -> [u8; 224] {
        let mut bytes = [0_u8; 224];
        bytes[..32].copy_from_slice(&self.sk);
        bytes
    }
}
