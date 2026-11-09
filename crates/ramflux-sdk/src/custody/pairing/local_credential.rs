// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Annex E private local data credential. Passphrase never enters pairing DTOs.

use crate::SdkError;
use ramflux_protocol::custody::pairing::local_dto::{CredentialInput, CredentialRequest};
use ramflux_protocol::custody::pairing::{PairingWire, WireError};
use zeroize::{Zeroize, Zeroizing};

/// One-shot attended provider. Registered only by the owning local frontend.
pub trait LocalCredentialProvider {
    /// Return a fresh setup/unlock secret or refuse. Never cache the result.
    ///
    /// # Errors
    /// Provider transport or validation failures.
    fn provide(&self, request: &CredentialRequest) -> Result<CredentialOutcome, SdkError>;
}

/// Private provider result. Not a pairing DTO.
pub enum CredentialOutcome {
    /// Owned UTF-8 secret buffers. Setup confirmation is byte-identical.
    Provided { passphrase: SecretUtf8, confirmation: Option<SecretUtf8> },
    /// User or UI cancelled. Unlock/setup must not substitute an empty secret.
    Refused,
}

/// Owned nonempty UTF-8 secret, at most 1024 bytes. No Debug/serde.
pub struct SecretUtf8(Zeroizing<Vec<u8>>);

impl SecretUtf8 {
    /// # Errors
    /// Rejects empty, overlong, or non-UTF-8 input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SdkError> {
        if bytes.is_empty() || bytes.len() > 1024 || std::str::from_utf8(bytes).is_err() {
            return Err(SdkError::PairingField("credential_length"));
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretUtf8 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Acquire a twice-entered setup passphrase. Refusal never unlocks.
///
/// # Errors
/// `VaultUnavailable` on refusal; field errors on mismatch/binding.
pub fn acquire_setup(
    expected: &CredentialRequest,
    provider: &dyn LocalCredentialProvider,
) -> Result<SecretUtf8, SdkError> {
    expected.validate().map_err(|error| wire(&error))?;
    if expected.action != "setup" {
        return Err(SdkError::PairingField("credential_action"));
    }
    take_provided(expected, provider)
}

/// Acquire a re-entry unlock passphrase. Refusal never tries the data store.
///
/// # Errors
/// `VaultUnavailable` on refusal; field errors on binding.
pub fn acquire_unlock(
    expected: &CredentialRequest,
    provider: &dyn LocalCredentialProvider,
) -> Result<SecretUtf8, SdkError> {
    expected.validate().map_err(|error| wire(&error))?;
    if expected.action != "unlock" {
        return Err(SdkError::PairingField("credential_action"));
    }
    take_provided(expected, provider)
}

fn take_provided(
    expected: &CredentialRequest,
    provider: &dyn LocalCredentialProvider,
) -> Result<SecretUtf8, SdkError> {
    match provider.provide(expected)? {
        CredentialOutcome::Refused => {
            record_cleanup([0_u8; 224]);
            Err(SdkError::PairingCode("VaultUnavailable"))
        }
        CredentialOutcome::Provided { passphrase, confirmation } => {
            let mut hold = CredentialHold { passphrase, confirmation };
            let input = CredentialInput {
                passphrase: hold.passphrase.as_bytes(),
                confirmation: hold.confirmation.as_ref().map(SecretUtf8::as_bytes),
            };
            expected.validate_input(expected, input).map_err(|error| {
                hold.cleanup();
                wire(&error)
            })?;
            let secret = SecretUtf8::from_bytes(hold.passphrase.as_bytes())?;
            hold.cleanup();
            Ok(secret)
        }
    }
}

struct CredentialHold {
    passphrase: SecretUtf8,
    confirmation: Option<SecretUtf8>,
}

impl CredentialHold {
    fn cleanup(&mut self) {
        self.passphrase.0.zeroize();
        if let Some(confirmation) = &mut self.confirmation {
            confirmation.0.zeroize();
        }
        let mut bytes = [0_u8; 224];
        copy_prefix(&mut bytes, self.passphrase.as_bytes());
        record_cleanup(bytes);
    }
}

impl Drop for CredentialHold {
    fn drop(&mut self) {
        if !self.passphrase.as_bytes().iter().all(|byte| *byte == 0) {
            self.cleanup();
            record_drop();
        }
    }
}

fn copy_prefix(dst: &mut [u8; 224], src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
}

fn wire(error: &WireError) -> SdkError {
    match error {
        WireError::Field(name) => SdkError::PairingField(name),
        WireError::Size | WireError::Json | WireError::Shape | WireError::NonCanonical => {
            SdkError::PairingCode("InvalidInput")
        }
    }
}

fn record_cleanup(bytes: [u8; 224]) {
    let _ = bytes;
    #[cfg(test)]
    observer::record_cleanup(bytes);
}

fn record_drop() {
    #[cfg(test)]
    observer::record_drop();
}

/// Owned branch seeds, data key and passphrase copies. Drop and cleanup zeroize.
pub struct RecipientSecrets {
    pub(super) branch: Zeroizing<[u8; 64]>,
    pub(super) data: Zeroizing<[u8; 32]>,
    pub(super) passphrase: Zeroizing<Vec<u8>>,
    cleaned: bool,
}

impl RecipientSecrets {
    pub(super) fn new(
        branch: Zeroizing<[u8; 64]>,
        data: Zeroizing<[u8; 32]>,
        passphrase: &[u8],
    ) -> Self {
        Self { branch, data, passphrase: Zeroizing::new(passphrase.to_vec()), cleaned: false }
    }

    /// Wipe owned bytes and record the explicit cleanup.
    pub fn cleanup(&mut self) {
        self.branch.zeroize();
        self.data.zeroize();
        self.passphrase.zeroize();
        self.cleaned = true;
        let mut bytes = [0_u8; 224];
        bytes[..64].copy_from_slice(&self.branch[..]);
        bytes[64..96].copy_from_slice(&self.data[..]);
        copy_prefix_at(&mut bytes, 96, &self.passphrase);
        record_cleanup(bytes);
    }

    #[cfg(test)]
    pub(super) fn is_wiped(&self) -> bool {
        self.branch.iter().all(|byte| *byte == 0)
            && self.data.iter().all(|byte| *byte == 0)
            && self.passphrase.iter().all(|byte| *byte == 0)
    }
}

fn copy_prefix_at(dst: &mut [u8; 224], at: usize, src: &[u8]) {
    let room = dst.len().saturating_sub(at);
    let n = src.len().min(room);
    dst[at..at + n].copy_from_slice(&src[..n]);
}

impl Drop for RecipientSecrets {
    fn drop(&mut self) {
        if !self.cleaned {
            self.cleanup();
            record_drop();
        }
    }
}

/// Number of explicit recipient-secret cleanup calls since the last take on this thread.
#[cfg(test)]
#[must_use]
pub fn take_pairing_secret_cleanups() -> u64 {
    observer::take_cleanups()
}

/// Independent drop observations since the last take on this thread.
#[cfg(test)]
#[must_use]
pub fn take_pairing_secret_drops() -> u64 {
    observer::take_drops()
}

/// Bytes observed after the last explicit cleanup on this thread.
#[cfg(test)]
#[must_use]
pub fn last_wiped_pairing_bytes() -> [u8; 224] {
    observer::last()
}

#[cfg(test)]
mod observer {
    use std::cell::{Cell, RefCell};
    thread_local! {
        static CLEANUPS: Cell<u64> = const { Cell::new(0) };
        static DROPS: Cell<u64> = const { Cell::new(0) };
        static LAST: RefCell<[u8; 224]> = const { RefCell::new([0; 224]) };
    }
    pub fn take_cleanups() -> u64 {
        CLEANUPS.with(Cell::take)
    }
    pub fn take_drops() -> u64 {
        DROPS.with(Cell::take)
    }
    pub fn last() -> [u8; 224] {
        LAST.with(|bytes| *bytes.borrow())
    }
    pub fn record_cleanup(bytes: [u8; 224]) {
        CLEANUPS.with(|count| count.set(count.get() + 1));
        LAST.with(|slot| *slot.borrow_mut() = bytes);
    }
    pub fn record_drop() {
        DROPS.with(|count| count.set(count.get() + 1));
    }
}
