// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Annex E private local data credential. Passphrase never enters pairing DTOs.

use crate::SdkError;
use ramflux_protocol::canonical_json_bytes;
use ramflux_protocol::custody::pairing::local_dto::{CredentialInput, CredentialRequest};
use ramflux_protocol::custody::pairing::{PairingWire, WireError};
use ramflux_protocol::parse_i_json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
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
        let leftover = !self.0.iter().all(|byte| *byte == 0);
        self.0.zeroize();
        record_secret_utf8_drop(leftover);
    }
}

/// Persisted reservation nonce and frontend generation. One slot per account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedReservation {
    pub account_id: String,
    pub reservation_id: String,
    pub frontend_generation: u64,
}

/// Persist the local reservation nonce before any provider callback.
///
/// # Errors
/// Field or I/O failures.
pub fn persist_reservation(root: &Path, value: &PersistedReservation) -> Result<(), SdkError> {
    value.validate()?;
    open_slot(&value.account_id, &value.reservation_id, value.frontend_generation);
    let bytes = canonical_json_bytes(value).map_err(|_| SdkError::PairingField("json"))?;
    write_private(&reservation_path(root, &value.account_id), &bytes)
}

/// Load the persisted reservation for `account_id`.
///
/// # Errors
/// Field or I/O failures.
pub fn load_reservation(
    root: &Path,
    account_id: &str,
) -> Result<Option<PersistedReservation>, SdkError> {
    let path = reservation_path(root, account_id);
    if !path.is_file() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    File::open(&path)?.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err(SdkError::PairingField("size"));
    }
    let value: PersistedReservation =
        parse_i_json(&bytes).map_err(|_| SdkError::PairingField("json"))?;
    value.validate()?;
    if canonical_json_bytes(&value).map_err(|_| SdkError::PairingField("json"))? != bytes {
        return Err(SdkError::PairingField("json"));
    }
    Ok(Some(value))
}

impl PersistedReservation {
    fn validate(&self) -> Result<(), SdkError> {
        CredentialRequest {
            local_account_id: self.account_id.clone(),
            reservation_id: self.reservation_id.clone(),
            frontend_generation: self.frontend_generation,
            action: "unlock".into(),
        }
        .validate()
        .map_err(|error| wire(&error))
    }

    fn request(&self, action: &str) -> Result<CredentialRequest, SdkError> {
        let value = CredentialRequest {
            local_account_id: self.account_id.clone(),
            reservation_id: self.reservation_id.clone(),
            frontend_generation: self.frontend_generation,
            action: action.into(),
        };
        value.validate().map_err(|error| wire(&error))?;
        Ok(value)
    }
}

/// Fence late callbacks for `account_id` before drop. Distinct from provider refusal.
pub fn cancel_credential(account_id: &str) {
    let mut map = slots().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    match map.get_mut(account_id) {
        Some(slot) => slot.cancelled = true,
        None => {
            map.insert(
                account_id.into(),
                AccountSlot {
                    reservation_id: String::new(),
                    generation: 0,
                    cancelled: true,
                    consumed: false,
                },
            );
        }
    }
    record_cancel();
}

/// Acquire a twice-entered setup passphrase bound to the persisted reservation.
///
/// # Errors
/// `VaultUnavailable` on refusal/cancel; field errors on mismatch/binding.
pub fn acquire_setup(
    expected: &CredentialRequest,
    provider: &dyn LocalCredentialProvider,
    stored: &PersistedReservation,
) -> Result<SecretUtf8, SdkError> {
    take_bound(expected, provider, stored, "setup")
}

/// Acquire a re-entry unlock passphrase bound to the persisted reservation.
///
/// # Errors
/// `VaultUnavailable` on refusal/cancel; field errors on binding.
pub fn acquire_unlock(
    expected: &CredentialRequest,
    provider: &dyn LocalCredentialProvider,
    stored: &PersistedReservation,
) -> Result<SecretUtf8, SdkError> {
    take_bound(expected, provider, stored, "unlock")
}

fn take_bound(
    expected: &CredentialRequest,
    provider: &dyn LocalCredentialProvider,
    stored: &PersistedReservation,
    action: &str,
) -> Result<SecretUtf8, SdkError> {
    expected.validate().map_err(|error| wire(&error))?;
    if expected.action != action {
        return Err(SdkError::PairingField("credential_action"));
    }
    let bound = stored.request(action)?;
    admit_slot(expected, &bound)?;
    match provider.provide(expected)? {
        CredentialOutcome::Refused => {
            record_cleanup(Owner::Refusal, [0_u8; 224]);
            Err(SdkError::PairingCode("VaultUnavailable"))
        }
        CredentialOutcome::Provided { passphrase, confirmation } => {
            let mut hold = CredentialHold { passphrase, confirmation };
            let input = CredentialInput {
                passphrase: hold.passphrase.as_bytes(),
                confirmation: hold.confirmation.as_ref().map(SecretUtf8::as_bytes),
            };
            if let Err(error) = bound.validate_input(expected, input) {
                hold.cleanup();
                return Err(wire(&error));
            }
            let secret = SecretUtf8::from_bytes(hold.passphrase.as_bytes())?;
            hold.cleanup();
            consume_slot(&expected.local_account_id);
            Ok(secret)
        }
    }
}

fn admit_slot(expected: &CredentialRequest, bound: &CredentialRequest) -> Result<(), SdkError> {
    if expected.local_account_id != bound.local_account_id {
        return Err(SdkError::PairingField("credential_account"));
    }
    if expected.reservation_id != bound.reservation_id {
        return Err(SdkError::PairingField("credential_reservation"));
    }
    if expected.frontend_generation != bound.frontend_generation {
        return Err(SdkError::PairingField("credential_generation"));
    }
    let mut map = slots().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = map
        .get_mut(&expected.local_account_id)
        .ok_or(SdkError::PairingField("credential_reservation"))?;
    if slot.cancelled || slot.consumed {
        return Err(SdkError::PairingCode("VaultUnavailable"));
    }
    if slot.reservation_id != expected.reservation_id
        || slot.generation != expected.frontend_generation
    {
        return Err(SdkError::PairingField("credential_generation"));
    }
    Ok(())
}

fn open_slot(account_id: &str, reservation_id: &str, generation: u64) {
    let mut map = slots().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    map.insert(
        account_id.into(),
        AccountSlot {
            reservation_id: reservation_id.into(),
            generation,
            cancelled: false,
            consumed: false,
        },
    );
}

fn consume_slot(account_id: &str) {
    let mut map = slots().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = map.get_mut(account_id) {
        slot.consumed = true;
    }
}

struct AccountSlot {
    reservation_id: String,
    generation: u64,
    cancelled: bool,
    consumed: bool,
}

fn slots() -> &'static Mutex<HashMap<String, AccountSlot>> {
    static SLOTS: OnceLock<Mutex<HashMap<String, AccountSlot>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn reservation_path(root: &Path, account_id: &str) -> PathBuf {
    root.join("custody_accounts").join(account_id).join("pairing-reservation.json")
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SdkError> {
    let parent = path.parent().ok_or(SdkError::PairingField("path"))?;
    std::fs::create_dir_all(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
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
        let mut pass = [0_u8; 224];
        copy_prefix(&mut pass, self.passphrase.as_bytes());
        record_cleanup(Owner::Passphrase, pass);
        let mut confirm = [0_u8; 224];
        if let Some(confirmation) = &self.confirmation {
            copy_prefix(&mut confirm, confirmation.as_bytes());
        }
        record_cleanup(Owner::Confirmation, confirm);
    }
}

impl Drop for CredentialHold {
    fn drop(&mut self) {
        if !self.passphrase.as_bytes().iter().all(|byte| *byte == 0) {
            self.cleanup();
            record_drop(Owner::Passphrase);
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

/// Owned branch seed. Passphrase stays in [`SecretUtf8`]; no extra copy (D7/L2).
pub struct RecipientSecrets {
    pub(super) branch: Zeroizing<[u8; 64]>,
    cleaned: bool,
}

impl RecipientSecrets {
    pub(super) fn new(branch: Zeroizing<[u8; 64]>) -> Self {
        Self { branch, cleaned: false }
    }

    /// Wipe owned bytes and record the explicit cleanup.
    pub fn cleanup(&mut self) {
        self.branch.zeroize();
        self.cleaned = true;
        let mut bytes = [0_u8; 224];
        bytes[..64].copy_from_slice(&self.branch[..]);
        record_cleanup(Owner::Branch, bytes);
    }

    #[cfg(test)]
    pub(super) fn is_wiped(&self) -> bool {
        self.branch.iter().all(|byte| *byte == 0)
    }
}

impl Drop for RecipientSecrets {
    fn drop(&mut self) {
        if !self.cleaned {
            self.cleanup();
            record_drop(Owner::Branch);
        }
    }
}

#[derive(Clone, Copy)]
enum Owner {
    Passphrase,
    Confirmation,
    Branch,
    Refusal,
}

fn record_cleanup(owner: Owner, bytes: [u8; 224]) {
    let _ = (owner, bytes);
    #[cfg(test)]
    observer::record_cleanup(owner, bytes);
}

fn record_drop(owner: Owner) {
    let _ = owner;
    #[cfg(test)]
    observer::record_drop(owner);
}

fn record_secret_utf8_drop(leftover: bool) {
    let _ = leftover;
    #[cfg(test)]
    observer::record_secret_utf8(leftover);
}

fn record_cancel() {
    #[cfg(test)]
    observer::record_cancel();
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

/// Confirmation-buffer bytes observed after the last explicit confirmation clear.
#[cfg(test)]
#[must_use]
pub fn last_wiped_confirmation_bytes() -> [u8; 224] {
    observer::last_confirmation()
}

/// `SecretUtf8` drop observations since the last take on this thread.
#[cfg(test)]
#[must_use]
pub fn take_secret_utf8_drops() -> u64 {
    observer::take_secret_utf8()
}

/// Cancel-fence observations since the last take on this thread.
#[cfg(test)]
#[must_use]
pub fn take_cancel_fences() -> u64 {
    observer::take_cancels()
}

#[cfg(test)]
mod observer {
    use super::Owner;
    use std::cell::{Cell, RefCell};
    thread_local! {
        static CLEANUPS: Cell<u64> = const { Cell::new(0) };
        static DROPS: Cell<u64> = const { Cell::new(0) };
        static LAST: RefCell<[u8; 224]> = const { RefCell::new([0; 224]) };
        static LAST_CONFIRM: RefCell<[u8; 224]> = const { RefCell::new([0; 224]) };
        static UTF8: Cell<u64> = const { Cell::new(0) };
        static CANCELS: Cell<u64> = const { Cell::new(0) };
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
    pub fn last_confirmation() -> [u8; 224] {
        LAST_CONFIRM.with(|bytes| *bytes.borrow())
    }
    pub fn take_secret_utf8() -> u64 {
        UTF8.with(Cell::take)
    }
    pub fn take_cancels() -> u64 {
        CANCELS.with(Cell::take)
    }
    pub fn record_cleanup(owner: Owner, bytes: [u8; 224]) {
        CLEANUPS.with(|count| count.set(count.get() + 1));
        LAST.with(|slot| *slot.borrow_mut() = bytes);
        if matches!(owner, Owner::Confirmation) {
            LAST_CONFIRM.with(|slot| *slot.borrow_mut() = bytes);
        }
    }
    pub fn record_drop(_owner: Owner) {
        DROPS.with(|count| count.set(count.get() + 1));
    }
    pub fn record_secret_utf8(_leftover: bool) {
        UTF8.with(|count| count.set(count.get() + 1));
    }
    pub fn record_cancel() {
        CANCELS.with(|count| count.set(count.get() + 1));
    }
}
