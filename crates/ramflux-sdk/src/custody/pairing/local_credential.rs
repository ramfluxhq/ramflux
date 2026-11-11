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
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use zeroize::{Zeroize, Zeroizing};

/// One-shot attended provider. Registered only by the owning local frontend.
pub trait LocalCredentialProvider: Send + Sync {
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
    bind_slot(root, value);
    let bytes = canonical_json_bytes(value).map_err(|_| SdkError::PairingField("json"))?;
    write_private(&reservation_path(root, &value.account_id), &bytes)
}

/// Remove the persisted reservation file. Missing files succeed.
///
/// # Errors
/// I/O failures other than not-found.
pub fn remove_reservation(root: &Path, account_id: &str) -> Result<(), SdkError> {
    match std::fs::remove_file(reservation_path(root, account_id)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
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

/// Fence late callbacks for `(root, account_id)` before drop. Distinct from provider refusal.
pub fn cancel_credential(root: &Path, account_id: &str) {
    let mut map = slots().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = map.entry(slot_key(root, account_id)).or_insert_with(AccountSlot::retired);
    if slot.outstanding {
        slot.request_generation = slot.request_generation.saturating_add(1);
        record_cancel();
    }
    slot.cancelled = true;
    slot.outstanding = false;
}

/// Acquire a twice-entered setup passphrase bound to the persisted reservation.
///
/// # Errors
/// `VaultUnavailable` on refusal/cancel; field errors on mismatch/binding.
pub fn acquire_setup(
    root: &Path,
    expected: &CredentialRequest,
    provider: &dyn LocalCredentialProvider,
    stored: &PersistedReservation,
) -> Result<SecretUtf8, SdkError> {
    take_bound(root, expected, provider, stored, "setup")
}

/// Acquire a re-entry unlock passphrase bound to the persisted reservation.
///
/// # Errors
/// `VaultUnavailable` on refusal/cancel; field errors on binding.
pub fn acquire_unlock(
    root: &Path,
    expected: &CredentialRequest,
    provider: &dyn LocalCredentialProvider,
    stored: &PersistedReservation,
) -> Result<SecretUtf8, SdkError> {
    take_bound(root, expected, provider, stored, "unlock")
}

fn take_bound(
    root: &Path,
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
    admit_expected(expected, &bound)?;
    let request_generation = begin_request(root, stored);
    match provider.provide(expected)? {
        CredentialOutcome::Refused => {
            finish_request(root, stored, request_generation, None)?;
            record_cleanup(Owner::Refusal, [0_u8; 224]);
            Err(SdkError::PairingCode("VaultUnavailable"))
        }
        CredentialOutcome::Provided { passphrase, confirmation } => {
            let mut hold = CredentialHold { passphrase, confirmation };
            if finish_request(root, stored, request_generation, Some(&mut hold)).is_err() {
                return Err(SdkError::PairingCode("VaultUnavailable"));
            }
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
            Ok(secret)
        }
    }
}

fn admit_expected(expected: &CredentialRequest, bound: &CredentialRequest) -> Result<(), SdkError> {
    if expected.local_account_id != bound.local_account_id {
        return Err(SdkError::PairingField("credential_account"));
    }
    if expected.reservation_id != bound.reservation_id {
        return Err(SdkError::PairingField("credential_reservation"));
    }
    if expected.frontend_generation != bound.frontend_generation {
        return Err(SdkError::PairingField("credential_generation"));
    }
    Ok(())
}

fn begin_request(root: &Path, stored: &PersistedReservation) -> u64 {
    let mut map = slots().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = map.entry(slot_key(root, &stored.account_id)).or_insert_with(AccountSlot::empty);
    slot.bind(stored);
    slot.request_generation = slot.request_generation.saturating_add(1);
    slot.cancelled = false;
    slot.outstanding = true;
    slot.request_generation
}

fn finish_request(
    root: &Path,
    stored: &PersistedReservation,
    request_generation: u64,
    hold: Option<&mut CredentialHold>,
) -> Result<(), SdkError> {
    let mut map = slots().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = map
        .get_mut(&slot_key(root, &stored.account_id))
        .ok_or(SdkError::PairingField("credential_reservation"))?;
    let retired = slot.cancelled
        || slot.request_generation != request_generation
        || slot.reservation_id != stored.reservation_id
        || slot.frontend_generation != stored.frontend_generation;
    slot.outstanding = false;
    if retired {
        if let Some(hold) = hold {
            hold.cleanup();
        }
        record_cancel();
        return Err(SdkError::PairingCode("VaultUnavailable"));
    }
    Ok(())
}

fn bind_slot(root: &Path, stored: &PersistedReservation) {
    let mut map = slots().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = map.entry(slot_key(root, &stored.account_id)).or_insert_with(AccountSlot::empty);
    if slot.outstanding {
        slot.request_generation = slot.request_generation.saturating_add(1);
        record_cancel();
    }
    slot.bind(stored);
    slot.cancelled = false;
    slot.outstanding = false;
}

fn slot_key(root: &Path, account_id: &str) -> String {
    format!("{}\0{account_id}", root.as_os_str().to_string_lossy())
}

struct AccountSlot {
    reservation_id: String,
    frontend_generation: u64,
    request_generation: u64,
    cancelled: bool,
    outstanding: bool,
}

impl AccountSlot {
    fn empty() -> Self {
        Self {
            reservation_id: String::new(),
            frontend_generation: 0,
            request_generation: 0,
            cancelled: false,
            outstanding: false,
        }
    }

    fn retired() -> Self {
        Self { cancelled: true, ..Self::empty() }
    }

    fn bind(&mut self, stored: &PersistedReservation) {
        self.reservation_id.clone_from(&stored.reservation_id);
        self.frontend_generation = stored.frontend_generation;
    }
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
    let mut file = crate::platform::fs::open_owner_only_truncate(path)?;
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

/// Per-owner drop counts `(passphrase, confirmation, branch)` since the last take.
#[cfg(test)]
#[must_use]
pub fn take_owner_drops() -> (u64, u64, u64) {
    observer::take_owner_drops()
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

/// `SecretUtf8` drops that still held leftover bytes since the last take.
#[cfg(test)]
#[must_use]
pub fn take_secret_utf8_drops() -> u64 {
    observer::take_secret_utf8_leftover()
}

/// `SecretUtf8` drops that were already zeroized since the last take.
#[cfg(test)]
#[must_use]
pub fn take_secret_utf8_zeroed() -> u64 {
    observer::take_secret_utf8_zeroed()
}

/// Cancel-fence observations since the last take on this thread.
#[cfg(test)]
#[must_use]
pub fn take_cancel_fences() -> u64 {
    observer::take_cancels()
}

/// Drop in-memory slots. Models a process restart over the persisted reservation.
#[cfg(test)]
pub fn forget_slots() {
    slots().lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
}

#[cfg(test)]
mod observer {
    use super::Owner;
    use std::cell::{Cell, RefCell};
    thread_local! {
        static CLEANUPS: Cell<u64> = const { Cell::new(0) };
        static DROPS: RefCell<[u64; 4]> = const { RefCell::new([0; 4]) };
        static LAST: RefCell<[u8; 224]> = const { RefCell::new([0; 224]) };
        static LAST_CONFIRM: RefCell<[u8; 224]> = const { RefCell::new([0; 224]) };
        static UTF8_LEFT: Cell<u64> = const { Cell::new(0) };
        static UTF8_ZERO: Cell<u64> = const { Cell::new(0) };
        static CANCELS: Cell<u64> = const { Cell::new(0) };
    }
    fn owner_index(owner: Owner) -> usize {
        match owner {
            Owner::Passphrase => 0,
            Owner::Confirmation => 1,
            Owner::Branch => 2,
            Owner::Refusal => 3,
        }
    }
    pub fn take_cleanups() -> u64 {
        CLEANUPS.with(Cell::take)
    }
    pub fn take_drops() -> u64 {
        DROPS.with(|slot| {
            let mut counts = slot.borrow_mut();
            let total = counts.iter().sum();
            *counts = [0; 4];
            total
        })
    }
    pub fn take_owner_drops() -> (u64, u64, u64) {
        DROPS.with(|slot| {
            let mut counts = slot.borrow_mut();
            let passphrase = counts[0];
            let confirmation = counts[1];
            let branch = counts[2];
            *counts = [0; 4];
            (passphrase, confirmation, branch)
        })
    }
    pub fn last() -> [u8; 224] {
        LAST.with(|bytes| *bytes.borrow())
    }
    pub fn last_confirmation() -> [u8; 224] {
        LAST_CONFIRM.with(|bytes| *bytes.borrow())
    }
    pub fn take_secret_utf8_leftover() -> u64 {
        UTF8_LEFT.with(Cell::take)
    }
    pub fn take_secret_utf8_zeroed() -> u64 {
        UTF8_ZERO.with(Cell::take)
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
    pub fn record_drop(owner: Owner) {
        DROPS.with(|slot| slot.borrow_mut()[owner_index(owner)] += 1);
    }
    pub fn record_secret_utf8(leftover: bool) {
        if leftover {
            UTF8_LEFT.with(|count| count.set(count.get() + 1));
        } else {
            UTF8_ZERO.with(|count| count.set(count.get() + 1));
        }
    }
    pub fn record_cancel() {
        CANCELS.with(|count| count.set(count.get() + 1));
    }
}
