// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host callbacks own no SDK secret buffer; replacement/close drains their outstanding uses.
use crate::{
    SdkError,
    custody::pairing::{CredentialOutcome, LocalCredentialProvider, SecretUtf8},
};
use ramflux_protocol::custody::pairing::{PairingWire, local_dto::CredentialRequest};
use std::{
    ffi::c_void,
    path::PathBuf,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

/// Return 0 for provided input, 1 for refusal. Both SDK-owned output capacities are 1024.
/// The callback must respect those capacities and must not reenter this client.
/// `user_data` must remain valid until replacement/unregister/client close returns.
pub type CredentialCallback = extern "C" fn(
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
    *mut u8,
    usize,
    *mut usize,
    *mut c_void,
) -> i32;
pub(super) struct CallbackProvider {
    root: PathBuf,
    callback: CredentialCallback,
    // The host's opaque pointer is never dereferenced by Rust. Its exposed provenance
    // is restored only for the callback, and close/replacement waits for every use.
    user_data: usize,
    stopped: AtomicBool,
    active: Mutex<usize>,
    idle: Condvar,
    serial: Mutex<()>,
}
struct Invocation<'a>(&'a CallbackProvider);
impl Drop for Invocation<'_> {
    fn drop(&mut self) {
        let mut active = self.0.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = active.saturating_sub(1);
        self.0.idle.notify_all();
    }
}
fn invalid() -> SdkError {
    SdkError::PairingField("credential_callback")
}
impl CallbackProvider {
    pub(super) fn new(root: PathBuf, callback: CredentialCallback, user_data: *mut c_void) -> Self {
        Self {
            root,
            callback,
            user_data: user_data.expose_provenance(),
            stopped: AtomicBool::new(false),
            active: Mutex::new(0),
            idle: Condvar::new(),
            serial: Mutex::new(()),
        }
    }
    pub(super) fn stop_and_drain(&self) {
        self.cancel();
        let mut active = self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active != 0 {
            active = self.idle.wait(active).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    fn enter(&self) -> Result<Invocation<'_>, SdkError> {
        let mut active = self.active.lock().map_err(|_| invalid())?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(SdkError::PairingCode("Retired"));
        }
        *active = active.checked_add(1).ok_or_else(invalid)?;
        Ok(Invocation(self))
    }
    fn invoke(&self, request: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        let metadata = request.to_wire_bytes().map_err(|_| invalid())?;
        let mut passphrase = Zeroizing::new([0_u8; 1024]);
        let mut confirmation = Zeroizing::new([0_u8; 1024]);
        let mut pass_len = 0_usize;
        let mut confirm_len = 0_usize;
        let provided = (self.callback)(
            metadata.as_ptr(),
            metadata.len(),
            passphrase.as_mut_ptr(),
            passphrase.len(),
            &mut pass_len,
            confirmation.as_mut_ptr(),
            confirmation.len(),
            &mut confirm_len,
            std::ptr::with_exposed_provenance_mut(self.user_data),
        );
        if self.stopped.load(Ordering::Acquire) || provided == 1 {
            return Ok(CredentialOutcome::Refused);
        }
        if provided != 0 {
            return Err(invalid());
        }
        let passphrase = SecretUtf8::from_bytes(passphrase.get(..pass_len).ok_or_else(invalid)?)?;
        let confirmation = if confirm_len == 0 {
            None
        } else {
            Some(SecretUtf8::from_bytes(confirmation.get(..confirm_len).ok_or_else(invalid)?)?)
        };
        match (request.action.as_str(), confirmation.as_ref()) {
            ("setup", Some(value)) if passphrase.as_bytes() == value.as_bytes() => {}
            ("unlock" | "phrase", None) => {}
            _ => return Err(invalid()),
        }
        Ok(CredentialOutcome::Provided { passphrase, confirmation })
    }
}
impl LocalCredentialProvider for CallbackProvider {
    fn provide(&self, request: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        request.validate().map_err(|_| invalid())?;
        let reservation =
            crate::custody::pairing::load_reservation(&self.root, &request.local_account_id)?
                .ok_or_else(invalid)?;
        if reservation.reservation_id != request.reservation_id
            || reservation.frontend_generation != request.frontend_generation
        {
            return Err(invalid());
        }
        let _serial = self.serial.lock().map_err(|_| invalid())?;
        let _invocation = self.enter()?;
        self.invoke(request)
    }
    fn cancel(&self) {
        self.stopped.store(true, Ordering::Release);
    }
}
pub(super) struct Refuse;
impl LocalCredentialProvider for Refuse {
    fn provide(&self, _: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        Ok(CredentialOutcome::Refused)
    }
}

#[cfg(test)]
mod tests;
