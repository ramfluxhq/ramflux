// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attended local calls bind a private channel before the shared actor invokes its provider.
use super::{
    CredentialOutcome, CredentialRequest, PrivateCredentialChannel, PrivateCredentialScope, invalid,
};
use crate::{
    SdkError,
    custody::pairing::{LocalCredentialProvider, load_reservation},
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
type Key = (PathBuf, String);
/// The local method that owns this input window. It is never reconstructed from relay bytes.
#[derive(Clone)]
pub enum PrivateCredentialCallKind {
    Join,
    Unlock,
    Prepare { operation_id: String },
    Resume { operation_id: String },
}
struct Call {
    active: AtomicBool,
    request_id: String,
    kind: PrivateCredentialCallKind,
    channel: Arc<PrivateCredentialChannel>,
    input: Mutex<Option<Weak<dyn LocalCredentialProvider>>>,
}
fn calls() -> &'static Mutex<HashMap<Key, Arc<Call>>> {
    static CALLS: OnceLock<Mutex<HashMap<Key, Arc<Call>>>> = OnceLock::new();
    CALLS.get_or_init(|| Mutex::new(HashMap::new()))
}
/// Drop retires this exact call's callback, including timeout/disconnect paths.
pub struct PrivateCredentialCall {
    key: Key,
    call: Arc<Call>,
}
impl PrivateCredentialCall {
    /// # Errors
    /// Refuses an input owner retired by account lock or call cancellation.
    pub fn require_live(&self) -> Result<(), SdkError> {
        if self.call.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(SdkError::PairingCode("Retired"))
        }
    }
}
impl Drop for PrivateCredentialCall {
    fn drop(&mut self) {
        {
            let mut owners = calls().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            self.call.active.store(false, Ordering::Release);
            if owners.get(&self.key).is_some_and(|current| Arc::ptr_eq(current, &self.call)) {
                // Retire the SDK callback before another call can claim this account.
                crate::custody::pairing::cancel_credential(&self.key.0, &self.key.1);
                owners.remove(&self.key);
            }
        }
        let provider = self
            .call
            .input
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(provider) = provider {
            provider.cancel();
        }
    }
}
/// Cancel this account's attended input before account lock starts draining its actor.
/// # Errors
/// Returns root lookup or poisoned registry errors.
pub fn cancel_call(root: &Path, account: &str) -> Result<(), SdkError> {
    let key = (std::fs::canonicalize(root)?, account.into());
    let owner = {
        let owners = calls().lock().map_err(|_| invalid())?;
        let owner = owners.get(&key).cloned();
        if let Some(owner) = &owner {
            crate::custody::pairing::cancel_credential(root, account);
            owner.active.store(false, Ordering::Release);
        }
        owner
    };
    if let Some(owner) = owner {
        let input = owner.input.lock().map_err(|_| invalid())?.as_ref().and_then(Weak::upgrade);
        if let Some(input) = input {
            input.cancel();
        }
    }
    Ok(())
}
/// Bind one local account's initiating call to its authenticated connection.
/// # Errors
/// Refuses another live input owner, malformed public identifiers or an unavailable root.
pub fn bind_call(
    root: &Path,
    account: &str,
    request_id: String,
    kind: PrivateCredentialCallKind,
    channel: Arc<PrivateCredentialChannel>,
) -> Result<PrivateCredentialCall, SdkError> {
    crate::custody::valid_id(account)?;
    if request_id.is_empty() || request_id.len() > 128 {
        return Err(invalid());
    }
    if let PrivateCredentialCallKind::Prepare { operation_id }
    | PrivateCredentialCallKind::Resume { operation_id } = &kind
    {
        super::identifier(operation_id)?;
    }
    let key = (std::fs::canonicalize(root)?, account.into());
    let mut owners = calls().lock().map_err(|_| invalid())?;
    if owners.get(&key).is_some_and(|call| call.active.load(Ordering::Acquire)) {
        return Err(SdkError::PairingCode("Busy"));
    }
    let call = Arc::new(Call {
        active: AtomicBool::new(true),
        request_id,
        kind,
        channel,
        input: Mutex::new(None),
    });
    owners.insert(key.clone(), call.clone());
    Ok(PrivateCredentialCall { key, call })
}
/// Public parent request correlation for the connection's metadata-only prompt frame.
/// # Errors
/// Refuses absent/retired ownership. No secret is returned or serialized here.
pub fn parent_request_id(root: &Path, account: &str) -> Result<String, SdkError> {
    let key = (std::fs::canonicalize(root)?, account.into());
    let owners = calls().lock().map_err(|_| invalid())?;
    let call =
        owners.get(&key).filter(|call| call.active.load(Ordering::Acquire)).ok_or_else(invalid)?;
    Ok(call.request_id.clone())
}
struct RoutedProvider {
    key: Key,
    input: Mutex<Option<Weak<dyn LocalCredentialProvider>>>,
}
/// Shared actor provider: it resolves only the currently attended local call, never a saved password.
/// # Errors
/// Refuses an unavailable root or malformed account identifier.
pub fn provider_for_account(
    root: &Path,
    account: String,
) -> Result<Arc<dyn LocalCredentialProvider>, SdkError> {
    crate::custody::valid_id(&account)?;
    Ok(Arc::new(RoutedProvider {
        key: (std::fs::canonicalize(root)?, account),
        input: Mutex::new(None),
    }))
}
impl Call {
    fn require_scope(&self, scope: &PrivateCredentialScope) -> Result<(), SdkError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(SdkError::PairingCode("Retired"));
        }
        let permitted = match &self.kind {
            PrivateCredentialCallKind::Join => {
                matches!(scope.request().action.as_str(), "setup" | "unlock")
                    && scope.operation_id().is_some()
            }
            PrivateCredentialCallKind::Unlock => {
                scope.request().action == "unlock" && scope.operation_id().is_none()
            }
            PrivateCredentialCallKind::Resume { operation_id } => {
                scope.request().action == "unlock"
                    && scope.operation_id() == Some(operation_id.as_str())
            }
            PrivateCredentialCallKind::Prepare { operation_id } => {
                scope.request().action == "phrase"
                    && scope.operation_id() == Some(operation_id.as_str())
            }
        };
        if permitted { Ok(()) } else { Err(invalid()) }
    }
}
struct CallbackLease<'a> {
    owner: &'a RoutedProvider,
    call: Arc<Call>,
    input: Weak<dyn LocalCredentialProvider>,
}
fn clear(
    slot: &Mutex<Option<Weak<dyn LocalCredentialProvider>>>,
    expected: &Weak<dyn LocalCredentialProvider>,
) {
    let mut slot = slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot.as_ref().is_some_and(|current| Weak::ptr_eq(current, expected)) {
        *slot = None;
    }
}
impl Drop for CallbackLease<'_> {
    fn drop(&mut self) {
        clear(&self.owner.input, &self.input);
        clear(&self.call.input, &self.input);
    }
}
impl LocalCredentialProvider for RoutedProvider {
    fn provide(&self, request: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        let scope = PrivateCredentialScope::data(request.clone(), None)?;
        self.provide_scoped(request, &scope)
    }
    fn provide_scoped(
        &self,
        request: &CredentialRequest,
        scope: &PrivateCredentialScope,
    ) -> Result<CredentialOutcome, SdkError> {
        if scope.request() != request || request.local_account_id != self.key.1 {
            return Err(invalid());
        }
        let call =
            calls().lock().map_err(|_| invalid())?.get(&self.key).cloned().ok_or_else(invalid)?;
        call.require_scope(scope)?;
        let expected = scope.clone();
        let owner = call.clone();
        let root = self.key.0.clone();
        let input = call.channel.provider(
            self.key.1.clone(),
            Arc::new(move |request| {
                owner.require_scope(&expected)?;
                if expected.request() != request {
                    return Err(invalid());
                }
                let reservation =
                    load_reservation(&root, &request.local_account_id)?.ok_or_else(invalid)?;
                if reservation.reservation_id != request.reservation_id
                    || reservation.frontend_generation != request.frontend_generation
                {
                    return Err(invalid());
                }
                Ok(expected.clone())
            }),
        );
        let weak = Arc::downgrade(&input);
        *self.input.lock().map_err(|_| invalid())? = Some(weak.clone());
        *call.input.lock().map_err(|_| invalid())? = Some(weak.clone());
        let _input = CallbackLease { owner: self, call, input: weak };
        input.provide(request)
    }
    fn cancel(&self) {
        let input = self
            .input
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(input) = input {
            input.cancel();
        }
    }
}
