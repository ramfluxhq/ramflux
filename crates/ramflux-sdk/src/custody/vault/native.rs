// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keychain operations; secret reads alone may request user presence.
//!
//! The data-protection keychain is preferred. A process without the entitlement it requires
//! (`errSecMissingEntitlement`, typical of ad hoc signed builds) stores the same
//! non-synchronizing items in the login keychain instead; see
//! `docs/macos_keychain_authorization.md`.
// Only this private FFI boundary permits unsafe. The safe password setter updates duplicate
// items, so it cannot implement our insert-only primary replacement protocol.
#![allow(unsafe_code)]
use super::{SdkError, Zeroizing, presence::Items, primary_items};
use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    string::CFString,
};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    passwords::AccessControlOptions,
};
use security_framework_sys::{
    access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    base::errSecItemNotFound,
    item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnAttributes, kSecReturnData, kSecUseAuthenticationUI,
        kSecUseDataProtectionKeychain, kSecValueData,
    },
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate},
};

const SERVICE: &str = "org.ramflux.identity.primary.v1";
/// Distinct service so login-keychain items can never be mistaken for protected ones.
pub(super) const LOGIN_SERVICE: &str = "org.ramflux.identity.primary.login-keychain.v1";
const PROBE_REFERENCE: &str = "provider-availability-probe";
/// `errSecMissingEntitlement`: the process may not use the data-protection keychain.
const MISSING_ENTITLEMENT: i32 = -34018;
// The pinned sys crate does not expose these documented constants. Keep their missing
// declarations inside the same private Security FFI boundary as the item calls.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    #[link_name = "kSecUseAuthenticationUIFail"]
    static AUTHENTICATION_UI_FAIL: core_foundation::string::CFStringRef;
    #[link_name = "kSecAttrAccessible"]
    static ATTR_ACCESSIBLE: core_foundation::string::CFStringRef;
}
/// Keychain implementation holding this process's primary-vault items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Backend {
    /// Data-protection keychain with `SecAccessControl`; requires a provisioned entitlement.
    DataProtection,
    /// File-based login keychain, when-unlocked-this-device-only; no user-presence items.
    LoginKeychain,
}
#[derive(Clone, Copy)]
pub(super) struct KeychainItems {
    backend: Backend,
}
impl KeychainItems {
    /// Only the data-protection keychain can hold the migration user-presence item.
    pub(super) const PROTECTED: Self = Self { backend: Backend::DataProtection };
    const LOGIN: Self = Self { backend: Backend::LoginKeychain };
}
type Pairs = Vec<(CFString, CFType)>;
fn unavailable() -> SdkError {
    SdkError::CustodyVaultUnavailable
}
#[cfg(not(test))]
static SELECTED: std::sync::OnceLock<Backend> = std::sync::OnceLock::new();
/// Select the backend once per process with a real insert probe. A read-only probe cannot
/// detect a missing entitlement: lookups report "not found" instead. Failures are not cached.
pub(super) fn backend() -> Result<Backend, SdkError> {
    #[cfg(not(test))]
    if let Some(selected) = SELECTED.get() {
        return Ok(*selected);
    }
    #[cfg(test)]
    if let Some(selected) = tests::BACKEND.get() {
        return Ok(selected);
    }
    let selected = select(probe(Backend::DataProtection), || probe(Backend::LoginKeychain))?;
    #[cfg(not(test))]
    let selected = *SELECTED.get_or_init(|| selected);
    Ok(selected)
}
fn select(protected: i32, login: impl FnOnce() -> i32) -> Result<Backend, SdkError> {
    match protected {
        0 => Ok(Backend::DataProtection),
        MISSING_ENTITLEMENT if login() == 0 => Ok(Backend::LoginKeychain),
        _ => Err(unavailable()),
    }
}
fn probe(backend: Backend) -> i32 {
    let items = KeychainItems { backend };
    let status = add_status(items, PROBE_REFERENCE, b"probe", false);
    if status == 0 || status == security_framework_sys::base::errSecDuplicateItem {
        // The probe holds no secret; a failed removal is retried by the next probe.
        let _ = items.delete(PROBE_REFERENCE);
        return 0;
    }
    status
}
/// Stores used by reads and deletes: protected items first, then login-keychain items, so
/// accounts created by an unentitled build stay readable after an entitled upgrade.
fn readable() -> Result<&'static [KeychainItems], SdkError> {
    Ok(match backend()? {
        Backend::DataProtection => &[KeychainItems::PROTECTED, KeychainItems::LOGIN],
        Backend::LoginKeychain => &[KeychainItems::LOGIN],
    })
}
fn read_any(reference: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SdkError> {
    for items in readable()? {
        if let Some(bytes) = items.read(reference, false)? {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}
fn keychain_status(call: impl FnOnce() -> i32) -> i32 {
    #[cfg(test)]
    if let Some(status) = tests::FORCED_STATUS.get() {
        return status;
    }
    call()
}
fn pairs(items: KeychainItems, reference: &str, interactive: bool) -> Pairs {
    let protected = items.backend == Backend::DataProtection;
    let service = if protected { SERVICE } else { LOGIN_SERVICE };
    // SAFETY: Security's keys/values are process-lifetime CFString constants. Each returned
    // wrapper retains its value, and dictionaries own all values across the synchronous call.
    unsafe {
        let mut fields = vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
            ),
            (CFString::wrap_under_get_rule(kSecAttrService), CFString::new(service).into_CFType()),
            (
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::new(reference).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFBoolean::false_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFBoolean::from(protected).into_CFType(),
            ),
        ];
        // Login-keychain reads may show the per-application ACL confirmation after an ad hoc
        // rebuild changes the code signature; that is not a user-presence grant.
        if !interactive && protected {
            fields.push((
                CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
                CFString::wrap_under_get_rule(AUTHENTICATION_UI_FAIL).into_CFType(),
            ));
        }
        // No authentication context is supplied: Security creates one, uses it once and
        // discards it. In particular, never reuse a prior successful LAContext.
        fields
    }
}
fn copy(
    items: KeychainItems,
    reference: &str,
    data: bool,
    interactive: bool,
) -> Result<Option<CFType>, SdkError> {
    #[cfg(test)]
    tests::COPY_REQUEST.set(Some((data, interactive)));
    let mut fields = pairs(items, reference, interactive);
    // SAFETY: Both return keys are static Security constants and the Boolean is retained.
    unsafe {
        fields.push((
            CFString::wrap_under_get_rule(if data { kSecReturnData } else { kSecReturnAttributes }),
            CFBoolean::true_value().into_CFType(),
        ));
    }
    let query = CFDictionary::from_CFType_pairs(&fields);
    let mut value = std::ptr::null();
    // SAFETY: query is a live immutable dictionary; value receives a create-rule result.
    let status = keychain_status(|| unsafe {
        SecItemCopyMatching(query.as_concrete_TypeRef(), &raw mut value)
    });
    // SAFETY: Any non-null copy result follows the create rule, including an anomalous
    // result accompanying an error. Wrap it before branching so every exit releases it.
    let owned = (!value.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(value) });
    if status == errSecItemNotFound {
        return Ok(None);
    }
    if status != 0 {
        return Err(unavailable());
    }
    owned.map(Some).ok_or_else(unavailable)
}
/// Raw insert status. The login keychain cannot hold user-presence items: refuse them there.
fn add_status(items: KeychainItems, reference: &str, bytes: &[u8], presence: bool) -> i32 {
    // SecItemAdd receives creation attributes, not query-only UI controls. It never
    // reads/replaces an existing item; duplicates return without an update.
    let mut fields = pairs(items, reference, true);
    if items.backend == Backend::DataProtection {
        let flags = if presence { AccessControlOptions::USER_PRESENCE.bits() } else { 0 };
        let Ok(access) = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            flags,
        ) else {
            return security_framework_sys::base::errSecParam;
        };
        // SAFETY: the key is static and the retained object lives through SecItemAdd.
        unsafe {
            fields
                .push((CFString::wrap_under_get_rule(kSecAttrAccessControl), access.into_CFType()));
        }
    } else if presence {
        return security_framework_sys::base::errSecParam;
    } else {
        // SAFETY: both values are process-lifetime Security constants, retained by the wrappers.
        unsafe {
            fields.push((
                CFString::wrap_under_get_rule(ATTR_ACCESSIBLE),
                CFString::wrap_under_get_rule(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
                    .into_CFType(),
            ));
        }
    }
    // SAFETY: the key is static and the CFData is retained by the dictionary.
    unsafe {
        fields.push((
            CFString::wrap_under_get_rule(kSecValueData),
            CFData::from_buffer(bytes).into_CFType(),
        ));
    }
    let query = CFDictionary::from_CFType_pairs(&fields);
    // SAFETY: The dictionary owns the complete bounded value; no result is requested.
    keychain_status(|| unsafe { SecItemAdd(query.as_concrete_TypeRef(), std::ptr::null_mut()) })
}
impl Items for KeychainItems {
    fn exists(&self, reference: &str) -> Result<bool, SdkError> {
        Ok(copy(*self, reference, false, false)?.is_some())
    }
    fn read(
        &self,
        reference: &str,
        presence: bool,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SdkError> {
        copy(*self, reference, true, presence)?
            .map(|value| {
                let data = value.downcast::<CFData>().ok_or_else(unavailable)?;
                if data.len() > 1024 {
                    return Err(unavailable());
                }
                Ok(Zeroizing::new(data.bytes().to_vec()))
            })
            .transpose()
    }
    fn insert(&self, reference: &str, bytes: &[u8], presence: bool) -> Result<bool, SdkError> {
        #[cfg(test)]
        tests::INSERT_PRESENCE.set(Some(presence));
        let status = add_status(*self, reference, bytes, presence);
        if status == security_framework_sys::base::errSecDuplicateItem {
            return Ok(false);
        }
        if status != 0 {
            return Err(unavailable());
        }
        Ok(true)
    }
    fn journal(&self, reference: &str, bytes: &[u8]) -> Result<(), SdkError> {
        if bytes.len() > 1024 {
            return Err(unavailable());
        }
        if self.insert(reference, bytes, false)? {
            return Ok(());
        }
        let query = CFDictionary::from_CFType_pairs(&pairs(*self, reference, false));
        // SAFETY: The update contains only public upgrade metadata and owns its CFData.
        let updates = unsafe {
            CFDictionary::from_CFType_pairs(&[(
                CFString::wrap_under_get_rule(kSecValueData),
                CFData::from_buffer(bytes).into_CFType(),
            )])
        };
        // SAFETY: Both dictionaries remain live for the synchronous update.
        if keychain_status(|| unsafe {
            SecItemUpdate(query.as_concrete_TypeRef(), updates.as_concrete_TypeRef())
        }) != 0
        {
            return Err(unavailable());
        }
        Ok(())
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        let query = CFDictionary::from_CFType_pairs(&pairs(*self, reference, false));
        // SAFETY: The exact service/account dictionary lives through the synchronous call.
        let status = keychain_status(|| unsafe { SecItemDelete(query.as_concrete_TypeRef()) });
        if status != 0 && status != errSecItemNotFound {
            return Err(unavailable());
        }
        Ok(())
    }
}
pub(super) fn preflight() -> Result<(), SdkError> {
    backend().map(|_| ())
}
pub(super) fn store_primary(reference: &str, secret: &[u8]) -> Result<(), SdkError> {
    primary_items::store(&KeychainItems { backend: backend()? }, reference, secret)
}
pub(super) fn get_primary(reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    for items in readable()? {
        if items.exists(reference)? {
            return primary_items::load(items, reference);
        }
    }
    Err(SdkError::CustodyVaultUnavailable)
}
fn insert_new(reference: &str, secret: &[u8]) -> Result<(), SdkError> {
    if !(KeychainItems { backend: backend()? }).insert(reference, secret, false)? {
        return Err(SdkError::CustodyVaultUnavailable);
    }
    Ok(())
}
pub(super) fn store_branch(reference: &str, secret: &[u8]) -> Result<(), SdkError> {
    insert_new(reference, secret)
}
pub(super) fn get_branch(reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    read_any(reference)?.ok_or(SdkError::CustodyVaultUnavailable)
}
pub(super) fn put(reference: &str, secret: &[u8]) -> Result<(), SdkError> {
    insert_new(reference, secret)
}
pub(super) fn get(reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    read_any(reference)?.ok_or_else(unavailable)
}
pub(super) fn delete(reference: &str) -> Result<(), SdkError> {
    let stores = readable()?;
    let primary = primary_items::delete(&stores[0], reference);
    // Fallback login-keychain items are best-effort for an entitled process: its own items
    // live in the protected store, and a locked login keychain must not block cleanup.
    for items in &stores[1..] {
        let _ = primary_items::delete(items, reference);
    }
    primary
}

#[cfg(test)]
mod tests;
