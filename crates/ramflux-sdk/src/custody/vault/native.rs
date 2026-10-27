// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Data-protection Keychain operations; secret reads alone may request user presence.
// Only this private FFI boundary permits unsafe. The safe password setter updates duplicate
// items, so it cannot implement our insert-only primary replacement protocol.
#![allow(unsafe_code)]
use super::{
    SdkError, Zeroizing,
    presence::{Items, protected_reference},
};
use crate::custody::home_authorization::unavailable;
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
    base::errSecItemNotFound,
    item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnAttributes, kSecReturnData, kSecUseAuthenticationUI,
        kSecUseDataProtectionKeychain, kSecValueData,
    },
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate},
};

const SERVICE: &str = "org.ramflux.identity.primary.v1";
// The pinned sys crate does not expose this documented constant. Keep its missing
// declaration inside the same private Security FFI boundary as the item calls.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    #[link_name = "kSecUseAuthenticationUIFail"]
    static AUTHENTICATION_UI_FAIL: core_foundation::string::CFStringRef;
}
pub(super) struct KeychainItems;
type Pairs = Vec<(CFString, CFType)>;
fn pairs(reference: &str, interactive: bool) -> Pairs {
    // SAFETY: Security's keys/values are process-lifetime CFString constants. Each returned
    // wrapper retains its value, and dictionaries own all values across the synchronous call.
    unsafe {
        let mut fields = vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
            ),
            (CFString::wrap_under_get_rule(kSecAttrService), CFString::new(SERVICE).into_CFType()),
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
                CFBoolean::true_value().into_CFType(),
            ),
        ];
        if !interactive {
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
fn copy(reference: &str, data: bool, interactive: bool) -> Result<Option<CFType>, SdkError> {
    let mut fields = pairs(reference, interactive);
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
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &raw mut value) };
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
impl Items for KeychainItems {
    fn exists(&self, reference: &str) -> Result<bool, SdkError> {
        Ok(copy(reference, false, false)?.is_some())
    }
    fn read(
        &self,
        reference: &str,
        presence: bool,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SdkError> {
        copy(reference, true, presence)?
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
        // SecItemAdd receives creation attributes, not query-only UI controls. It never
        // reads/replaces an existing item; duplicates return without an update.
        let mut fields = pairs(reference, true);
        let flags = if presence { AccessControlOptions::USER_PRESENCE.bits() } else { 0 };
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            flags,
        )
        .map_err(|_| unavailable())?;
        // SAFETY: keys are static and all retained objects live through SecItemAdd.
        unsafe {
            fields
                .push((CFString::wrap_under_get_rule(kSecAttrAccessControl), access.into_CFType()));
            fields.push((
                CFString::wrap_under_get_rule(kSecValueData),
                CFData::from_buffer(bytes).into_CFType(),
            ));
        }
        let query = CFDictionary::from_CFType_pairs(&fields);
        // SAFETY: The dictionary owns the complete bounded value; no result is requested.
        let status = unsafe { SecItemAdd(query.as_concrete_TypeRef(), std::ptr::null_mut()) };
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
        let query = CFDictionary::from_CFType_pairs(&pairs(reference, false));
        // SAFETY: The update contains only public upgrade metadata and owns its CFData.
        let updates = unsafe {
            CFDictionary::from_CFType_pairs(&[(
                CFString::wrap_under_get_rule(kSecValueData),
                CFData::from_buffer(bytes).into_CFType(),
            )])
        };
        // SAFETY: Both dictionaries remain live for the synchronous update.
        if unsafe { SecItemUpdate(query.as_concrete_TypeRef(), updates.as_concrete_TypeRef()) } != 0
        {
            return Err(unavailable());
        }
        Ok(())
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        let query = CFDictionary::from_CFType_pairs(&pairs(reference, false));
        // SAFETY: The exact service/account dictionary lives through the synchronous call.
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        if status != 0 && status != errSecItemNotFound {
            return Err(unavailable());
        }
        Ok(())
    }
}
pub(super) fn preflight() -> Result<(), SdkError> {
    KeychainItems
        .exists("provider-availability-probe")
        .map(|_| ())
        .map_err(|_| SdkError::CustodyVaultUnavailable)
}
pub(super) fn store_primary(reference: &str, secret: &[u8]) -> Result<(), SdkError> {
    if KeychainItems.exists(reference)?
        || !KeychainItems.insert(&protected_reference(reference), secret, true)?
    {
        return Err(SdkError::CustodyVaultUnavailable);
    }
    Ok(())
}
pub(super) fn get_primary(reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let protected = protected_reference(reference);
    if KeychainItems.exists(&protected)? {
        KeychainItems.read(&protected, true)?.ok_or_else(unavailable)
    } else {
        KeychainItems.read(reference, false)?.ok_or_else(unavailable)
    }
}
pub(super) fn store_branch(reference: &str, secret: &[u8]) -> Result<(), SdkError> {
    if !KeychainItems.insert(reference, secret, false)? {
        return Err(SdkError::CustodyVaultUnavailable);
    }
    Ok(())
}
pub(super) fn get_branch(reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    KeychainItems.read(reference, false)?.ok_or(SdkError::CustodyVaultUnavailable)
}
