// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary primary credentials never request UI; migration uses its own protected item.
use super::{
    SdkError, Zeroizing,
    presence::{Items, protected_reference},
};

pub(super) fn store(items: &impl Items, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
    if items.exists(&protected_reference(reference))? || !items.insert(reference, secret, false)? {
        return Err(SdkError::CustodyVaultUnavailable);
    }
    Ok(())
}

pub(super) fn load(items: &impl Items, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    items.read(reference, false)?.ok_or(SdkError::CustodyVaultUnavailable)
}

pub(super) fn delete(items: &impl Items, reference: &str) -> Result<(), SdkError> {
    items.delete(reference)?;
    items.delete(&protected_reference(reference))
}
