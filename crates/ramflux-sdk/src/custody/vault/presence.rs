// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Crash-safe replacement of an unprotected primary item, never branch credentials.
use crate::SdkError;
use crate::custody::home_authorization::unavailable;
use ramflux_crypto::custody::SelfSigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    CopyPlanned,
    PresencePending,
    Verified,
    DeleteLegacy,
    Ready,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Upgrade {
    version: u32,
    public_key: String,
    stage: Stage,
}

pub(super) trait Items {
    /// Attributes only; must never prompt or read secret data.
    fn exists(&self, reference: &str) -> Result<bool, SdkError>;
    fn read(&self, reference: &str, presence: bool)
    -> Result<Option<Zeroizing<Vec<u8>>>, SdkError>;
    /// Insert only, without replacing an existing item. Returns false for a duplicate.
    fn insert(&self, reference: &str, bytes: &[u8], presence: bool) -> Result<bool, SdkError>;
    /// Metadata only; never contains a seed or authorization/approval token.
    fn journal(&self, reference: &str, bytes: &[u8]) -> Result<(), SdkError>;
    fn delete(&self, reference: &str) -> Result<(), SdkError>;
}
pub(super) fn protected_reference(reference: &str) -> String {
    format!("presence:v1:{reference}")
}
fn key(bytes: &Zeroizing<Vec<u8>>) -> Result<SelfSigningKey, SdkError> {
    if bytes.len() != 32 {
        return Err(unavailable());
    }
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(bytes);
    Ok(SelfSigningKey::from_vault_seed(&seed))
}

/// Every call reads the protected item under a fresh OS authentication context.
/// Ready metadata cannot replace that read; no flags-0 fallback can authorize a move.
pub(super) fn approved_primary(
    items: &impl Items,
    reference: &str,
    expected: &str,
) -> Result<SelfSigningKey, SdkError> {
    if reference.is_empty() || reference.len() > 256 || reference.chars().any(char::is_control) {
        return Err(unavailable());
    }
    let protected = protected_reference(reference);
    let journal = format!("upgrade:v1:{reference}");
    if let Some(bytes) = items.read(&journal, false)? {
        if bytes.len() > 1024 {
            return Err(unavailable());
        }
        let prior: Upgrade = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
        if prior.version != 1 || prior.public_key != expected {
            return Err(unavailable());
        }
    }
    let save = |stage| {
        let bytes =
            serde_json::to_vec(&Upgrade { version: 1, public_key: expected.into(), stage })?;
        items.journal(&journal, &bytes)
    };
    if items.exists(reference)? {
        // The legacy item is flags 0. A silent read failure must not trigger UI or fallback.
        let legacy = key(&items.read(reference, false)?.ok_or_else(unavailable)?)?;
        if legacy.public_key() != expected {
            return Err(unavailable());
        }
        if !items.exists(&protected)? {
            save(Stage::CopyPlanned)?;
            items.insert(&protected, &*legacy.vault_seed(), true)?;
        }
        drop(legacy);
    }
    if !items.exists(&protected)? {
        return Err(unavailable());
    }
    save(Stage::PresencePending)?;
    let primary = key(&items.read(&protected, true)?.ok_or_else(unavailable)?)?;
    if primary.public_key() != expected {
        return Err(unavailable());
    }
    save(Stage::Verified)?;
    if items.exists(reference)? {
        save(Stage::DeleteLegacy)?;
        items.delete(reference)?;
    }
    if items.exists(reference)? {
        return Err(unavailable());
    }
    save(Stage::Ready)?;
    Ok(primary)
}

#[cfg(test)]
mod tests;
