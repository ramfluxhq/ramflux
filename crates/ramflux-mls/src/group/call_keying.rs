// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! MLS-CALL key layer: the `SFrame` base key of one call, read from the MLS exporter.
//!
//! This is the RFC 9605 section 5.2 profile with a per-call context. The exporter label is the
//! RFC's `"SFrame 1.0 Base Key"`; the RFC context is empty, ours is [`call_context`], so two calls
//! in one epoch of one group never share a base key (and so never share keys, salts or counters).
//!
//! Context bytes, exactly (audit L2): `b"rf-call-v1"` (10 bytes, no NUL) followed by one byte
//! `len` followed by the call id as its ASCII text (`len` bytes, `1..=255`; the SDK's id is
//! base64url, 22 bytes today). Total `11 + len` bytes. Nothing else is mixed in.
//!
//! [`Mls::call_keying`] reads the epoch, the own leaf, the member list and the exporter value in
//! one storage operation, so no commit can land between them. It stores nothing. The base key is
//! wiped when dropped and never appears in `Debug` output.

use std::fmt;

use zeroize::Zeroizing;

use super::Mls;
use crate::MlsError;
use crate::credential::{self, MemberIdentity};
use crate::storage::kv::MlsKv;

/// The exporter label (RFC 9605 section 5.2).
pub const CALL_EXPORT_LABEL: &str = "SFrame 1.0 Base Key";

/// The fixed prefix of the exporter context.
pub const CALL_CONTEXT_PREFIX: &[u8; 10] = b"rf-call-v1";

/// Base key length: `AEAD.Nk` of suite 5 (`AES_256_GCM_SHA512_128`).
pub const CALL_BASE_KEY_LEN: usize = 32;

/// Longest call id the context can carry (one length byte).
pub const CALL_ID_MAX_LEN: usize = 255;

/// Leaf indexes at or above this do not fit the 16-bit leaf field of the call KID.
pub const CALL_LEAF_LIMIT: u32 = 1 << 16;

/// The exporter context of `call_id`: [`CALL_CONTEXT_PREFIX`] || `u8(len)` || `call_id` bytes.
///
/// # Errors
/// `policy_rejected` when the id is empty or longer than [`CALL_ID_MAX_LEN`] bytes.
pub fn call_context(call_id: &str) -> Result<Vec<u8>, MlsError> {
    let bytes = call_id.as_bytes();
    let len = match u8::try_from(bytes.len()) {
        Ok(len) if len > 0 => len,
        _ => return Err(MlsError::PolicyRejected("call id length must be 1..=255".to_owned())),
    };
    let mut context = Vec::with_capacity(CALL_CONTEXT_PREFIX.len() + 1 + bytes.len());
    context.extend_from_slice(CALL_CONTEXT_PREFIX);
    context.push(len);
    context.extend_from_slice(bytes);
    Ok(context)
}

/// One member of the key-source group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallMember {
    /// Leaf index (below [`CALL_LEAF_LIMIT`]).
    pub leaf: u32,
    /// Root commitment (device credentials).
    pub root_commitment: Option<String>,
    /// Device id (device credentials).
    pub device_id: Option<String>,
}

/// The call key material of one group epoch.
pub struct CallKeying {
    /// The group epoch the key was exported from.
    pub epoch: u64,
    /// Own leaf index (below [`CALL_LEAF_LIMIT`]).
    pub own_leaf: u32,
    /// The `SFrame` base key; wiped when dropped.
    pub base_key: Zeroizing<[u8; CALL_BASE_KEY_LEN]>,
    /// Every member, bounded by the group's leaf cap.
    pub members: Vec<CallMember>,
}

impl fmt::Debug for CallKeying {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallKeying")
            .field("epoch", &self.epoch)
            .field("own_leaf", &self.own_leaf)
            .field("base_key", &"<redacted>")
            .field("members", &self.members.len())
            .finish()
    }
}

impl<K: MlsKv> Mls<K> {
    /// The call key material of `call_id` in the current epoch of `group_id`.
    ///
    /// Epoch, own leaf, members and the exporter value come from one operation. Nothing is
    /// stored.
    ///
    /// # Errors
    /// `policy_rejected` for a bad call id or a leaf at or above [`CALL_LEAF_LIMIT`],
    /// `not_found` for an unknown group, or a provider failure.
    pub fn call_keying(&self, group_id: &[u8], call_id: &str) -> Result<CallKeying, MlsError> {
        let context = call_context(call_id)?;
        let op = self.begin()?;
        let loaded = Self::load(&op, group_id)?;
        let own_leaf = loaded.group.own_leaf_index().u32();
        if own_leaf >= CALL_LEAF_LIMIT {
            return Err(MlsError::PolicyRejected("own leaf exceeds the call KID range".to_owned()));
        }
        let mut members = Vec::new();
        for member in loaded.group.members() {
            let leaf = member.index.u32();
            if leaf >= CALL_LEAF_LIMIT || members.len() >= loaded.leaf_cap {
                return Err(MlsError::PolicyRejected(
                    "member leaf exceeds the call bound".to_owned(),
                ));
            }
            let (root_commitment, device_id) =
                match credential::describe(loaded.kind, &member.credential, &member.signature_key)?
                {
                    MemberIdentity::Device(device) => {
                        (Some(device.root_commitment.clone()), Some(device.device_id.clone()))
                    }
                    _ => (None, None),
                };
            members.push(CallMember { leaf, root_commitment, device_id });
        }
        let secret = loaded
            .group
            .export_secret(self.crypto.crypto(), CALL_EXPORT_LABEL, &context, CALL_BASE_KEY_LEN)
            .map_err(MlsError::mls)?;
        let mut base_key = Zeroizing::new([0_u8; CALL_BASE_KEY_LEN]);
        if secret.as_slice().len() != CALL_BASE_KEY_LEN {
            return Err(MlsError::internal("exporter returned a wrong length"));
        }
        base_key.copy_from_slice(secret.as_slice());
        Ok(CallKeying { epoch: loaded.group.epoch().as_u64(), own_leaf, base_key, members })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_bytes_are_prefix_len_id() {
        let context = call_context("abc").unwrap_or_default();
        assert_eq!(context, b"rf-call-v1\x03abc");
        let id = "A".repeat(22);
        let context = call_context(&id).unwrap_or_default();
        assert_eq!(context.len(), 11 + 22);
        assert_eq!(context.get(10), Some(&22));
    }

    #[test]
    fn context_refuses_empty_and_long_ids() {
        assert!(call_context("").is_err());
        assert!(call_context(&"x".repeat(256)).is_err());
        assert!(call_context(&"x".repeat(255)).is_ok());
    }

    #[test]
    fn different_calls_get_different_contexts() {
        assert_ne!(call_context("a").ok(), call_context("b").ok());
    }

    #[test]
    fn debug_never_prints_the_key() {
        let keying = CallKeying {
            epoch: 3,
            own_leaf: 1,
            base_key: Zeroizing::new([0xAB; CALL_BASE_KEY_LEN]),
            members: Vec::new(),
        };
        let text = format!("{keying:?}");
        assert!(text.contains("redacted"));
        assert!(!text.contains("171") && !text.to_lowercase().contains("ab, ab"));
    }
}
