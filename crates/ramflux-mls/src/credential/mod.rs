// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The two private-use credential types and the (credential, leaf signature key) verification.
//!
//! * `0xF0D1` device credential: direct-message groups (`dm`).
//! * `0xF0D2` pseudonym credential: groups of every size (`group`).
//!
//! The group kind decides which single type a leaf may carry. A credential is never judged alone:
//! the pair with the leaf's signature key is, because a valid credential copied into another leaf
//! must not pass (RFC 9420 5.3.1).

pub mod device;
pub mod device_sets;
pub mod pseudonym;

use openmls::prelude::{Credential, CredentialType};

use crate::storage::MlsStorage;
use crate::storage::kv::MlsKv;
use crate::{CREDENTIAL_TYPE_DEVICE, CREDENTIAL_TYPE_PSEUDONYM, MAX_CREDENTIAL_BYTES, MlsError};

pub use self::device::{DeviceCertSigner, DeviceIdentity};

/// The two group kinds. There is no third kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupKind {
    /// A two-principal conversation, one leaf per device, credential `0xF0D1`.
    Dm,
    /// Every group of any size, credential `0xF0D2`.
    Group,
}

impl GroupKind {
    /// Stored and wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dm => "dm",
            Self::Group => "group",
        }
    }

    /// Parse the stored or wire spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "dm" => Some(Self::Dm),
            "group" => Some(Self::Group),
            _ => None,
        }
    }

    /// The one rf credential type the kind allows.
    #[must_use]
    pub fn credential_type(self) -> u16 {
        match self {
            Self::Dm => CREDENTIAL_TYPE_DEVICE,
            Self::Group => CREDENTIAL_TYPE_PSEUDONYM,
        }
    }

    /// The kind that owns a credential type code, if it is one of ours.
    #[must_use]
    pub fn from_credential_type(code: u16) -> Option<Self> {
        match code {
            CREDENTIAL_TYPE_DEVICE => Some(Self::Dm),
            CREDENTIAL_TYPE_PSEUDONYM => Some(Self::Group),
            _ => None,
        }
    }
}

/// A device credential that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMember {
    /// Root commitment of the principal (base64url, from the device-set record).
    pub root_commitment: String,
    /// Device id inside the principal's device set.
    pub device_id: String,
    /// Epoch of the device-set record the credential presented.
    pub device_set_epoch: u64,
    /// The leaf signature key the credential is bound to.
    pub leaf_sig_pk: [u8; 32],
}

/// Identity behind a verified leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemberIdentity {
    /// A device of a principal (`dm`).
    Device(VerifiedMember),
    /// A pseudonym key (`group`).
    Pseudonym {
        /// The pseudonym key, equal to the leaf signature key.
        pseudonym_pk: [u8; 32],
    },
    /// A Basic credential whose signature key was pinned (debug builds only).
    PinnedBasic {
        /// The pinned signature key.
        signature_key: Vec<u8>,
    },
}

impl MemberIdentity {
    /// Principal key for the two-principal limit of `dm`: the root commitment, or the pinned key.
    #[must_use]
    pub fn principal(&self) -> Option<String> {
        match self {
            Self::Device(member) => Some(member.root_commitment.clone()),
            Self::PinnedBasic { signature_key } => Some(hex::encode(signature_key)),
            Self::Pseudonym { .. } => None,
        }
    }

    /// `(root_commitment, device_id)` for the one-leaf-per-device and successor rules.
    #[must_use]
    pub fn device_key(&self) -> Option<(&str, &str)> {
        match self {
            Self::Device(member) => {
                Some((member.root_commitment.as_str(), member.device_id.as_str()))
            }
            _ => None,
        }
    }
}

/// Identity of an already admitted leaf, without the authority checks of [`CredentialPolicy`].
///
/// # Errors
/// [`MlsError::CredentialRejected`] when the credential content is malformed.
pub fn describe(
    kind: GroupKind,
    credential: &Credential,
    leaf_sig_pk: &[u8],
) -> Result<MemberIdentity, MlsError> {
    let leaf_pk: [u8; 32] = leaf_sig_pk
        .try_into()
        .map_err(|_| MlsError::CredentialRejected("leaf signature key length".to_owned()))?;
    match credential.credential_type() {
        CredentialType::Other(code) if code == CREDENTIAL_TYPE_DEVICE && kind == GroupKind::Dm => {
            device::describe(credential.serialized_content(), &leaf_pk).map(MemberIdentity::Device)
        }
        CredentialType::Other(code)
            if code == CREDENTIAL_TYPE_PSEUDONYM && kind == GroupKind::Group =>
        {
            Ok(MemberIdentity::Pseudonym { pseudonym_pk: leaf_pk })
        }
        CredentialType::Basic => {
            Ok(MemberIdentity::PinnedBasic { signature_key: leaf_pk.to_vec() })
        }
        other => Err(MlsError::PolicyRejected(format!(
            "credential type {other:?} does not belong to a {} group",
            kind.as_str()
        ))),
    }
}

/// Verifies pairs for a group kind.
#[derive(Default)]
pub struct CredentialPolicy {
    /// Pinned signature keys. Only debug builds ever write it, so production builds reject every
    /// Basic credential and every pseudonym roster entry.
    pinned: std::sync::Mutex<std::collections::BTreeSet<Vec<u8>>>,
}

impl CredentialPolicy {
    /// A policy with no pinned keys.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin one signature key (interop and group roster, debug builds only).
    ///
    /// # Errors
    /// The pin list lock is poisoned.
    #[cfg(feature = "itest-mls-debug")]
    pub fn pin(&self, signature_key: &[u8]) -> Result<(), MlsError> {
        let mut pinned = self.pinned.lock().map_err(|_| MlsError::internal("pin list poisoned"))?;
        pinned.insert(signature_key.to_vec());
        Ok(())
    }

    /// Keys pinned so far (debug builds only).
    #[cfg(feature = "itest-mls-debug")]
    #[must_use]
    pub fn pinned_keys(&self) -> Vec<Vec<u8>> {
        self.pinned.lock().map(|keys| keys.iter().cloned().collect()).unwrap_or_default()
    }

    /// True when the key was pinned.
    #[must_use]
    pub fn is_pinned(&self, signature_key: &[u8]) -> bool {
        self.pinned.lock().is_ok_and(|keys| keys.contains(signature_key))
    }

    /// Check order: size, credential type against the kind, then the pair (and for devices the
    /// device-set authority).
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] for a wrong type, [`MlsError::CredentialRejected`] for a bad
    /// pair, size, device set or revocation.
    pub fn verify_pair<K: MlsKv>(
        &self,
        storage: &MlsStorage<'_, K>,
        kind: GroupKind,
        credential: &Credential,
        leaf_sig_pk: &[u8],
    ) -> Result<MemberIdentity, MlsError> {
        if credential.serialized_content().len() > MAX_CREDENTIAL_BYTES {
            return Err(MlsError::CredentialRejected("credential exceeds the size cap".to_owned()));
        }
        match credential.credential_type() {
            CredentialType::Other(code) if code == kind.credential_type() => {
                let leaf_pk: [u8; 32] = leaf_sig_pk.try_into().map_err(|_| {
                    MlsError::CredentialRejected("leaf signature key length".to_owned())
                })?;
                match kind {
                    GroupKind::Dm => {
                        device::verify(storage, credential.serialized_content(), &leaf_pk)
                            .map(MemberIdentity::Device)
                    }
                    GroupKind::Group => {
                        pseudonym::verify(credential.serialized_content(), &leaf_pk)
                            .map(|pseudonym_pk| MemberIdentity::Pseudonym { pseudonym_pk })
                    }
                }
            }
            CredentialType::Basic if self.is_pinned(leaf_sig_pk) => {
                Ok(MemberIdentity::PinnedBasic { signature_key: leaf_sig_pk.to_vec() })
            }
            other => Err(MlsError::PolicyRejected(format!(
                "credential type {other:?} is not allowed in a {} group",
                kind.as_str()
            ))),
        }
    }
}
