// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The Android Keystore seam: what the vault asks of a hardware-backed AES-256-GCM wrapping
//! key, and the rule that refuses every key that is not held by secure hardware.
//!
//! This file depends on nothing but `zeroize`, so the JNI implementation and a host-side fake
//! share one contract. The seed is never a Keystore key: the Keystore key wraps it.

use zeroize::Zeroizing;

/// AES-GCM nonce length the Keystore generates for a randomized encryption.
pub(crate) const GCM_IV_LEN: usize = 12;
/// AES-GCM tag length appended to every ciphertext.
pub(crate) const GCM_TAG_LEN: usize = 16;
/// Largest secret the vault ever wraps (the macOS provider uses the same bound).
pub(crate) const MAX_SECRET_LEN: usize = 1024;

/// Where a Keystore key's material lives, as reported by `KeyInfo.getSecurityLevel()`
/// (API 31+) or derived from `KeyInfo.isInsideSecureHardware()` on older releases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecurityLevel {
    /// `SECURITY_LEVEL_SOFTWARE`, or `isInsideSecureHardware() == false`.
    Software,
    /// `SECURITY_LEVEL_UNKNOWN`: the platform could not say.
    Unknown,
    /// `SECURITY_LEVEL_UNKNOWN_SECURE`: secure, but not identified as TEE or `StrongBox`.
    UnknownSecure,
    /// `SECURITY_LEVEL_TRUSTED_ENVIRONMENT`, or `isInsideSecureHardware() == true` before
    /// API 31.
    TrustedEnvironment,
    /// `SECURITY_LEVEL_STRONGBOX`.
    StrongBox,
}

impl SecurityLevel {
    /// Stable one-byte code shared with the Kotlin helper and the on-disk envelope.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Software => 0,
            Self::TrustedEnvironment => 1,
            Self::StrongBox => 2,
            Self::Unknown => 3,
            Self::UnknownSecure => 4,
        }
    }

    /// Decode a helper or envelope code. An unrecognized code is `Unknown`, which is refused.
    pub(crate) const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Software,
            1 => Self::TrustedEnvironment,
            2 => Self::StrongBox,
            4 => Self::UnknownSecure,
            _ => Self::Unknown,
        }
    }

    /// The fail-closed rule: only a TEE or `StrongBox` key may wrap vault material.
    /// `UnknownSecure` is refused too, because the vault class must name the hardware.
    pub(crate) const fn is_hardware(self) -> bool {
        matches!(self, Self::TrustedEnvironment | Self::StrongBox)
    }
}

/// Which wrapping key an operation uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyKind {
    /// Usable without user authentication after first unlock, and without requiring an
    /// unlocked device, so a push handler can read a branch credential on a locked phone.
    Background,
    /// Requires a fresh user authentication for every use (`BiometricPrompt` with a
    /// `CryptoObject`). Used only by interactive ceremonies.
    Presence,
}

impl KeyKind {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Background => 0,
            Self::Presence => 1,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Background),
            1 => Some(Self::Presence),
            _ => None,
        }
    }
}

/// Whether key generation asks for `StrongBox` first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum StrongBoxPreference {
    /// Generate in the TEE. This is the default: `StrongBox` is slower and absent on many
    /// devices.
    #[default]
    TeeOnly,
    /// Opt in: try `setIsStrongBoxBacked(true)` and fall back to the TEE when the device
    /// throws `StrongBoxUnavailableException`. Never falls back to software.
    PreferStrongBox,
}

/// Why the Keystore refused. No variant carries key material, an alias or a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BridgeError {
    /// The host has not installed the bridge, or the helper class is not reachable.
    NotInstalled,
    /// The generated key is not in secure hardware. The helper deleted it again.
    NotHardwareBacked,
    /// The key does not exist, or was permanently invalidated.
    KeyMissing,
    /// The device has not been unlocked since boot, or user authentication is required.
    Locked,
    /// The user cancelled or failed the presence prompt, or no prompter is registered.
    PresenceRefused,
    /// The ciphertext or its associated data failed authentication.
    Authentication,
    /// Any other Keystore, provider or JNI failure.
    Failed,
}

/// A secret encrypted by a Keystore key. The IV is chosen by the Keystore
/// (`setRandomizedEncryptionRequired` stays at its default, so a caller IV is rejected).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Wrapped {
    pub(crate) iv: [u8; GCM_IV_LEN],
    /// Ciphertext followed by the 128-bit tag.
    pub(crate) ciphertext: Vec<u8>,
}

/// The operations the vault needs from the Android Keystore.
///
/// Implementations must never fall back to a software key: `ensure_key` returns the level
/// the platform reported for the key that now exists, and the vault refuses anything that is
/// not hardware.
pub(crate) trait KeystoreBridge: Send + Sync {
    /// Create the key when absent and report where its material lives.
    fn ensure_key(
        &self,
        kind: KeyKind,
        strongbox: StrongBoxPreference,
    ) -> Result<SecurityLevel, BridgeError>;
    /// Level of an existing key, without creating one. `KeyMissing` when absent.
    fn key_level(&self, kind: KeyKind) -> Result<SecurityLevel, BridgeError>;
    /// Encrypt `plaintext` bound to `aad`.
    fn wrap(&self, kind: KeyKind, aad: &[u8], plaintext: &[u8]) -> Result<Wrapped, BridgeError>;
    /// Decrypt and authenticate. A `Presence` key blocks until the user answered the prompt.
    fn unwrap(
        &self,
        kind: KeyKind,
        aad: &[u8],
        wrapped: &Wrapped,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError>;
    /// Whether an interactive presence prompt can be shown at all.
    fn presence_available(&self) -> bool;
    /// Delete the key. A missing key succeeds.
    fn delete_key(&self, kind: KeyKind) -> Result<(), BridgeError>;
}

/// Accept a reported level or refuse it. This is the only place a level becomes usable.
pub(crate) fn require_hardware(level: SecurityLevel) -> Result<SecurityLevel, BridgeError> {
    if level.is_hardware() { Ok(level) } else { Err(BridgeError::NotHardwareBacked) }
}
