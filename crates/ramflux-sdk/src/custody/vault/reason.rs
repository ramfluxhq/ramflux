// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, secret-free reasons for a refused Linux vault operation. Built on every target
//! because `SdkError` carries it; only the Linux provider constructs it.

/// Why a vault operation was refused. The strings are stable wire `reason_code` values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyVaultReason {
    /// The installation root or the requested entry does not exist.
    Missing,
    /// Initialization is incomplete and must be reconciled explicitly.
    InitPending,
    /// A provisioning import is incomplete.
    ImportPending,
    /// Persisted installation or entry state is invalid or fails authentication.
    Corrupt,
    /// Ownership, permissions or file type are unsafe, or access was denied.
    Permission,
    /// The key provider is locked, was cancelled or timed out.
    Locked,
    /// The vault is in use; the caller may retry.
    Busy,
    /// This handle or role holds no primary authority.
    PrimaryUnavailable,
    /// The requested mode or role is not supported by this selection.
    ModeMismatch,
}
impl CustodyVaultReason {
    const ALL: [Self; 9] = [
        Self::Missing,
        Self::InitPending,
        Self::ImportPending,
        Self::Corrupt,
        Self::Permission,
        Self::Locked,
        Self::Busy,
        Self::PrimaryUnavailable,
        Self::ModeMismatch,
    ];
    /// Stable wire `reason_code`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "vault_missing",
            Self::InitPending => "vault_init_pending",
            Self::ImportPending => "vault_import_pending",
            Self::Corrupt => "vault_corrupt",
            Self::Permission => "vault_permission",
            Self::Locked => "vault_locked",
            Self::Busy => "vault_busy",
            Self::PrimaryUnavailable => "vault_primary_unavailable",
            Self::ModeMismatch => "vault_mode_mismatch",
        }
    }
    /// The bus error `code` that carries this reason.
    #[must_use]
    pub const fn wire_code(self) -> &'static str {
        match self {
            Self::ModeMismatch => "CustodySetupInvalid",
            _ => "CustodyVaultUnavailable",
        }
    }
    /// Only a busy vault is worth retrying.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Busy)
    }
    /// Suggested retry delay, for busy only.
    #[must_use]
    pub const fn retry_after_ms(self) -> Option<u64> {
        match self {
            Self::Busy => Some(1_000),
            _ => None,
        }
    }
    /// Fixed operator remedy, for the two pending states only.
    #[must_use]
    pub const fn remedy(self) -> Option<&'static str> {
        match self {
            Self::InitPending => Some("rf_vault_init"),
            Self::ImportPending => Some("provisioning_import_retry"),
            _ => None,
        }
    }
    /// Decode a wire reason, accepted only when it belongs to the given wire `code`.
    /// Unknown strings and mismatched codes return `None` (the caller keeps the unit error).
    #[must_use]
    pub fn from_wire(code: &str, reason: Option<&str>) -> Option<Self> {
        let reason = reason?;
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == reason && candidate.wire_code() == code)
    }
}
impl std::fmt::Display for CustodyVaultReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}
