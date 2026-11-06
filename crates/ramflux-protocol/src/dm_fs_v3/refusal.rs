// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native refusal codes, deliberately distinct from admission capacity and busy.
use super::DecodeError;
/// Closed stable wire values for `DmFsV3Refusal`; unknown and empty codes reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmFsV3Refusal {
    /// Wire code `native_publication_requires_custody`.
    NativePublicationRequiresCustody,
    /// Wire code `native_account_required`.
    NativeAccountRequired,
    /// Wire code `prekey_profile_inactive`.
    PrekeyProfileInactive,
    /// Wire code `prekey_cross_home_unavailable`.
    PrekeyCrossHomeUnavailable,
    /// Wire code `prekey_clock_untrusted`.
    PrekeyClockUntrusted,
    /// Wire code `prekey_capacity`.
    PrekeyCapacity,
    /// Wire code `prekey_repair_required`.
    PrekeyRepairRequired,
    /// Wire code `prekey_refresh_required`.
    PrekeyRefreshRequired,
    /// Wire code `prekey_lease_unavailable`.
    PrekeyLeaseUnavailable,
    /// Wire code `bootstrap_key_unavailable`.
    BootstrapKeyUnavailable,
    /// Wire code `update_required`.
    UpdateRequired,
    /// Wire code `replay`.
    Replay,
    /// Wire code `busy`.
    Busy,
    /// Wire code `persistence_unavailable`.
    PersistenceUnavailable,
    /// Wire code `capacity`.
    Capacity,
}
impl DmFsV3Refusal {
    /// Stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativePublicationRequiresCustody => "native_publication_requires_custody",
            Self::NativeAccountRequired => "native_account_required",
            Self::PrekeyProfileInactive => "prekey_profile_inactive",
            Self::PrekeyCrossHomeUnavailable => "prekey_cross_home_unavailable",
            Self::PrekeyClockUntrusted => "prekey_clock_untrusted",
            Self::PrekeyCapacity => "prekey_capacity",
            Self::PrekeyRepairRequired => "prekey_repair_required",
            Self::PrekeyRefreshRequired => "prekey_refresh_required",
            Self::PrekeyLeaseUnavailable => "prekey_lease_unavailable",
            Self::BootstrapKeyUnavailable => "bootstrap_key_unavailable",
            Self::UpdateRequired => "update_required",
            Self::Replay => "replay",
            Self::Busy => "busy",
            Self::PersistenceUnavailable => "persistence_unavailable",
            Self::Capacity => "capacity",
        }
    }
}
impl TryFrom<&str> for DmFsV3Refusal {
    type Error = DecodeError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "native_publication_requires_custody" => Ok(Self::NativePublicationRequiresCustody),
            "native_account_required" => Ok(Self::NativeAccountRequired),
            "prekey_profile_inactive" => Ok(Self::PrekeyProfileInactive),
            "prekey_cross_home_unavailable" => Ok(Self::PrekeyCrossHomeUnavailable),
            "prekey_clock_untrusted" => Ok(Self::PrekeyClockUntrusted),
            "prekey_capacity" => Ok(Self::PrekeyCapacity),
            "prekey_repair_required" => Ok(Self::PrekeyRepairRequired),
            "prekey_refresh_required" => Ok(Self::PrekeyRefreshRequired),
            "prekey_lease_unavailable" => Ok(Self::PrekeyLeaseUnavailable),
            "bootstrap_key_unavailable" => Ok(Self::BootstrapKeyUnavailable),
            "update_required" => Ok(Self::UpdateRequired),
            "replay" => Ok(Self::Replay),
            "busy" => Ok(Self::Busy),
            "persistence_unavailable" => Ok(Self::PersistenceUnavailable),
            "capacity" => Ok(Self::Capacity),
            _ => Err(DecodeError::Value),
        }
    }
}
