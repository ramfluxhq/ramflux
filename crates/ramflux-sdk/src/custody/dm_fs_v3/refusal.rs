// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exhaustive native projections and explicitly fallible existing custody projections.
use ramflux_protocol::{
    custody::{CustodyRefusal, RetryHint, RetryScope},
    dm_fs_v3 as p,
};
/// Closed SDK projection of the native refusal surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmFsV3Refusal {
    /// Same stable protocol code.
    NativePublicationRequiresCustody,
    /// Same stable protocol code.
    NativeAccountRequired,
    /// Same stable protocol code.
    PrekeyProfileInactive,
    /// Same stable protocol code.
    PrekeyCrossHomeUnavailable,
    /// Same stable protocol code.
    PrekeyClockUntrusted,
    /// Same stable protocol code.
    PrekeyCapacity,
    /// Same stable protocol code.
    PrekeyRepairRequired,
    /// Same stable protocol code.
    PrekeyRefreshRequired,
    /// Same stable protocol code.
    PrekeyLeaseUnavailable,
    /// Same stable protocol code.
    BootstrapKeyUnavailable,
    /// Same stable protocol code.
    UpdateRequired,
    /// Same stable protocol code.
    Replay,
    /// Same stable protocol code.
    Busy,
    /// Same stable protocol code.
    PersistenceUnavailable,
    /// Same stable protocol code.
    Capacity,
}
impl From<p::DmFsV3Refusal> for DmFsV3Refusal {
    fn from(value: p::DmFsV3Refusal) -> Self {
        match value {
            p::DmFsV3Refusal::NativePublicationRequiresCustody => {
                Self::NativePublicationRequiresCustody
            }
            p::DmFsV3Refusal::NativeAccountRequired => Self::NativeAccountRequired,
            p::DmFsV3Refusal::PrekeyProfileInactive => Self::PrekeyProfileInactive,
            p::DmFsV3Refusal::PrekeyCrossHomeUnavailable => Self::PrekeyCrossHomeUnavailable,
            p::DmFsV3Refusal::PrekeyClockUntrusted => Self::PrekeyClockUntrusted,
            p::DmFsV3Refusal::PrekeyCapacity => Self::PrekeyCapacity,
            p::DmFsV3Refusal::PrekeyRepairRequired => Self::PrekeyRepairRequired,
            p::DmFsV3Refusal::PrekeyRefreshRequired => Self::PrekeyRefreshRequired,
            p::DmFsV3Refusal::PrekeyLeaseUnavailable => Self::PrekeyLeaseUnavailable,
            p::DmFsV3Refusal::BootstrapKeyUnavailable => Self::BootstrapKeyUnavailable,
            p::DmFsV3Refusal::UpdateRequired => Self::UpdateRequired,
            p::DmFsV3Refusal::Replay => Self::Replay,
            p::DmFsV3Refusal::Busy => Self::Busy,
            p::DmFsV3Refusal::PersistenceUnavailable => Self::PersistenceUnavailable,
            p::DmFsV3Refusal::Capacity => Self::Capacity,
        }
    }
}
impl From<DmFsV3Refusal> for p::DmFsV3Refusal {
    fn from(value: DmFsV3Refusal) -> Self {
        match value {
            DmFsV3Refusal::NativePublicationRequiresCustody => {
                Self::NativePublicationRequiresCustody
            }
            DmFsV3Refusal::NativeAccountRequired => Self::NativeAccountRequired,
            DmFsV3Refusal::PrekeyProfileInactive => Self::PrekeyProfileInactive,
            DmFsV3Refusal::PrekeyCrossHomeUnavailable => Self::PrekeyCrossHomeUnavailable,
            DmFsV3Refusal::PrekeyClockUntrusted => Self::PrekeyClockUntrusted,
            DmFsV3Refusal::PrekeyCapacity => Self::PrekeyCapacity,
            DmFsV3Refusal::PrekeyRepairRequired => Self::PrekeyRepairRequired,
            DmFsV3Refusal::PrekeyRefreshRequired => Self::PrekeyRefreshRequired,
            DmFsV3Refusal::PrekeyLeaseUnavailable => Self::PrekeyLeaseUnavailable,
            DmFsV3Refusal::BootstrapKeyUnavailable => Self::BootstrapKeyUnavailable,
            DmFsV3Refusal::UpdateRequired => Self::UpdateRequired,
            DmFsV3Refusal::Replay => Self::Replay,
            DmFsV3Refusal::Busy => Self::Busy,
            DmFsV3Refusal::PersistenceUnavailable => Self::PersistenceUnavailable,
            DmFsV3Refusal::Capacity => Self::Capacity,
        }
    }
}
impl DmFsV3Refusal {
    /// Stable code comes from the protocol's single value set.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        p::DmFsV3Refusal::from(self).as_str()
    }
    /// Bind a Busy hint to the actual admission source, then clamp with S1 policy.
    /// Authenticated callers supply `NodeCapacity`; only source admission supplies `PreAuthSource`.
    /// # Errors
    /// Rejects hints on non-Busy refusals or hints for a different admission source.
    pub fn retry_hint(
        self,
        hint: Option<RetryHint>,
        source: RetryScope,
    ) -> Result<Option<RetryHint>, p::DecodeError> {
        match hint {
            None => Ok(None),
            Some(hint) if self == Self::Busy && hint.scope == source => Ok(Some(hint.clamped())),
            Some(_) => Err(p::DecodeError::Value),
        }
    }
}
impl TryFrom<&CustodyRefusal> for DmFsV3Refusal {
    type Error = CustodyRefusal;
    fn try_from(value: &CustodyRefusal) -> Result<Self, Self::Error> {
        match value {
            CustodyRefusal::UpdateRequired => Ok(Self::UpdateRequired),
            CustodyRefusal::Replay => Ok(Self::Replay),
            CustodyRefusal::Busy => Ok(Self::Busy),
            CustodyRefusal::PersistenceUnavailable => Ok(Self::PersistenceUnavailable),
            CustodyRefusal::Capacity => Ok(Self::Capacity),
            CustodyRefusal::Unsupported
            | CustodyRefusal::InvalidInput
            | CustodyRefusal::AuthorityUnavailable
            | CustodyRefusal::PrincipalIdTaken
            | CustodyRefusal::ChallengeUnknown
            | CustodyRefusal::ChallengeExpired
            | CustodyRefusal::BindingRefused
            | CustodyRefusal::SessionRequired
            | CustodyRefusal::SessionExpired
            | CustodyRefusal::HomeMigration { .. }
            | CustodyRefusal::AbortedRetrySafe
            | CustodyRefusal::CapacityRetryAfter { .. }
            | CustodyRefusal::IdempotencyConflict
            | CustodyRefusal::PayloadTooLarge => Err(value.clone()),
        }
    }
}
