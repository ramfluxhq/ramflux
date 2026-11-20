// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed creation states and failure tokens of an agent creation request (contract §7.3).
//! Stage B drives the local subset; the wire tokens are fixed here so later stages cannot drift.
use serde::{Deserialize, Serialize};

/// Operation state of one agent creation request. Only the local states are reached before the
/// transport and publication stages exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCreationState {
    Preparing,
    PairingPending,
    MetadataPending,
    AuthorizationPending,
    Authorized,
    PublicationPending,
    PublicationUnknown,
    Complete,
    Refused,
    Expired,
    Cancelled,
    CleanupPending,
    RebindPending,
}

impl AgentCreationState {
    /// Stable wire token (equal to the serde name).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::PairingPending => "pairing_pending",
            Self::MetadataPending => "metadata_pending",
            Self::AuthorizationPending => "authorization_pending",
            Self::Authorized => "authorized",
            Self::PublicationPending => "publication_pending",
            Self::PublicationUnknown => "publication_unknown",
            Self::Complete => "complete",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::CleanupPending => "cleanup_pending",
            Self::RebindPending => "rebind_pending",
        }
    }

    /// Refused, expired and cancelled requests hold no pending secrets and accept only replays.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Refused | Self::Expired | Self::Cancelled)
    }
}

/// Specific reason carried beside a state. No prose: a closed token only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentFailure {
    CreationPairingRequired,
    CustodianAuthorityPending,
    AuthorizationRefused,
    CreationPrimaryChanged,
    CustodyKeyUnavailable,
}

impl AgentFailure {
    /// Stable wire token (equal to the serde name).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreationPairingRequired => "creation_pairing_required",
            Self::CustodianAuthorityPending => "custodian_authority_pending",
            Self::AuthorizationRefused => "authorization_refused",
            Self::CreationPrimaryChanged => "creation_primary_changed",
            Self::CustodyKeyUnavailable => "custody_key_unavailable",
        }
    }
}
