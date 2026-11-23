// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed person / AI classification. Safety-number trust is a separate fact.
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::PrincipalKind;
use serde::Serialize;
use std::path::Path;

/// Account class taken from the accepted signed custody record.
///
/// `person` and `ai_agent` require the device set, its master certificate, and
/// its profile to name that same kind. A card label, a stored assertion, and a
/// safety-number check do not produce either value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedClassification {
    /// The accepted record names a human principal.
    Person,
    /// The accepted record names a headless AI principal.
    AiAgent,
    /// No current signed person or AI class is available.
    Unknown,
}

impl VerifiedClassification {
    /// JSON field every identity and contact fact uses for this value.
    pub const FIELD: &str = "verified_classification";

    /// Wire name: `person`, `ai_agent`, or `unknown`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::AiAgent => "ai_agent",
            Self::Unknown => "unknown",
        }
    }
}

impl RamfluxClient {
    /// Classify `principal` from current signed custody only.
    ///
    /// The local account uses its accepted authority file. Any other principal
    /// uses the observed custody publication for that identity's commitment.
    /// A missing publication, a label with no publication, and a stale or
    /// fenced head are [`VerifiedClassification::Unknown`].
    ///
    /// # Errors
    /// Returns storage and I/O errors. Authority that does not verify is
    /// [`VerifiedClassification::Unknown`].
    pub fn verified_classification(
        &self,
        principal: &str,
    ) -> Result<VerifiedClassification, SdkError> {
        if principal.is_empty() {
            return Ok(VerifiedClassification::Unknown);
        }
        if let Some(class) = self.own_marker(principal)? {
            return Ok(class);
        }
        self.observed_marker(principal)
    }

    fn own_marker(&self, principal: &str) -> Result<Option<VerifiedClassification>, SdkError> {
        let Some(own) = &self.born_v3_account else {
            return Ok(None);
        };
        if own.record().body.principal_id != principal {
            return Ok(None);
        }
        let now = crate::custody::network_now()?;
        let root = authority_root(self)?;
        match crate::custody::load_data_account(root, own.local_account_id(), now) {
            Ok(current) => Ok(Some(loaded_class(&current, principal))),
            Err(error) if authority_unusable(&error) => Ok(Some(VerifiedClassification::Unknown)),
            Err(error) => Err(error),
        }
    }

    fn observed_marker(&self, principal: &str) -> Result<VerifiedClassification, SdkError> {
        let Some(row) = self.account_db()?.client_record("identity", principal)? else {
            return Ok(VerifiedClassification::Unknown);
        };
        let Some(anchor) = row.get("contact_identity_commitment").and_then(|value| value.as_str())
        else {
            return Ok(VerifiedClassification::Unknown);
        };
        if anchor.is_empty() {
            return Ok(VerifiedClassification::Unknown);
        }
        // `kind` and `kind_asserted` on this row are not an authority input.
        let now = crate::custody::network_now()?;
        match self.current_custody_authority(anchor, now) {
            Ok(Some(record)) => Ok(from_verified(&record, principal)),
            Ok(None) => Ok(VerifiedClassification::Unknown),
            Err(error) if authority_unusable(&error) => Ok(VerifiedClassification::Unknown),
            Err(error) => Err(error),
        }
    }
}

fn loaded_class(current: &crate::custody::BornAccount, principal: &str) -> VerifiedClassification {
    if current.authority_blocked() {
        return VerifiedClassification::Unknown;
    }
    from_verified(current.verified(), principal)
}

fn from_verified(record: &VerifiedRecord, principal: &str) -> VerifiedClassification {
    let body = &record.envelope().body;
    let cert = &body.master_certificate.body;
    if body.principal_id != principal
        || body.principal_kind != cert.principal_kind
        || body.profile.kind != body.principal_kind
    {
        return VerifiedClassification::Unknown;
    }
    match body.principal_kind {
        PrincipalKind::Human => VerifiedClassification::Person,
        PrincipalKind::HeadlessAi => VerifiedClassification::AiAgent,
        PrincipalKind::Bot | PrincipalKind::Workflow => VerifiedClassification::Unknown,
    }
}

fn authority_root(client: &RamfluxClient) -> Result<&Path, SdkError> {
    if let Some(root) = &client.reader_account_root {
        return Ok(root.as_path());
    }
    Ok(client.account_index()?.root())
}

fn authority_unusable(error: &SdkError) -> bool {
    matches!(
        error,
        SdkError::Crypto(_)
            | SdkError::InboundRejected(_)
            | SdkError::CustodyForkFenced
            | SdkError::CustodyModeDowngrade
            | SdkError::CustodySetupInvalid
            | SdkError::PairingCode(_)
            | SdkError::NetworkingPending
            | SdkError::FreshHeadRequired { .. }
    )
}
