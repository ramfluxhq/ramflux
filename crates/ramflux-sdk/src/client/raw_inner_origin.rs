// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private first-hand origin material, sharing the audited history authority verifier.
use crate::client::routed::Opened;
#[cfg(test)]
use crate::client::routed::Routing;
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message::{self as g, original_header::EvidenceError};
mod group;
#[cfg(test)]
mod group_golden_tests;
#[cfg(test)]
mod group_tests;

pub(crate) use ramflux_crypto::native_origin::{RetainedOrigin, VerifiedOrigin};

impl RamfluxClient {
    pub(crate) fn capture_retained_origin(
        &self,
        opened: &Opened,
        entry: &crate::GatewayInboxEntry,
    ) -> Result<Option<RetainedOrigin>, SdkError> {
        if opened.routing.group_id.is_some() {
            return Ok(None);
        }
        self.capture_origin_material(opened, entry)
    }

    fn capture_origin_material(
        &self,
        opened: &Opened,
        entry: &crate::GatewayInboxEntry,
    ) -> Result<Option<RetainedOrigin>, SdkError> {
        if entry.envelope.schema != g::outer::CANDIDATE_ENVELOPE_SCHEMA {
            return Ok(None);
        }
        let parsed = ramflux_crypto::parse_report_plaintext(&opened.decrypted.plaintext)?;
        let authority = self
            .current_custody_evidence(
                opened.remote_device.root_commitment(),
                crate::custody::network_now()?,
            )?
            .ok_or(EvidenceError::OriginEvidenceMissing)?;
        let manifest = ramflux_protocol::custody::CustodyManifest {
            publication: authority.publication,
            custodian_publication: authority.custodian_publication,
            devices: Vec::new(),
        };
        Ok(Some(RetainedOrigin {
            evidence: g::HistoryOriginEvidence {
                canonical_sender_envelope: ramflux_protocol::sender_origin_evidence(
                    &entry.envelope,
                )?,
                source_authority: Some(g::NativeCustodyManifest {
                    canonical: ramflux_protocol::canonical_json_bytes(&manifest)?,
                }),
                report_opening: parsed.opening().to_vec(),
                ..Default::default()
            },
            reported_inner: if parsed.inner() == opened.body.as_slice() {
                Vec::new()
            } else {
                parsed.inner().to_vec()
            },
            routing: opened.routing.clone(),
        }))
    }
}

impl RamfluxClient {
    pub(crate) fn retain_raw_origin_copy(
        &self,
        owner: &str,
        source: &str,
        copy_id: &str,
        origin: &RetainedOrigin,
        target: Option<&g::MessageRef>,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let encoded = zeroize::Zeroizing::new(serde_json::to_vec(origin)?);
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: owner,
            verified_source_anchor: source,
            copy_id,
            kind: ramflux_storage::RawInnerCopyKind::SourceEvidence,
            bytes: &encoded,
            bounded_metadata: b"source evidence",
        })?;
        if let Some(target) = target {
            db.bind_raw_inner_copy(copy_id, &ramflux_protocol::encode_base64url(&target.id))?;
        }
        Ok(())
    }
}

impl RamfluxClient {
    pub(crate) fn persist_known_origin(
        &self,
        owner: &str,
        origin: &RetainedOrigin,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if db.message_is_deleted(owner)?
            || db
                .load_actor_state::<bool>(&format!("routed/report-opening-retired/{owner}"))?
                .unwrap_or(false)
        {
            return Err(EvidenceError::ReportOpeningRetired.into());
        }
        let encoded = zeroize::Zeroizing::new(serde_json::to_vec(origin)?);
        // Known evidence follows ordinary local-history policy, not Unsupported owner quotas.
        // Bound the private record by the existing history-container limit before persistence.
        if encoded.len() > 4 * 1024 * 1024 {
            return Err(EvidenceError::OriginCommitmentMismatch.into());
        }
        self.account_db()?.persist_message_actor_state(
            owner,
            &format!("routed/origin-evidence/{owner}"),
            origin,
        )?;
        Ok(())
    }
}
