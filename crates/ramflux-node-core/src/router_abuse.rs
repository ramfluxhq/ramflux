// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    AbuseReportRecord, AbuseReportRequest, AbuseReportResponse, FrankingReportStatus,
    LifecycleMetadataSummary, NodeCoreError, RetentionMetadataRecord, RouterCore,
    selected_evidence_hash, verify_selected_franking_evidence,
    verify_selected_franking_evidence_with_node_public_key,
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

impl RouterCore {
    /// # Errors
    /// Returns an error when report metadata cannot be serialized.
    pub fn mvp7_submit_abuse_report(
        &self,
        request: &AbuseReportRequest,
    ) -> Result<AbuseReportResponse, NodeCoreError> {
        let evidence_hash = selected_evidence_hash(&request.selected_evidence)?;
        let node_franking_public_key = self.node_franking_public_key();
        let verification = match node_franking_public_key.as_deref() {
            Some(public_key) => verify_selected_franking_evidence_with_node_public_key(
                &request.selected_evidence,
                public_key,
            ),
            None => verify_selected_franking_evidence(&request.selected_evidence),
        };
        let (status, reason, verified_commitment) = match verification {
            Ok(commitment) => (
                FrankingReportStatus::Verified,
                "franking evidence verified".to_owned(),
                Some(commitment),
            ),
            Err(reason) => (FrankingReportStatus::Rejected, reason, None),
        };
        let retention_policy_id = "selected_evidence.unresolved_90_days".to_owned();
        let expires_at = request.submitted_at.saturating_add(90 * 24 * 60 * 60);
        let report = AbuseReportRecord {
            report_id: request.report_id.clone(),
            reporter_identity: request.reporter_identity.clone(),
            reported_identity: request.reported_identity.clone(),
            reported_node: request.reported_node.clone(),
            status,
            reason,
            verified_commitment,
            evidence_hash: evidence_hash.clone(),
            retention_policy_id: retention_policy_id.clone(),
            expires_at,
        };
        let retention_record = RetentionMetadataRecord {
            record_id: format!("selected_evidence_{}", request.report_id),
            subject_hash: request.reported_identity.clone(),
            metadata_class: "selected_evidence".to_owned(),
            source_service_id: "ramflux-router".to_owned(),
            retention_policy_id,
            created_at: request.submitted_at,
            expires_at,
            delete_after_ack: None,
            legal_hold: false,
            legal_hold_next_review_at: None,
            legal_basis: None,
            legal_hold_actor: None,
            legal_hold_created_at: None,
            metadata_hash: evidence_hash,
        };
        crate::lock_unpoisoned(&self.control)
            .abuse_reports
            .insert(request.report_id.clone(), report.clone());
        Ok(AbuseReportResponse { report, retention_record })
    }

    #[must_use]
    pub fn mvp7_abuse_report(&self, report_id: &str) -> Option<AbuseReportRecord> {
        crate::lock_unpoisoned(&self.control).abuse_reports.get(report_id).cloned()
    }

    #[must_use]
    pub fn mvp7_metadata_summary(&self, principal_id: &str) -> LifecycleMetadataSummary {
        let control = crate::lock_unpoisoned(&self.control);
        let target_delivery_id =
            control.mvp1_identities.target_delivery_id_for_principal(principal_id);
        let session_bound = target_delivery_id
            .is_some_and(|target| self.target_shard(target).registry.contains_target(target));
        let pending_inbox_count = target_delivery_id
            .map(|target| self.target_shard(target).inbox.pull_after(target, 0, usize::MAX).len())
            .unwrap_or_default();
        let lifecycle = control.lifecycle_by_principal.get(principal_id);
        control.mvp1_identities.metadata_summary(
            principal_id,
            session_bound,
            pending_inbox_count,
            lifecycle.and_then(|record| record.tombstone_hash.clone()),
            lifecycle
                .and_then(|record| record.deletion_proof.as_ref())
                .map(|proof| proof.proof_hash.clone()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrankingEvidenceKind, NodeFrankingTagInput, NodeServiceSigningKey};

    #[test]
    fn abuse_report_fails_closed_without_node_franking_public_key() -> Result<(), NodeCoreError> {
        let router = RouterCore::new();
        let (request, _signer) = signed_abuse_report("report_no_key");

        let response = router.mvp7_submit_abuse_report(&request)?;

        assert_eq!(response.report.status, FrankingReportStatus::Rejected);
        assert_eq!(response.report.reason, "node franking public key unavailable");
        assert!(response.report.verified_commitment.is_none());
        Ok(())
    }

    #[test]
    fn abuse_report_verifies_with_configured_node_franking_public_key() -> Result<(), NodeCoreError>
    {
        let router = RouterCore::new();
        let (request, signer) = signed_abuse_report("report_real_key");
        router.set_node_franking_public_key(Some(signer.public_key_base64url().to_owned()));

        let response = router.mvp7_submit_abuse_report(&request)?;

        assert_eq!(response.report.status, FrankingReportStatus::Verified);
        assert_eq!(response.report.reason, "franking evidence verified");
        assert_eq!(
            response.report.verified_commitment.as_deref(),
            Some(request.selected_evidence.commitment.as_str())
        );
        Ok(())
    }

    #[test]
    fn abuse_report_rejects_wrong_node_franking_public_key() -> Result<(), NodeCoreError> {
        let router = RouterCore::new();
        let (request, _signer) = signed_abuse_report("report_wrong_key");
        let wrong_signer = NodeServiceSigningKey::from_seed([0x72; 32]);
        router.set_node_franking_public_key(Some(wrong_signer.public_key_base64url().to_owned()));

        let response = router.mvp7_submit_abuse_report(&request)?;

        assert_eq!(response.report.status, FrankingReportStatus::Rejected);
        assert!(response.report.reason.contains("node franking tag mismatch"));
        assert!(response.report.verified_commitment.is_none());
        Ok(())
    }

    fn signed_abuse_report(report_id: &str) -> (AbuseReportRequest, NodeServiceSigningKey) {
        let signer = NodeServiceSigningKey::from_seed([0x71; 32]);
        let opening_key = [0x41; 32];
        let commitment_key = [0x42; 32];
        let sender_device_id_hash = [0x43; 32];
        let plaintext = "selected abuse excerpt";
        let canonical_header_bytes = b"abuse-header";
        let associated_data = b"abuse-ad";
        let ciphertext = b"abuse-ciphertext";
        let message_event_id = "msg_abuse_report_real";
        let commitment =
            ramflux_crypto::franking_commitment(&ramflux_crypto::FrankingCommitmentInput {
                plaintext: plaintext.as_bytes(),
                sender_device_id_hash: &sender_device_id_hash,
                message_event_id,
                canonical_header_bytes,
                associated_data,
                ciphertext,
                opening_key: &opening_key,
                commitment_key: &commitment_key,
            });
        let franking_timestamp = 1_760_000_700;
        let franking_tag = signer.sign_franking_node_tag(NodeFrankingTagInput {
            node_id: "node-abuse-real",
            envelope_id: "env-abuse-real",
            message_event_id,
            sender_device_id_hash: &sender_device_id_hash,
            commitment: &commitment.commitment,
            ciphertext_hash: &commitment.ciphertext_hash,
            accepted_at_unix_ms: franking_timestamp,
        });
        let request = AbuseReportRequest {
            report_id: report_id.to_owned(),
            reporter_identity: "reporter_abuse_real".to_owned(),
            reported_identity: "reported_abuse_real".to_owned(),
            reported_node: "node-abuse-real".to_owned(),
            selected_evidence: crate::SelectedFrankingEvidence {
                evidence_kind: FrankingEvidenceKind::ReceiverAttestedDm,
                node_id: "node-abuse-real".to_owned(),
                envelope_id: "env-abuse-real".to_owned(),
                plaintext_excerpt: plaintext.to_owned(),
                opening_key: ramflux_protocol::encode_base64url(opening_key),
                commitment_key: ramflux_protocol::encode_base64url(commitment_key),
                sender_device_id_hash: ramflux_protocol::encode_base64url(sender_device_id_hash),
                msg_event_id: message_event_id.to_owned(),
                canonical_header_bytes: ramflux_protocol::encode_base64url(canonical_header_bytes),
                associated_data: ramflux_protocol::encode_base64url(associated_data),
                ciphertext: ramflux_protocol::encode_base64url(ciphertext),
                header_hash: commitment.header_hash,
                associated_data_hash: commitment.associated_data_hash,
                ciphertext_hash: commitment.ciphertext_hash,
                franking_commitment: commitment.franking_commitment,
                commitment: commitment.commitment,
                franking_tag,
                franking_timestamp,
                group_header_signature: None,
            },
            submitted_at: franking_timestamp,
        };
        (request, signer)
    }
}
