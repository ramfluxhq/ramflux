// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    AbuseReportRecord, AbuseReportRequest, AbuseReportResponse, FrankingReportStatus,
    ItestMvp7MetadataSummary, NodeCoreError, RetentionMetadataRecord, RouterCore,
    selected_evidence_hash, verify_selected_franking_evidence,
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
        let verification = verify_selected_franking_evidence(&request.selected_evidence);
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
    pub fn mvp7_metadata_summary(&self, principal_id: &str) -> ItestMvp7MetadataSummary {
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
