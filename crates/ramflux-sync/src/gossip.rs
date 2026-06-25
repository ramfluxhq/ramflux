// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use crate::SyncError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactGossipReport {
    pub reporter_identity_commitment: String,
    pub subject_identity_commitment: String,
    pub lineage_head: String,
    pub device_set_hash: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactGossipExpectation<'a> {
    pub subject_identity_commitment: &'a str,
    pub lineage_head: &'a str,
    pub device_set_hash: &'a str,
}

/// # Errors
/// Returns an error when contact gossip reports a conflicting lineage or device-set checkpoint.
pub fn verify_contact_gossip_checkpoint(
    expectation: ContactGossipExpectation<'_>,
    reports: &[ContactGossipReport],
) -> Result<(), SyncError> {
    for report in reports.iter().filter(|report| {
        report.subject_identity_commitment == expectation.subject_identity_commitment
    }) {
        if report.lineage_head != expectation.lineage_head
            || report.device_set_hash != expectation.device_set_hash
        {
            return Err(SyncError::ContactGossipFork);
        }
    }
    Ok(())
}
