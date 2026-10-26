// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded relationship snapshots inside the authenticated encrypted account backup.
use crate::{RamfluxClient, SdkError};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BackupContactSkipReason {
    StaleAuthority,
    PinnedConflict,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct BackupContactSkipCount {
    pub(crate) reason: BackupContactSkipReason,
    pub(crate) count: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub(crate) struct BackupContactRestoreReport {
    pub(crate) restored: usize,
    pub(crate) skipped: Vec<BackupContactSkipCount>,
}

impl BackupContactRestoreReport {
    fn record_skip(&mut self, reason: BackupContactSkipReason) {
        if let Some(entry) = self.skipped.iter_mut().find(|entry| entry.reason == reason) {
            entry.count += 1;
        } else {
            self.skipped.push(BackupContactSkipCount { reason, count: 1 });
        }
    }
}

impl RamfluxClient {
    pub(crate) fn backup_contacts(&self) -> Result<Vec<String>, SdkError> {
        // Preserve the legacy key-backup format's admission budget. Full jobs copy all rows.
        let mut bytes = 0;
        Ok(self
            .own_history_contacts()?
            .into_iter()
            .take(512)
            .take_while(|packet| {
                bytes += packet.len();
                bytes <= 3 * 1024 * 1024
            })
            .collect())
    }

    pub(crate) fn restore_backup_contacts(
        &self,
        contacts: &[String],
    ) -> Result<BackupContactRestoreReport, SdkError> {
        if contacts.len() > 512 || contacts.iter().map(String::len).sum::<usize>() > 3 * 1024 * 1024
        {
            return Err(SdkError::InboundRejected("backup contact snapshot exceeds budget".into()));
        }
        let mut report = BackupContactRestoreReport::default();
        // Only call after backup AEAD authentication. Each relationship must name this root;
        // peer manifests still verify and existing local restrictions always win.
        self.account_db()?.write_transaction(|| {
            for contact in contacts {
                let body = ramflux_protocol::decode_base64url(contact).map_err(|error| {
                    SdkError::LocalBus(format!("invalid backup contact encoding: {error}"))
                })?;
                if let Some(reason) = self.backup_contact_skip_reason(&body)? {
                    report.record_skip(reason);
                    continue;
                }
                if !self.receive_own_contact(&body)? {
                    return Err(SdkError::InboundRejected("invalid backup contact packet".into()));
                }
                report.restored += 1;
            }
            Ok(())
        })?;
        Ok(report)
    }
}
