// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded relationship snapshots inside the authenticated encrypted account backup.
use crate::bus::protocol::LocalBusBackupContactRestoreReport;
use crate::client::own_contact::OwnContactReceiveOutcome;
use crate::{RamfluxClient, SdkError};

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
    ) -> Result<LocalBusBackupContactRestoreReport, SdkError> {
        if contacts.len() > 512 || contacts.iter().map(String::len).sum::<usize>() > 3 * 1024 * 1024
        {
            return Err(SdkError::InboundRejected("backup contact snapshot exceeds budget".into()));
        }
        let mut report = LocalBusBackupContactRestoreReport::default();
        // Only call after backup AEAD authentication. Each relationship must name this root;
        // peer manifests still verify and existing local restrictions always win.
        self.account_db()?.write_transaction(|| {
            for contact in contacts {
                let body = ramflux_protocol::decode_base64url(contact).map_err(|error| {
                    SdkError::LocalBus(format!("invalid backup contact encoding: {error}"))
                })?;
                if let Some(skip) = self.backup_contact_skip(&body)? {
                    report.skipped.push(skip);
                    continue;
                }
                match self.receive_own_contact_outcome(&body)? {
                    OwnContactReceiveOutcome::Restored => report.restored += 1,
                    OwnContactReceiveOutcome::TombstoneApplied => {
                        report.tombstones_applied += 1;
                    }
                    OwnContactReceiveOutcome::TombstoneSkippedOlder => {
                        report.tombstones_skipped_older += 1;
                    }
                    OwnContactReceiveOutcome::AlreadyPresent => report.already_present += 1,
                    OwnContactReceiveOutcome::NotPacket => {
                        return Err(SdkError::InboundRejected(
                            "invalid backup contact packet".into(),
                        ));
                    }
                }
            }
            Ok(())
        })?;
        Ok(report)
    }
}
