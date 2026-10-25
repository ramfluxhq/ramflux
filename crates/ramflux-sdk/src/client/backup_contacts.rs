// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded relationship snapshots inside the authenticated encrypted account backup.
use crate::{RamfluxClient, SdkError};

impl RamfluxClient {
    pub(crate) fn backup_contacts(&self) -> Result<Vec<String>, SdkError> {
        self.own_history_contacts()
    }

    pub(crate) fn restore_backup_contacts(&self, contacts: &[String]) -> Result<(), SdkError> {
        if contacts.len() > 512 || contacts.iter().map(String::len).sum::<usize>() > 3 * 1024 * 1024
        {
            return Err(SdkError::InboundRejected("backup contact snapshot exceeds budget".into()));
        }
        // Only call after backup AEAD authentication. Each relationship must name this root;
        // peer manifests still verify and existing local restrictions always win.
        self.account_db()?.write_transaction(|| {
            for contact in contacts {
                let body = ramflux_protocol::decode_base64url(contact).map_err(|error| {
                    SdkError::LocalBus(format!("invalid backup contact encoding: {error}"))
                })?;
                if !self.receive_own_contact(&body)? {
                    return Err(SdkError::InboundRejected("invalid backup contact packet".into()));
                }
            }
            Ok(())
        })
    }
}
