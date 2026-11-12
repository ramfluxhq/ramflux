// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native directory backfill queues current registers once for each certified sibling incarnation.
use super::{RamfluxClient, SdkError};
use crate::client::identity_authority::NativeOperation;
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::custody::DeviceRef;

impl RamfluxClient {
    pub(crate) fn stage_native_self_sync_bootstrap(&self) -> Result<(), SdkError> {
        self.stage_native_self_sync_registers(true)
    }

    pub(crate) fn stage_native_self_sync_publications(&self) -> Result<(), SdkError> {
        self.stage_native_self_sync_registers(false)
    }

    fn stage_native_self_sync_registers(&self, enrollment_only: bool) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if db.actor_state_keys("self-sync/state/")?.is_empty() {
            return Ok(());
        }
        let local = self.owned_device_identity()?;
        let now = crate::custody::network_now()?;
        let Some(authority) = self.current_custody_authority(local.root_commitment(), now)? else {
            return Ok(());
        };
        let local_entry = authority
            .envelope()
            .body
            .devices
            .iter()
            .find(|entry| entry.device_id == local.device_id())
            .ok_or_else(|| SdkError::InboundRejected("local SelfSync authority missing".into()))?;
        let reference = |device_id: &str, device_epoch| DeviceRef {
            account_anchor: local.root_commitment().into(),
            device_id: device_id.into(),
            device_epoch,
        };
        // Missing Sync is a certified feature restriction, not a directory failure.
        if authority
            .authorize(&reference(local.device_id(), local_entry.device_epoch), "sync", now)
            .is_err()
        {
            return Ok(());
        }
        match self.require_native_operation(&local, NativeOperation::Sync) {
            Ok(()) => {}
            // Enrollment invalidates the directory freshness stamp. Backfill must be
            // able to fetch the new roster before bootstrap can authorize it.
            Err(SdkError::FreshHeadRequired { .. }) => return Ok(()),
            Err(error) => return Err(error),
        }
        db.write_transaction(|| {
            for entry in &authority.envelope().body.devices {
                if entry.device_id == local.device_id() {
                    continue;
                }
                let Ok(certificate) = authority.authorize(
                    &reference(&entry.device_id, entry.device_epoch),
                    "sync",
                    now,
                ) else {
                    continue;
                };
                let sibling =
                    RootQualifiedDeviceRef::from_custody_record(&authority, &entry.device_id)?;
                if db.client_device_record(&sibling)?.is_none() {
                    continue;
                }
                let marker = format!(
                    "self-sync/bootstrap/{}/{}/{}/{}",
                    local.storage_key(),
                    local_entry.device_epoch,
                    sibling.storage_key(),
                    certificate.cert_id
                );
                if enrollment_only && db.load_actor_state::<bool>(&marker)?.unwrap_or(false) {
                    continue;
                }
                self.bootstrap_self_sync(&sibling)?;
                if enrollment_only {
                    db.persist_actor_state(&marker, &true)?;
                }
            }
            Ok(())
        })
    }
}
