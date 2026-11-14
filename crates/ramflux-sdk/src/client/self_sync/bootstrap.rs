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
                // One marker per certified incarnation: a restored or re-activated sibling
                // advances its epoch and is bootstrapped again even under a retained certificate.
                let marker = format!(
                    "self-sync/bootstrap/{}/{}/{}/{}/{}",
                    local.storage_key(),
                    local_entry.device_epoch,
                    sibling.storage_key(),
                    entry.device_epoch,
                    certificate.cert_id
                );
                if enrollment_only && db.load_actor_state::<bool>(&marker)?.unwrap_or(false) {
                    continue;
                }
                match self.bootstrap_self_sync(&sibling) {
                    Ok(()) => {}
                    Err(SdkError::InboundPending(_)) => continue,
                    Err(error) => return Err(error),
                }
                if enrollment_only {
                    db.persist_actor_state(&marker, &true)?;
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};

    fn registers(client: &RamfluxClient) -> TestResult<Vec<(String, Vec<u8>)>> {
        let db = client.account_db()?;
        db.actor_state_keys("self-sync/")?
            .into_iter()
            .map(|key| {
                let value = db
                    .load_actor_state::<Box<serde_json::value::RawValue>>(&key)?
                    .ok_or("register missing")?;
                Ok((key, value.get().as_bytes().to_vec()))
            })
            .collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn active_backfill_refuses_unavailable_floor_bootstrap_without_revising_registers()
    -> TestResult {
        crate::client::native_test_support::watchdog::within(
            active_backfill_refuses_unavailable_floor_bootstrap_without_revising_registers_body(),
        )
        .await?
    }

    async fn active_backfill_refuses_unavailable_floor_bootstrap_without_revising_registers_body()
    -> TestResult {
        let mut own = Fixture::new("dormant-sync-backfill").await?;
        let sibling = own.enroll_sibling("dormant-sync-sibling", "sibling").await?;

        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        own.client.change_self_sync(
            "thread",
            ramflux_protocol::message::SelfSync { operation: 6, mute: true, ..Default::default() },
        )?;

        assert!(
            ramflux_protocol::schema_profile::schema_v1_live(),
            "backfill must be tested with the active profile"
        );
        let before = registers(&own.client)?;
        assert!(!before.is_empty(), "fixture must retain an actual previously written register");
        own.client.stage_native_self_sync_bootstrap()?;
        own.client.stage_native_self_sync_publications()?;
        assert!(
            registers(&own.client)? == before,
            "unavailable authenticated bootstrap must not allocate new revisions"
        );
        assert_eq!(
            sibling.client.account_db()?.actor_state_usage("self-sync/repair/")?.0,
            0,
            "unavailable authenticated bootstrap must not publish values to the sibling"
        );
        Ok(())
    }
}
