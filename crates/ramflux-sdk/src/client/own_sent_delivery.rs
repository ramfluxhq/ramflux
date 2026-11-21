// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Best-effort plain-copy admission, local membership and confirmation-gated release.
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;
use serde_json::json;
impl RamfluxClient {
    pub(crate) fn local_own_copy_manifest(
        &self,
    ) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
        let local = self.owned_device_identity()?;
        let manifest = self
            .account_db()?
            .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
                "identity/manifest-root/{}",
                local.root_commitment()
            ))?
            .ok_or_else(|| {
                SdkError::InboundPending("own-device local manifest unavailable".into())
            })?;
        self.verify_own_copy_manifest(&manifest, local.root_commitment())?;
        if let Some(native) = &manifest.custody {
            let current = self
                .current_custody_authority(local.root_commitment(), crate::custody::network_now()?)?
                .ok_or(SdkError::NetworkingPending)?;
            if current.envelope() != &native.publication.record {
                return Err(SdkError::InboundPending(
                    "own-device local manifest needs refresh".into(),
                ));
            }
            self.require_cached_root_authority(HeadUse::NewAuthorization, &local)?;
            // The signed record can be current while the device entries projected beside it
            // predate a sibling's registration. A cache that lacks a sibling this root
            // authorizes would make the copy look unneeded and drop it: refresh instead.
            let now = crate::custody::network_now()?;
            let missing = current.envelope().body.devices.iter().any(|entry| {
                entry.device_id != local.device_id()
                    && ["message", "sync"].iter().all(|capability| {
                        current
                            .authorize(
                                &ramflux_protocol::custody::DeviceRef {
                                    account_anchor: local.root_commitment().into(),
                                    device_id: entry.device_id.clone(),
                                    device_epoch: entry.device_epoch,
                                },
                                capability,
                                now,
                            )
                            .is_ok()
                    })
                    && !manifest.devices.iter().any(|device| device.device_id == entry.device_id)
            });
            if missing {
                return Err(SdkError::InboundPending(
                    "own-device local manifest needs refresh".into(),
                ));
            }
        } else if manifest.signed_device_set != self.observed_device_set(local.root_commitment())? {
            return Err(SdkError::InboundPending("own-device local manifest needs refresh".into()));
        }
        Ok(manifest)
    }
    fn verify_own_copy_manifest(
        &self,
        manifest: &crate::prekey::SdkDeviceManifestResponse,
        expected: &str,
    ) -> Result<(), SdkError> {
        if manifest.custody.is_none() {
            return super::identity_authority::verify_manifest(manifest, expected);
        }
        let wall = now_unix_timestamp();
        let network = crate::custody::network_now()?;
        let bytes = serde_json::to_vec(&(expected, manifest, wall, network))?;
        let fingerprint = *blake3::hash(&bytes).as_bytes();
        if self.verified_authority_cache.borrow().own_manifest_verified(&fingerprint) {
            return Ok(());
        }
        super::identity_authority::verify_manifest(manifest, expected)?;
        // Both clock domains and every manifest byte bind this signature-work cache.
        // Current custody pins and live-head authorization are still checked by the caller.
        if wall == now_unix_timestamp() && network == crate::custody::network_now()? {
            self.verified_authority_cache.borrow_mut().remember_own_manifest(fingerprint);
        }
        Ok(())
    }

    pub(crate) fn prepare_own_copy_manifest_refresh(
        &self,
    ) -> Result<Option<crate::prekey::SdkDeviceManifestResponse>, SdkError> {
        if let Ok(manifest) = self.local_own_copy_manifest() {
            return Ok(Some(manifest));
        }
        let local = self.owned_device_identity()?;
        let epoch = if let Some(current) =
            self.current_custody_authority(local.root_commitment(), crate::custody::network_now()?)?
        {
            json!(ramflux_protocol::custody::object_hash(current.envelope())?)
        } else {
            json!(
                self.observed_device_set(local.root_commitment())?.map(|set| set.device_set_epoch)
            )
        };
        let db = self.account_db()?;
        let now = now_unix_timestamp();
        let old = db.load_actor_state::<serde_json::Value>("own-device/manifest-refresh")?;
        if old.as_ref().is_some_and(|row| {
            row["epoch"] == json!(epoch) && row["next_at"].as_i64().is_some_and(|at| at > now)
        }) {
            return Err(SdkError::InboundPending("own-device manifest refresh backed off".into()));
        }
        db.persist_actor_state(
            "own-device/manifest-refresh",
            &json!({"epoch":epoch,"next_at":now.saturating_add(60)}),
        )?;
        Ok(None)
    }

    pub(crate) fn own_sent_has_siblings(&self) -> Result<bool, SdkError> {
        let local = self.owned_device_identity()?;
        let now = crate::custody::network_now()?;
        if let Some(current) = self.current_custody_authority(local.root_commitment(), now)? {
            return Ok(current.envelope().body.devices.iter().any(|device| {
                device.device_id != local.device_id()
                    && current
                        .authorize(
                            &ramflux_protocol::custody::DeviceRef {
                                account_anchor: local.root_commitment().into(),
                                device_id: device.device_id.clone(),
                                device_epoch: device.device_epoch,
                            },
                            "sync",
                            now,
                        )
                        .is_ok()
            }));
        }
        if self.born_v3_account.is_some()
            || self.custody_epoch_floor(local.root_commitment())?.is_some()
        {
            return Err(SdkError::InboundPending(
                "own-device custody authority unavailable".into(),
            ));
        }
        let set = self
            .observed_device_set(local.root_commitment())?
            .ok_or_else(|| SdkError::InboundPending("own-device signed set unavailable".into()))?;
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        ramflux_crypto::verify_signed_device_set(&root.signing_key.verifying_key(), &set)?;
        Ok(set.devices.iter().any(|d| {
            d.status == ramflux_protocol::DeviceSetStatus::Active
                && d.device_id != local.device_id()
        }))
    }
    #[cfg(test)]
    pub(crate) fn queue_own_sent_copy(
        &self,
        message: &str,
        stage: impl FnOnce() -> Result<String, SdkError>,
    ) -> Option<String> {
        let result = (|| {
            if !self.own_sent_has_siblings()? {
                return Ok(None);
            }
            self.account_db()?.write_transaction(|| stage().map(Some))
        })();
        match result {
            Ok(ticket) => ticket,
            Err(error) => {
                self.own_sent_copy_failure(message, &error);
                None
            }
        }
    }
    #[cfg(test)]
    fn own_sent_copy_failure(&self, message: &str, error: &SdkError) {
        tracing::warn!(%error,"sent message own-device copy failed");
        let record = (|| -> Result<(), SdkError> {
            let db = self.account_db()?;
            db.write_transaction(|| {
                let count = db
                    .load_actor_state::<u64>("own-device/sent-failures")?
                    .unwrap_or(0)
                    .saturating_add(1);
                db.persist_actor_state("own-device/sent-failures", &count)?;
                let mut row = db.client_record("message", message)?.unwrap_or_else(|| json!({}));
                row["own_device_copy_state"] = json!("failed");
                db.persist_client_record("message", message, &row)?;
                Ok(())
            })
        })();
        if let Err(error) = record {
            tracing::warn!(%error,"own-device failure bookkeeping unavailable");
        }
    }
    #[cfg(test)]
    pub(crate) fn finish_own_sent_copy(
        &self,
        message: &str,
        ticket: Option<&str>,
        confirmed: bool,
    ) {
        if let Some(ticket) = ticket
            && let Err(error) = crate::bus::own_device_copy::finish_held(self, ticket, confirmed)
        {
            self.own_sent_copy_failure(message, &error);
        }
    }
}

#[cfg(test)]
#[path = "own_sent_native_tests.rs"]
mod native_tests;
