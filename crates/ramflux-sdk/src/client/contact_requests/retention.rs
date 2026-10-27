// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retire unaccepted requester material while preserving compact rollback and consent fences.
use super::{TTL, invalid};
use crate::prelude::*;
use serde_json::json;
const CACHE_PREFIX: &str = "contact-request/cache/";
pub(crate) fn authority_digest(
    record: &ramflux_protocol::SignedDeviceSetRecord,
) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.contact_request.authority_floor.v1",
        &ramflux_protocol::canonical_json_bytes(record)?,
    ))
}
impl RamfluxClient {
    pub(super) fn contact_request_owns_identity_cache(&self, root: &str) -> Result<bool, SdkError> {
        Ok(self.account_db()?.actor_state_exists(&format!("{CACHE_PREFIX}{root}"))?)
    }
    pub(crate) fn remember_contact_request_cache(
        &self,
        manifest: &crate::prekey::SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let root = &manifest.principal_commitment;
        let key = format!("{CACHE_PREFIX}{root}");
        if !db.actor_state_exists(&key)?
            && (self.observed_device_set(root)?.is_some()
                || db.actor_state_exists(&format!("identity/manifest-root/{root}"))?)
        {
            return Ok(());
        }
        if let Some(native) = &manifest.custody {
            let verified = ramflux_crypto::custody::verify_publication(
                &ramflux_protocol::custody::CustodyAuthority {
                    publication: native.publication.clone(),
                    custodian_publication: native.custodian_publication.clone(),
                },
                crate::custody::network_now()?,
            )?;
            if verified.envelope().body.account_anchor != *root {
                return Err(invalid("requester native root mismatch"));
            }
            self.retain_native_request_floor(verified.envelope())?;
            db.persist_actor_state(&key, &json!({"principal_id":manifest.principal_id}))?;
            return Ok(());
        }
        let record = manifest
            .signed_device_set
            .as_ref()
            .ok_or_else(|| invalid("requester authority is absent"))?;
        self.check_observed_set(record)?;
        self.retain_request_floor(record)?;
        db.persist_actor_state(&key, &json!({"principal_id":manifest.principal_id}))?;
        Ok(())
    }
    fn retain_native_request_floor(
        &self,
        record: &ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    ) -> Result<(), SdkError> {
        let now = now_unix_timestamp();
        let hash = ramflux_protocol::custody::object_hash(record)?;
        if let Some((epoch, old)) =
            self.account_db()?.contact_request_authority_floor(&record.body.account_anchor, now)?
            && (record.body.device_set_epoch < epoch
                || (record.body.device_set_epoch == epoch && hash != old))
        {
            return Err(invalid("native requester authority is stale or conflicting"));
        }
        if !self.account_db()?.retain_contact_request_authority_floor(
            &record.body.account_anchor,
            record.body.device_set_epoch,
            &hash,
            now.saturating_add(2 * TTL),
            now,
        )? {
            return Err(SdkError::ContactRequestCapacity(
                "native requester cache capacity exhausted".into(),
            ));
        }
        Ok(())
    }

    fn retain_request_floor(
        &self,
        record: &ramflux_protocol::SignedDeviceSetRecord,
    ) -> Result<(), SdkError> {
        let now = now_unix_timestamp();
        if !self.account_db()?.retain_contact_request_authority_floor(
            &record.principal_commitment,
            record.device_set_epoch,
            &authority_digest(record)?,
            now.saturating_add(2 * TTL),
            now,
        )? {
            return Err(SdkError::ContactRequestCapacity(
                "contact requester cache capacity exhausted".into(),
            ));
        }
        Ok(())
    }
    pub(super) fn promote_contact_request_cache(&self, root: &str) -> Result<(), SdkError> {
        // A durable accepted relationship retains the normal complete monotonic authority record.
        self.account_db()?.remove_actor_state(&format!("{CACHE_PREFIX}{root}"))?;
        self.account_db()?.release_contact_request_authority_floor(root)?;
        Ok(())
    }
    fn retire_contact_request_cache(
        &self,
        row: &ramflux_storage::ContactRequestRecord,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let root = &row.contact_identity_commitment;
        let key = format!("{CACHE_PREFIX}{root}");
        if !db.actor_state_exists(&key)? {
            return Ok(());
        }
        if self.friend_link_peer_is_accepted(root)? || db.contact_verification(root)?.is_some() {
            return self.promote_contact_request_cache(root);
        }
        if let Some(native) =
            self.current_custody_authority(root, crate::custody::network_now()?)?
        {
            let record = native.envelope();
            for entry in &record.body.devices {
                if db
                    .pinned_group_root_metadata(&record.body.principal_id, &entry.device_id)?
                    .iter()
                    .any(|known| known == root)
                {
                    return self.promote_contact_request_cache(root);
                }
            }
            self.retain_native_request_floor(record)?;
            for entry in &record.body.devices {
                let device = ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(
                    &native,
                    &entry.device_id,
                )?;
                self.remove_device_pair(&device, "contact_request_closed")?;
            }
            db.purge_contact_request_identity_metadata(
                root,
                &record.body.principal_id,
                &row.link_id,
            )?;
            self.retire_custody_directory_payload(root)?;
            db.remove_actor_state(&key)?;
            return Ok(());
        }
        let Some(set) = self.observed_device_set(root)? else {
            db.remove_actor_state(&key)?;
            return Ok(());
        };
        for entry in &set.devices {
            if db
                .pinned_group_root_metadata(&set.principal_id, &entry.device_id)?
                .iter()
                .any(|known| known == root)
            {
                return self.promote_contact_request_cache(root);
            }
        }
        self.retain_request_floor(&set)?;
        for entry in &set.devices {
            if entry.status == ramflux_protocol::DeviceSetStatus::Active {
                let device = self.device_identity_for_root(root, &entry.device_id)?;
                self.remove_device_pair(&device, "contact_request_closed")?;
            }
        }
        db.purge_contact_request_identity_metadata(root, &set.principal_id, &row.link_id)?;
        db.remove_actor_state(&key)?;
        Ok(())
    }
    pub(crate) fn maintain_contact_requests(&self) -> Result<(), SdkError> {
        // Maintenance is best effort; a damaged retired row must not stop consent ingress.
        let db = self.account_db()?;
        if let Err(error) = self.maintain_contact_request_batch(db) {
            tracing::warn!(%error, "contact request maintenance deferred");
        }
        Ok(())
    }
    fn maintain_contact_request_batch(
        &self,
        db: &ramflux_storage::AccountDb,
    ) -> Result<(), SdkError> {
        const KEY: &str = "contact-request/maintenance-next";
        let now = now_unix_timestamp();
        if db.load_actor_state::<i64>(KEY)?.is_some_and(|next| now < next) {
            return Ok(());
        }
        db.persist_actor_state(KEY, &now.saturating_add(60))?;
        db.expire_contact_requests(now)?;
        db.prune_contact_request_fences_and_previews(now)?;
        for row in db.closed_contact_requests(now)? {
            let result = db.write_transaction(|| -> Result<(), SdkError> {
                if row.direction == "inbound" {
                    self.retire_contact_request_cache(&row)?;
                } else {
                    self.record_outbound_contact_state(
                        &row.contact_identity_commitment,
                        &row.state,
                        row.updated_at,
                    )?;
                }
                db.remove_contact_request(
                    &row.contact_identity_commitment,
                    &row.direction,
                    &row.request_id,
                )?;
                Ok(())
            });
            if let Err(error) = result {
                tracing::warn!(%error, "closed contact request retirement deferred");
                db.defer_contact_request_retirement(
                    &row.contact_identity_commitment,
                    &row.direction,
                    now.saturating_add(300),
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn check_retained_outbound_contact_cooldown(
        &self,
        root: &str,
    ) -> Result<(), SdkError> {
        if self.account_db()?.client_record("contact_request_status", root)?.is_some_and(|status| {
            status["state"] == "declined"
                && now_unix_timestamp()
                    < status["updated_at"]
                        .as_i64()
                        .unwrap_or(0)
                        .saturating_add(super::DECLINE_COOLDOWN_SECONDS)
        }) {
            return Err(invalid("contact request is cooling down"));
        }
        Ok(())
    }
    pub(super) fn record_outbound_contact_state(
        &self,
        root: &str,
        state: &str,
        at: i64,
    ) -> Result<(), SdkError> {
        self.account_db()?.persist_client_record(
            "contact_request_status",
            root,
            &json!({"state":state,"updated_at":at}),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod native_tests;
