// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cached attachment completion honors deletion fences and outstanding authorized ACKs.
use super::{
    DeferredObjectKeySlot, RamfluxClient, SdkDmAttachmentImportResult, SdkDmAttachmentRef,
    SdkError, ack_progress_prefix, reference_key, slot_reference_key, validate_reference,
};

use ramflux_storage::ObjectRetention;

impl RamfluxClient {
    pub(in crate::client) fn try_import_cached_attachment(
        &mut self,
        reference: &SdkDmAttachmentRef,
    ) -> Result<Option<SdkDmAttachmentImportResult>, SdkError> {
        self.try_import_cached_attachment_retained(reference, ObjectRetention::Imported)
    }

    pub(in crate::client) fn try_import_cached_attachment_retained(
        &mut self,
        reference: &SdkDmAttachmentRef,
        retention: ObjectRetention,
    ) -> Result<Option<SdkDmAttachmentImportResult>, SdkError> {
        self.account_db()?.check_object_identity(&reference.object_id, &reference.manifest_hash)?;
        let mut check = "attachment_deleted";
        let outcome = (|| {
            if self.discard_deleted_attachment_chunks(reference)? {
                return Err(SdkError::AttachmentDeleted);
            }
            check = "verified_local_object";
            let local = self.received_attachment_is_local(reference)?;
            if !local && !self.cached_attachment_bytes_complete(reference)? {
                return Ok(None);
            }
            check = "cached_reference";
            validate_reference(reference)?;
            if matches!(retention, ObjectRetention::OwnDeviceTransport) {
                self.account_db()?.retain_object(
                    &reference.object_id,
                    &reference.manifest_hash,
                    retention,
                )?;
            }
            if self.cached_attachment_ack_pending(reference)? {
                return Ok(None);
            }
            if !local {
                let slot = self
                    .received_attachment_prepared_slot(reference)?
                    .map_or_else(|| self.decrypt_object_key_slot(&reference.key_slot), Ok)?;
                self.materialize_cached_attachment(
                    reference,
                    slot.object_key,
                    retention,
                    &mut check,
                )?;
            }
            check = "cached_reference";
            validate_reference(reference)?;
            check = "cached_key_slot";
            if self.object_key_slot_committed(&reference.key_slot)? {
                self.account_db()?.write_transaction(|| self.sweep_attachment_acks(reference))?;
            } else {
                let slot = self
                    .received_attachment_prepared_slot(reference)?
                    .map_or_else(|| self.decrypt_object_key_slot(&reference.key_slot), Ok)?;
                let object_key =
                    zeroize::Zeroizing::new(self.object_content_key(&reference.object_id)?);
                if *object_key != slot.object_key {
                    return Err(SdkError::LocalBus(
                        "cached attachment key differs from key slot".into(),
                    ));
                }
                check = "key_slot_commit";
                self.commit_received_attachment_import(reference, &slot)?;
            }
            let plaintext = zeroize::Zeroizing::new(self.decrypt_object(&reference.object_id)?);
            Ok(Some(SdkDmAttachmentImportResult {
                object_id: reference.object_id.clone(),
                manifest_hash: reference.manifest_hash.clone(),
                plaintext_base64: ramflux_protocol::encode_base64url(&plaintext),
                plaintext_hash: reference.plaintext_hash.clone(),
                imported: true,
            }))
        })();
        super::super::attachment_diagnostics::checked(outcome, &reference.object_id, check)
    }

    pub(super) fn discard_deleted_attachment_chunks(
        &self,
        reference: &SdkDmAttachmentRef,
    ) -> Result<bool, SdkError> {
        let db = self.active_account_db.as_ref();
        let selector = if let Some(db) = db {
            db.load_actor_state::<String>(&slot_reference_key(reference)?)?
        } else {
            None
        };
        let mut deleted = false;
        for id in std::iter::once(reference.object_id.as_str()).chain(selector.as_deref()) {
            // A routed revocation may reach durable storage before the memory projection.
            let durable = db.map(|db| db.object_is_tombstoned(id)).transpose()?.unwrap_or(false);
            deleted |= durable
                || self.object_store.cached_object(id).is_some_and(|object| object.tombstoned);
        }
        if !deleted {
            return Ok(false);
        }
        if let Some(db) = db {
            let prefix = format!("attachment/chunk/{}/", reference.object_id);
            db.write_transaction(|| {
                for key in db.actor_state_keys(&prefix)? {
                    // Exactly manifest/index follow this id, even when another id contains '/'.
                    if key.strip_prefix(&prefix).is_some_and(|tail| tail.split('/').count() == 2) {
                        db.remove_actor_state(&key)?;
                    }
                }
                self.sweep_attachment_acks(reference)?;
                Ok::<(), SdkError>(())
            })?;
        }
        Ok(true)
    }

    fn cached_attachment_ack_pending(
        &self,
        reference: &SdkDmAttachmentRef,
    ) -> Result<bool, SdkError> {
        let now = u64::try_from(super::now_unix_timestamp()).unwrap_or(0);
        if !reference.access_grant.as_ref().is_some_and(|grant| {
            now < grant.expires_at
                && grant.capabilities.contains(&ramflux_protocol::ObjectRelayCapability::Ack)
        }) || self.object_key_slot_committed(&reference.key_slot)?
        {
            return Ok(false);
        }
        let db = self.account_db()?;
        let selector = db
            .load_actor_state::<String>(&slot_reference_key(reference)?)?
            .unwrap_or_else(|| reference.object_id.clone());
        if db.load_actor_state::<super::ReceivedAttachment>(&reference_key(&selector))?.is_none() {
            return Ok(true);
        }
        let prefix = ack_progress_prefix(reference)?;
        for index in 0..reference.total_chunks {
            if !db
                .load_actor_state::<super::AckProgress>(&format!("{prefix}{index}"))?
                .is_some_and(|saved| saved.object_id == selector && saved.acknowledged)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(in crate::client) fn commit_received_attachment_import(
        &self,
        reference: &SdkDmAttachmentRef,
        slot: &DeferredObjectKeySlot,
    ) -> Result<(), SdkError> {
        // Nested writer phases use savepoints, so the slot and ACK removal commit together.
        self.account_db()?.write_transaction(|| {
            self.account_db()?
                .check_object_identity(&reference.object_id, &reference.manifest_hash)?;
            self.commit_object_key_slot_session(slot)?;
            self.sweep_attachment_acks(reference)
        })
    }

    fn sweep_attachment_acks(&self, reference: &SdkDmAttachmentRef) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for key in db.actor_state_keys(&ack_progress_prefix(reference)?)? {
            db.remove_actor_state(&key)?;
        }
        Ok(())
    }
}
